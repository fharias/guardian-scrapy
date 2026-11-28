package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/fharias/guardian-scrapy/internal/acl"
	"github.com/fharias/guardian-scrapy/internal/apps"
	"github.com/fharias/guardian-scrapy/internal/challenge"
	"github.com/fharias/guardian-scrapy/internal/clientip"
	"github.com/fharias/guardian-scrapy/internal/config"
	"github.com/fharias/guardian-scrapy/internal/events"
	"github.com/fharias/guardian-scrapy/internal/fingerprint"
	"github.com/fharias/guardian-scrapy/internal/goodbot"
	"github.com/fharias/guardian-scrapy/internal/ja4source"
	"github.com/fharias/guardian-scrapy/internal/metrics"
	"github.com/fharias/guardian-scrapy/internal/middleware"
	"github.com/fharias/guardian-scrapy/internal/policy"
	"github.com/fharias/guardian-scrapy/internal/ratelimit"
	"github.com/fharias/guardian-scrapy/internal/reputation"
	"github.com/fharias/guardian-scrapy/internal/rules"
	"github.com/fharias/guardian-scrapy/internal/scoring"
	"github.com/fharias/guardian-scrapy/internal/tracing"
	"github.com/fharias/guardian-scrapy/internal/verdict"
)

// chainDeps son las piezas CON ESTADO (conexiones, cachés, métricas, circuit
// breakers) que se crean una sola vez al arrancar y que comparten las cadenas
// de todas las apps y de todas las recargas. Lo que no tiene estado (scorer,
// rules, modes, ja4Policy, el ReverseProxy de cada app) se crea nuevo en cada
// build.
//
// Vive en un struct y no en una closure dentro de main para poder probar la
// cadena REAL de punta a punta (build_test.go) sin levantar el proceso.
type chainDeps struct {
	logger        *slog.Logger
	tracer        trace.Tracer
	trustIncoming bool // tracing.trust_incoming: requiere reinicio
	preserveHost  bool // preserve_host: requiere reinicio
	clientip      *clientip.Resolver
	ja4Source     ja4source.Source
	repReader     *reputation.Reader // nil = reputación apagada
	aclStore      *acl.Store         // nil = Admin API apagada
	bots          *goodbot.Verifier
	ch            *challenge.Service
	mets          *metrics.Metrics
	emitFor       func(events.RouteFunc) middleware.Middleware
	rates         *ratelimit.Pool
	unknown       http.Handler // Host que no es de ninguna app
}

// build arma el apps.Router completo con una config ya validada: una cadena
// por app y la tabla de hosts. Corre al arrancar y en cada recarga; si algo
// falla, el Reloader no publica nada y sigue la config anterior entera.
func (d *chainDeps) build(c *config.Config, version string) (*apps.Router, error) {
	ja4Policy, err := fingerprint.NewJA4Policy(c.JA4)
	if err != nil {
		return nil, fmt.Errorf("ja4: %w", err)
	}
	resolved := c.ResolveApps()
	routes := make([]apps.Route, 0, len(resolved))
	for _, a := range resolved {
		h, err := d.buildApp(a, ja4Policy, version)
		if err != nil {
			return nil, fmt.Errorf("apps[%s]: %w", a.Name, err)
		}
		routes = append(routes, apps.Route{Name: a.Name, Hosts: a.Hosts, Handler: h})
	}
	return apps.NewRouter(routes, c.EffectiveDefaultApp(), d.unknown)
}

// buildApp arma la cadena de UNA app. Es la misma cadena de siempre; cambian
// tres cosas: middleware.App fija el nombre en el veredicto, el ratelimit usa
// el store de la app, y el upstream es el de la app.
func (d *chainDeps) buildApp(a config.App, ja4Policy *fingerprint.JA4Policy, version string) (http.Handler, error) {
	scorer, err := scoring.New(a.Scoring)
	if err != nil {
		return nil, fmt.Errorf("scoring: %w", err)
	}
	engine, err := rules.New(a.Rules)
	if err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	modes, err := policy.New(a.Modes)
	if err != nil {
		return nil, fmt.Errorf("modes: %w", err)
	}
	if a.UpstreamURL == nil {
		return nil, fmt.Errorf("sin upstream")
	}
	step := func(name string, mw middleware.Middleware) middleware.Middleware {
		return middleware.Traced(d.tracer, name, mw)
	}
	return middleware.Chain(newUpstreamProxy(a.UpstreamURL, d.preserveHost),
		middleware.Init,
		middleware.App(a.Name),
		middleware.ConfigVersion(version),
		d.mets.Middleware(modes.Route),
		d.emitFor(modes.Route),
		middleware.Trace(d.tracer, middleware.TraceOptions{
			Route: modes.Route,
			TrustIncoming: func(r *http.Request) bool {
				return d.trustIncoming && d.clientip.PeerIsTrusted(r)
			},
		}),
		step("clientip", middleware.ClientIP(d.clientip)),
		middleware.Logger(d.logger),
		step("suspiciousua", middleware.SuspiciousUA()),
		step("fingerprint", middleware.Fingerprint()),
		step("ja4", middleware.JA4(d.ja4Source, d.logger)),
		step("acl", middleware.ACL(d.aclStore, d.logger)),

		step("ja4mismatch", middleware.JA4Mismatch(ja4Policy)),
		step("reputation", middleware.Reputation(d.repReader, d.logger)),
		step("rules", middleware.Rules(engine, d.bots, 300*time.Millisecond)),
		step("ratelimit", middleware.RateLimit(d.rates.Get(a.Name, a.Rate, a.Burst), d.logger)),
		step("score", middleware.Score(scorer)),
		step("enforce", middleware.Enforce(d.ch, modes, d.logger)),
	), nil
}

// newUpstreamProxy crea el ReverseProxy de una app. Es barato: no abre
// conexiones. Todos comparten http.DefaultTransport (Transport nil), así que
// el pool de conexiones keep-alive hacia cada upstream sobrevive las recargas
// aunque el ReverseProxy se cree de nuevo.
//
// BufferPool: sin él, ReverseProxy hace make([]byte, 32 KB) por respuesta. En
// el perfil de carga del Reto 4 eso era el 49.8% de alloc_space.
func newUpstreamProxy(target *url.URL, preserveHost bool) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		BufferPool: proxyBufferPool,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
			if v := verdict.From(pr.In.Context()); v != nil && v.ClientIP.IsValid() {
				pr.Out.Header.Set("X-Forwarded-For", v.ClientIP.String())
			}
			if preserveHost {
				pr.Out.Host = pr.In.Host
			}
			tracing.InjectUpstream(pr.Out)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("error hacia upstream: %v", err)
			http.Error(w, "upstream no disponible", http.StatusBadGateway)
		},
	}
}

// misdirected atiende un Host que no es de ninguna app: 421 y una métrica sin
// label de host. El log va en Debug: los scanners de Internet llegan por IP o
// con Hosts inventados todo el día, y en Info inundarían el log. Para
// diagnosticar un host mal configurado está la métrica y el 421 que ve curl.
func misdirected(m *metrics.Metrics, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.UnknownHost.Inc()
		host := r.Host
		if len(host) > 255 {
			host = host[:255]
		}
		logger.Debug("host_desconocido", "host", host, "path", r.URL.Path, "remote", r.RemoteAddr)
		apps.Misdirected(w, r)
	})
}
