package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/pires/go-proxyproto"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/fharias/guardian-scrapy/internal/acl"
	"github.com/fharias/guardian-scrapy/internal/admin"
	"github.com/fharias/guardian-scrapy/internal/challenge"
	"github.com/fharias/guardian-scrapy/internal/clientip"
	"github.com/fharias/guardian-scrapy/internal/config"
	"github.com/fharias/guardian-scrapy/internal/configsource"
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
	"github.com/fharias/guardian-scrapy/internal/tlshello"
	"github.com/fharias/guardian-scrapy/internal/tracing"
	"github.com/fharias/guardian-scrapy/internal/verdict"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
)

// version identifica el build en los traces (service.version en Jaeger).
// Se puede sobrescribir al compilar:
//
//	go build -ldflags "-X main.version=$(git rev-parse --short HEAD)" ./cmd/guardian
var version = "dev"

func main() {
	path := flag.String("config", "guardian-config.yml", "ruta del archivo de configuración")
	poll := flag.Duration("config-poll", 10*time.Second,
		"revisa el archivo cada tanto aunque fsnotify no avise (0 = solo fsnotify y SIGHUP)")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	src := configsource.NewFileSource(*path, *poll, logger)
	// cfg es la config de ARRANQUE: todo lo que requiere reinicio (listen, TLS,
	// upstream, Redis, events, tracing, rate/burst...) se lee de aquí una sola
	// vez. Lo recargable se lee del snapshot vigente dentro de buildProtected.
	cfg, cfgVersion, err := configsource.LoadInitial(context.Background(), src)
	if err != nil {
		log.Fatal(err)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(cfg.UpstreamURL)
			pr.SetXForwarded()
			if v := verdict.From(pr.In.Context()); v != nil && v.ClientIP.IsValid() {
				pr.Out.Header.Set("X-Forwarded-For", v.ClientIP.String())
			}
			if cfg.PreserveHost {
				pr.Out.Host = pr.In.Host
			}
			tracing.InjectUpstream(pr.Out)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("error hacia upstream: %v", err)
			http.Error(w, "upstream no disponible", http.StatusBadGateway)
		},
	}

	var ready atomic.Bool
	ready.Store(true)

	healthz := func(w http.ResponseWriter, r *http.Request) {
		if ready.Load() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}
	readyz := func(w http.ResponseWriter, r *http.Request) {
		if ready.Load() {
			w.WriteHeader(http.StatusOK)
		}
	}
	go func() {
		m := http.NewServeMux()
		m.Handle("/metrics", promhttp.Handler())
		ms := &http.Server{Addr: ":2112", Handler: m, ReadHeaderTimeout: 5 * time.Second}
		if err := ms.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("servidor de métricas", "err", err)
		}
	}()
	rdb := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:                 []string{cfg.RedisAddr},
		DialTimeout:           200 * time.Millisecond,
		ReadTimeout:           100 * time.Millisecond,
		WriteTimeout:          100 * time.Millisecond,
		ContextTimeoutEnabled: true,
		MaxRetries:            -1,
	})
	defer rdb.Close()
	redisStore := ratelimit.NewRedisStore(rdb, cfg.App, cfg.Rate, cfg.Burst)
	local := ratelimit.NewMemoryStore(cfg.Rate, cfg.Burst)

	store := ratelimit.NewFailoverStore(redisStore, local, 50*time.Millisecond, 5, 10*time.Second, logger)

	clientipResolver, err := clientip.New(cfg.TrustedProxies, cfg.XForwardedForHeader)
	if err != nil {
		logger.Error("error al crear el resolver de clientip", "err", err)
		os.Exit(1)
	}
	bots := goodbot.NewVerifier(cfg.GoodBots, net.DefaultResolver, time.Hour)
	keys, err := challenge.ParseKeyring(os.Getenv("GUARDIAN_PASS_KEYS"))
	if err != nil {
		logger.Error("pass keys", "err", err)
		os.Exit(1)
	}
	ch := challenge.NewService(keys, cfg.Challenge.Difficulty, cfg.Challenge.TTL, cfg.Challenge.PassTTL)
	mets := metrics.New(prometheus.DefaultRegisterer)
	closeEvents, emitFor, err := setupEvents(cfg.Events, logger)
	if err != nil {
		logger.Error("events", "err", err)
		os.Exit(1)
	}
	ja4Source, err := ja4source.New(cfg.JA4.Source, clientipResolver.PeerIsTrusted)
	if err != nil {
		logger.Error("ja4source", "err", err)
		os.Exit(1)
	}
	var repReader *reputation.Reader
	if cfg.Reputation.Enabled {
		repReader = reputation.NewReader(rdb, cfg.App, cfg.Reputation)
	}
	logger.Info("reputation", "enabled", cfg.Reputation.Enabled,
		"min_distinct_ips", cfg.Reputation.MinDistinctIPs, "cache_ttl", cfg.Reputation.CacheTTL.String())
	// La ACL de la Admin API (bloqueos y allowlist en Redis). Tiene caché, así
	// que se crea UNA vez y la reutiliza cada cadena reconstruida, igual que
	// repReader. Con admin apagado queda nil y el middleware ACL no hace nada.
	var aclStore *acl.Store
	if cfg.Admin.Enabled {
		opts := cfg.Admin.ACLOptions()
		opts.Registerer = prometheus.DefaultRegisterer
		aclStore = acl.New(rdb, cfg.App, opts)
	}
	tracer := otel.Tracer("github.com/fharias/guardian-scrapy")
	step := func(name string, mw middleware.Middleware) middleware.Middleware {
		return middleware.Traced(tracer, name, mw)
	}
	// buildProtected arma la cadena COMPLETA con una config ya validada. Corre
	// al arrancar y en cada recarga. Las piezas recargables (scorer, rules,
	// modes, ja4Policy) se crean aquí, nuevas cada vez; las que cargan estado
	// (store, repReader, aclStore, bots, ch, clientipResolver, ja4Source, proxy,
	// mets) se crearon arriba una sola vez y se reutilizan.
	buildProtected := func(c *config.Config, version string) (http.Handler, error) {
		scorer, err := scoring.New(c.Scoring)
		if err != nil {
			return nil, fmt.Errorf("scoring: %w", err)
		}
		engine, err := rules.New(c.Rules)
		if err != nil {
			return nil, fmt.Errorf("rules: %w", err)
		}
		modes, err := policy.New(c.Modes)
		if err != nil {
			return nil, fmt.Errorf("modes: %w", err)
		}
		ja4Policy, err := fingerprint.NewJA4Policy(c.JA4)
		if err != nil {
			return nil, fmt.Errorf("ja4: %w", err)
		}
		return middleware.Chain(proxy,
			middleware.Init,
			middleware.ConfigVersion(version),
			mets.Middleware(modes.Route),
			emitFor(modes.Route),
			middleware.Trace(tracer, middleware.TraceOptions{
				Route: modes.Route,
				TrustIncoming: func(r *http.Request) bool {
					return cfg.Tracing.TrustIncoming && clientipResolver.PeerIsTrusted(r)
				},
			}),
			step("clientip", middleware.ClientIP(clientipResolver)),
			middleware.Logger(logger),
			step("suspiciousua", middleware.SuspiciousUA()),
			step("fingerprint", middleware.Fingerprint()),
			step("ja4", middleware.JA4(ja4Source, logger)),
			step("acl", middleware.ACL(aclStore, logger)),

			step("ja4mismatch", middleware.JA4Mismatch(ja4Policy)),
			step("reputation", middleware.Reputation(repReader, logger)),
			step("rules", middleware.Rules(engine, bots, 300*time.Millisecond)),
			step("ratelimit", middleware.RateLimit(store, logger)),
			step("score", middleware.Score(scorer)),
			step("enforce", middleware.Enforce(ch, modes, logger)),
		), nil
	}
	reloader, err := configsource.New(src, cfg, cfgVersion, buildProtected, configsource.Options{
		Logger:     logger,
		Registerer: prometheus.DefaultRegisterer,
	})
	if err != nil {
		logger.Error("config", "err", err)
		os.Exit(1)
	}
	logger.Info("config", "source", src.Name(), "version", cfgVersion,
		"poll", poll.String(), "recargable", config.Reloadable)
	protected := configsource.Handler(reloader)
	adminSrv, err := newAdminServer(cfg, aclStore, reloader, logger)
	if err != nil {
		logger.Error("admin", "err", err)
		os.Exit(1)
	}
	verify := middleware.Chain(middleware.VerifyHandler(ch, logger),
		middleware.Init,
		middleware.ClientIP(clientipResolver),
		middleware.Logger(logger),
		middleware.Fingerprint(),
		middleware.JA4(ja4Source, logger),
	)
	root := http.NewServeMux()
	root.Handle(middleware.VerifyPath, verify)
	root.HandleFunc("GET /healthz", healthz)
	root.HandleFunc("GET /readyz", readyz)
	root.Handle("/", protected)

	newServer := func(addr string, handler http.Handler) *http.Server {
		return &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			ReadTimeout:       cfg.ReadTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			IdleTimeout:       cfg.IdleTimeout,
		}
	}

	abrirListener := func(addr string) (net.Listener, error) {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		if cfg.ProxyProtocol {
			policy, err := proxyproto.TrustProxyHeaderFromRanges(cfg.TrustedProxies)
			if err != nil {
				ln.Close()
				return nil, err
			}
			ln = &proxyproto.Listener{
				Listener:          ln,
				ConnPolicy:        policy,
				ReadHeaderTimeout: 2 * time.Second,
			}
		}
		return ln, nil
	}

	httpSrv := newServer(cfg.Listen, root)

	var tlsSrv *http.Server
	if cfg.TLS.Enabled() {
		if _, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil {
			logger.Error("tls: no pude cargar el certificado", "err", err)
			os.Exit(1)
		}
		tlsSrv = newServer(cfg.TLS.Listen, tlshello.LogHandler(logger, root))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	shutdownTracing, err := tracing.Setup(ctx, cfg.Tracing, version)
	if err != nil {
		logger.Error("tracing", "err", err)
		os.Exit(1)
	}
	logger.Info("tracing", "enabled", cfg.Tracing.Enabled, "endpoint", cfg.Tracing.Endpoint,
		"sample_ratio", cfg.Tracing.SampleRatio, "trust_incoming", cfg.Tracing.TrustIncoming)
	local.StartJanitor(ctx, time.Minute, logger)
	defer stop()

	// Recarga en caliente: fsnotify + poll dentro de Run; SIGHUP como disparador
	// manual. Ojo: si no capturas SIGHUP, su acción por defecto MATA el proceso.
	go reloader.Run(ctx)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				reloader.Trigger("sighup")
			}
		}
	}()
	logger.Info("ja4", "source", cfg.JA4.Source)
	logger.Info("listener", "addr", cfg.Listen, "proxy_protocol", cfg.ProxyProtocol, "trusted", cfg.TrustedProxies)

	ln, err := abrirListener(cfg.Listen)
	if err != nil {
		logger.Error("no pude escuchar", "err", err)
		os.Exit(1)
	}
	go func() {
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("servidor", "err", err)
		}
	}()

	if adminSrv != nil {
		// net.Listen directo, SIN abrirListener: la Admin API no va detrás del
		// NLB, así que no habla Proxy Protocol, y RemoteAddr es el operador real.
		adminLn, err := net.Listen("tcp", adminSrv.Addr)
		if err != nil {
			logger.Error("no pude escuchar la Admin API", "err", err)
			os.Exit(1)
		}
		logger.Info("admin", "enabled", true, "addr", adminSrv.Addr,
			"max_ttl", cfg.Admin.MaxTTL.String(), "cache_ttl", cfg.Admin.CacheTTL.String(),
			"stale_ttl", cfg.Admin.StaleTTL.String())
		go func() {
			if err := adminSrv.Serve(adminLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("servidor admin", "err", err)
			}
		}()
	} else {
		logger.Info("admin", "enabled", false)
	}

	if tlsSrv != nil {
		tlsLn, err := abrirListener(cfg.TLS.Listen)
		if err != nil {
			logger.Error("no pude escuchar TLS", "err", err)
			os.Exit(1)
		}
		tlsLn = tlshello.Hook(tlsSrv, tlsLn)
		logger.Info("listener_tls", "addr", cfg.TLS.Listen, "cert", cfg.TLS.CertFile)
		go func() {
			if err := tlsSrv.ServeTLS(tlsLn, cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("servidor tls", "err", err)
			}
		}()
	}

	<-ctx.Done()
	log.Println("señal recibida: dejando de estar listo")
	ready.Store(false)
	time.Sleep(cfg.DrainDelay)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	log.Println("cerrando: esperando requests en curso")
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("apagado forzado: %v", err)
	}
	if tlsSrv != nil {
		if err := tlsSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("apagado forzado: %v", err)
		}
	}
	if adminSrv != nil {
		if err := adminSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("admin: apagado forzado: %v", err)
		}
	}
	if err := closeEvents(shutdownCtx); err != nil {
		log.Printf("events: no pude vaciar el buffer: %v", err)
	}
	if err := shutdownTracing(shutdownCtx); err != nil {
		log.Printf("tracing: no pude vaciar los spans: %v", err)
	}
	log.Println("apagado limpio")

}

// setupEvents crea el sink y el Async UNA vez (tienen conexiones y buffers) y
// devuelve una fábrica de middleware: cada cadena reconstruida en una recarga
// pide el suyo con el RouteFunc de sus propios modes.
func setupEvents(cfg events.Config, logger *slog.Logger) (func(context.Context) error, func(events.RouteFunc) middleware.Middleware, error) {
	noopClose := func(context.Context) error { return nil }
	passthrough := func(events.RouteFunc) middleware.Middleware {
		return func(next http.Handler) http.Handler { return next }
	}
	if !cfg.Enabled {
		logger.Info("events", "enabled", false)
		return noopClose, passthrough, nil
	}
	hasher, err := events.NewHasher(os.Getenv("GUARDIAN_EVENT_SALT"))
	if err != nil {
		return noopClose, passthrough, err
	}
	dest, err := events.NewSink(cfg, logger, prometheus.DefaultRegisterer)
	if err != nil {
		return noopClose, passthrough, err
	}
	async := events.NewAsync(dest, cfg, prometheus.DefaultRegisterer)
	eff := cfg.WithDefaults()
	logger.Info("events", "enabled", true, "sink", eff.Sink, "buffer", eff.Buffer,
		"batch_size", eff.BatchSize, "flush_interval", eff.FlushInterval.String())
	return async.Close, func(route events.RouteFunc) middleware.Middleware {
		return events.Middleware(async, hasher, route)
	}, nil
}

// newAdminServer arma la Admin API si admin.enabled; si está apagada devuelve
// nil. Sin un token válido en GUARDIAN_ADMIN_TOKEN devuelve error y main no
// arranca: es preferible un deploy que falla a una API de bloqueos abierta.
func newAdminServer(cfg *config.Config, store *acl.Store, reloader *configsource.Reloader[http.Handler], logger *slog.Logger) (*http.Server, error) {
	if !cfg.Admin.Enabled {
		return nil, nil
	}
	tokens, err := admin.ParseTokens(os.Getenv(admin.TokenEnv))
	if err != nil {
		return nil, err
	}
	h, err := admin.NewHandler(admin.Options{
		Store:      store,
		Tokens:     tokens,
		MaxTTL:     cfg.Admin.MaxTTL,
		Logger:     logger,
		Registerer: prometheus.DefaultRegisterer,
		// POST /v1/reload usa el MISMO Reloader que fsnotify y SIGHUP: misma
		// validación en tres capas, mismo mutex, mismas métricas.
		Reload: func(ctx context.Context) (string, string, error) {
			before := reloader.Current().Version
			err := reloader.Reload(ctx, "admin_api")
			return before, reloader.Current().Version, err
		},
		Info: func() admin.ConfigInfo {
			s := reloader.Current()
			return admin.ConfigInfo{Version: s.Version, LoadedAt: s.LoadedAt, Reloadable: config.Reloadable}
		},
	})
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              cfg.Admin.Listen,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}, nil
}
