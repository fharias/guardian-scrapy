package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/fharias/guardian-scrapy/internal/acl"
	"github.com/fharias/guardian-scrapy/internal/clientip"
	"github.com/fharias/guardian-scrapy/internal/fingerprint"
	"github.com/fharias/guardian-scrapy/internal/goodbot"
	"github.com/fharias/guardian-scrapy/internal/ja4source"
	"github.com/fharias/guardian-scrapy/internal/ratelimit"
	"github.com/fharias/guardian-scrapy/internal/reputation"
	"github.com/fharias/guardian-scrapy/internal/rules"
	"github.com/fharias/guardian-scrapy/internal/scoring"
	"github.com/fharias/guardian-scrapy/internal/tlshello"
	"github.com/fharias/guardian-scrapy/internal/verdict"
	"go.opentelemetry.io/otel/trace"
)

// Inicializa el middleware de verificación de acceso
func Init(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := &verdict.Verdict{
			Score:    0,
			Reasons:  []string{},
			Decision: verdict.Allow,
		}
		ctx := verdict.WithVerdict(r.Context(), v)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ConfigVersion deja en el veredicto el hash de la config con la que se
// construyó esta cadena. Como la cadena entera se reconstruye en cada recarga,
// el valor queda fijo dentro de la closure: el log de cada request dice con
// qué config se evaluó, aunque haya terminado después de una recarga.
func ConfigVersion(version string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := verdict.From(r.Context()); v != nil {
				v.ConfigVersion = version
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Registra la solicitud y el resultado de la verificación de acceso
func Logger(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			v := verdict.From(r.Context())
			if v == nil {
				v = &verdict.Verdict{}
			}
			attrs := []any{
				"client_ip", v.ClientIP.String(),
				"mode", v.Mode,
				"shadow", v.Shadowed,
				"fingerprint", v.Fingerprint,
				"method", r.Method,
				"path", r.URL.Path,
				"score", v.Score,
				"decision", v.Decision.String(),
				"reasons", v.Reasons,
				"dur_ms", time.Since(start).Milliseconds(),
			}
			if h := tlshello.FromRequest(r); h != nil {
				attrs = append(attrs, "tls_version", h.VersionName(), "sni", h.SNI)
			}
			if v.JA4Source != "" {
				attrs = append(attrs, "ja4", v.JA4, "ja4_source", v.JA4Source)
			}
			if v.ConfigVersion != "" {
				attrs = append(attrs, "config_version", v.ConfigVersion)
			}
			if sc := trace.SpanContextFromContext(r.Context()); sc.IsValid() {
				attrs = append(attrs, "trace_id", sc.TraceID().String())
			}
			log.Info("request", attrs...)
		})
	}
}

// JA4 le pregunta a la Source de dónde sale el JA4 de esta petición y lo deja
// en el veredicto. Después borra el header de CloudFront: si la petición llegó
// hasta aquí, el JA4 ya quedó decidido, y el upstream no debe creerle a un
// header que cualquiera pudo escribir.
func JA4(src ja4source.Source, log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			res := src.JA4(r)
			if res.Rejected != "" {
				log.Warn("ja4_header_rechazado",
					"motivo", res.Rejected,
					"peer", r.RemoteAddr,
					"path", r.URL.Path,
					"header", res.Header,
				)
			}
			if v := verdict.From(r.Context()); v != nil {
				v.JA4, v.JA4Source = res.JA4, res.Source
			}
			r.Header.Del(ja4source.CloudFrontHeader)
			next.ServeHTTP(w, r)
		})
	}
}

// JA4Mismatch marca la señal cuando el User-Agent dice "navegador" pero el JA4
// del veredicto es de una herramienta conocida. No le importa de dónde salió
// el JA4: eso lo decidió el middleware JA4. Debe ir después de él.
func JA4Mismatch(policy *fingerprint.JA4Policy) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := verdict.From(r.Context()); v != nil && v.JA4 != "" {
				if _, bad := policy.Mismatch(r.UserAgent(), v.JA4); bad {
					v.Signals.JA4Mismatch = true
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Calcula el fingerprint de la solicitud y lo agrega al score
func Fingerprint() Middleware {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := verdict.From(r.Context()); v != nil {
				fp := fingerprint.Compute(r.Header)
				v.Fingerprint = fp.Hash
				if len(fp.Missing) > 0 {
					v.Signals.HeadersIncomplete = true
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Verifica si la User-Agent es sospechosa
func SuspiciousUA() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := verdict.From(r.Context()); v != nil && isToolUA(r.UserAgent()) {
				v.Signals.UATool = true
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isToolUA(ua string) bool {
	return ua == "" || strings.Contains(ua, "curl")
}

// Bloqua honeypots (rutas que no existen)
func Honeypot(paths ...string) Middleware {
	trap := make(map[string]bool)
	for _, path := range paths {
		trap[path] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := verdict.From(r.Context()); v != nil && trap[r.URL.Path] {
				v.Signals.Honeypot = true
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RateLimit(store ratelimit.RateStore, log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v := verdict.From(r.Context())
			if v == nil || v.ClientIP == (netip.Addr{}) {
				v = &verdict.Verdict{}
			}
			ip := v.ClientIP.String()
			res, err := store.Allow(r.Context(), ip)
			switch {
			case err != nil:
				log.Warn("ratelimit no disponible", "err", err)
			case !res.Allowed && v != nil:
				v.Signals.RateExceeded = true
			default:
				w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(res.Remaining))
			}
			next.ServeHTTP(w, r)
		})
	}
}

func ClientIP(res *clientip.Resolver) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := verdict.From(r.Context()); v != nil {
				v.ClientIP = res.ClientIP(r)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func Score(s *scoring.Scorer) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := verdict.From(r.Context()); v != nil {
				v.Score, v.Reasons, v.Decision = s.Evaluate(v.Signals)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func Rules(e *rules.Engine, bots *goodbot.Verifier, dnsTimeout time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v := verdict.From(r.Context())
			if v == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Si un middleware anterior (ACL) ya puso una negación dura, no la pisamos.
			if v.Signals.DenyReason == "" {
				v.Signals.DenyReason = e.DenyReason(v.ClientIP, r.URL.Path)
			}
			v.Signals.Honeypot = e.IsHoneypot(r.URL.Path)

			ctx, cancel := context.WithTimeout(r.Context(), dnsTimeout)
			claimed, verified := bots.Verify(ctx, r.UserAgent(), v.ClientIP)
			cancel()
			v.Signals.VerifiedBot = verified
			v.Signals.FakeBot = claimed && !verified

			next.ServeHTTP(w, r)
		})
	}
}

func Reputation(rep *reputation.Reader, log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		if rep == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := verdict.From(r.Context()); v != nil && v.JA4 != "" {
				bad, _, err := rep.Bad(r.Context(), v.JA4)
				if err != nil {
					log.Warn("reputation no disponible", "err", err)
				}
				v.Signals.JA4Reputation = bad
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ACL consulta los bloqueos y la allowlist de la Admin API (en Redis, con caché
// local) y solo deja señales: un bloqueo va a DenyReason (negación dura, el
// scorer devuelve Block y Enforce lo aplica aunque la ruta esté en monitor) y
// la allowlist a Signals.Allowlisted. Decide el scorer, como con todo lo demás.
// Va apenas se conocen la IP y el JA4 (después de ClientIP y JA4).
func ACL(store *acl.Store, log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		if store == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := verdict.From(r.Context()); v != nil {
				m, err := store.Check(r.Context(), v.ClientIP, v.JA4)
				if err != nil {
					log.Warn("acl no disponible", "err", err)
				}
				if m.Block != nil && v.Signals.DenyReason == "" {
					v.Signals.DenyReason = m.Block.SignalReason()
				}
				v.Signals.Allowlisted = m.Allow != nil
			}
			next.ServeHTTP(w, r)
		})
	}
}
