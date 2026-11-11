package middleware

import (
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/fharias/guardian-scrapy/internal/clientip"
	"github.com/fharias/guardian-scrapy/internal/fingerprint"
	"github.com/fharias/guardian-scrapy/internal/ratelimit"
	"github.com/fharias/guardian-scrapy/internal/verdict"
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
			log.Info("request",
				"client_ip", v.ClientIP.String(),

				"fingerprint", v.Fingerprint,
				"method", r.Method,
				"path", r.URL.Path,
				"score", v.Score,
				"decision", v.Decision.String(),
				"reasons", v.Reasons,
				"dur_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

// Calcula el fingerprint de la solicitud y lo agrega al score
func Fingerprint(weight int) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := verdict.From(r.Context()); v != nil {
				fp := fingerprint.Compute(r.Header)
				v.Fingerprint = fp.Hash
				if len(fp.Missing) > 0 {
					v.Score += weight
					v.Reasons = append(v.Reasons, "headers_incompletos")
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Verifica si la User-Agent es sospechosa
func SuspiciousUA(points int) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := verdict.From(r.Context()); v != nil {
				ua := strings.ToLower(r.UserAgent())
				switch {
				case ua == "":
					v.Add(points, "ua_vacio")
				case strings.Contains(ua, "curl"):
					v.Add(points, "ua_herramienta")
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Bloquea la solicitud si el score es mayor o igual a blockAt
func Enforce(blockAt int) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v := verdict.From(r.Context())
			if v != nil && v.Score >= blockAt {
				v.Decision = verdict.Block
				http.Error(w, "acceso denegado", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Bloqua honeypots (rutas que no existen)
func Honeypot(points int, paths ...string) Middleware {
	trap := make(map[string]bool)
	for _, path := range paths {
		trap[path] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := verdict.From(r.Context()); v != nil && trap[r.URL.Path] {
				v.Add(points, "honeypot")
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RateLimit(store ratelimit.RateStore, points int, log *slog.Logger) Middleware {
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
				v.Add(points, "rate_limit")
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
