package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/fharias/guardian-scrapy/internal/clientip"
	"github.com/fharias/guardian-scrapy/internal/fingerprint"
	"github.com/fharias/guardian-scrapy/internal/goodbot"
	"github.com/fharias/guardian-scrapy/internal/ratelimit"
	"github.com/fharias/guardian-scrapy/internal/rules"
	"github.com/fharias/guardian-scrapy/internal/scoring"
	"github.com/fharias/guardian-scrapy/internal/tlshello"
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
			log.Info("request", attrs...)
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

			v.Signals.DenyReason = e.DenyReason(v.ClientIP, r.URL.Path)
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
