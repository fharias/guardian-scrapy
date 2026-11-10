package middleware

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/fharias/guardian-scrapy/internal/verdict"
)

// Inicializa el middleware de verificación de acceso
func Init(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := &verdict.Verdict{}
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
