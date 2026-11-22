package events

import (
	"net/http"
	"time"

	"github.com/fharias/guardian-scrapy/internal/verdict"
)

// RouteFunc convierte un path en un label de baja cardinalidad.
// NUNCA el path crudo.
type RouteFunc func(path string) string

// Middleware emite un Event al volver de la cadena, cuando el veredicto
// ya está completo (mode, shadow, decision, reasons, ja4, trace_id).
// Va justo después de Init y de las métricas, envolviendo el resto.
func Middleware(sink EventSink, hasher *Hasher, route RouteFunc) func(http.Handler) http.Handler {
	if sink == nil {
		sink = Noop()
	}
	if route == nil {
		route = func(string) string { return "default" }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			v := verdict.From(r.Context())
			if v == nil {
				return
			}
			reasons := append([]string(nil), v.Reasons...)
			mode := v.Mode
			if mode == "" {
				mode = "none"
			}
			ev := Event{
				Time:        time.Now().UTC(),
				App:         v.App,
				IPHash:      hasher.Hash(v.ClientIP),
				JA4:         v.JA4,
				JA4Source:   v.JA4Source,
				Fingerprint: v.Fingerprint,
				Route:       route(r.URL.Path),
				Method:      r.Method,
				Score:       v.Score,
				Decision:    v.Decision.String(),
				Reasons:     reasons,
				Mode:        mode,
				Shadow:      v.Shadowed,
			}
			ev.TraceID = v.TraceID
			sink.Emit(ev)
		})
	}
}
