package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/fharias/guardian-scrapy/internal/verdict"
)

// RouteFunc convierte un path en un label de baja cardinalidad.
// NUNCA debe devolver el path crudo.
type RouteFunc func(path string) string

type Metrics struct {
	requests  *prometheus.CounterVec
	duration  *prometheus.HistogramVec
	inFlight  prometheus.Gauge
	decisions *prometheus.CounterVec
	signals   *prometheus.CounterVec

	// UnknownHost cuenta los requests cuyo Host no es de ninguna app (421).
	// SIN label host: el Host lo escribe el cliente, y un scanner que manda
	// un Host distinto por request crearía una serie por request.
	UnknownHost prometheus.Counter
}

func New(reg prometheus.Registerer) *Metrics {
	f := promauto.With(reg)
	return &Metrics{
		requests: f.NewCounterVec(prometheus.CounterOpts{
			Name: "guardian_http_requests_total",
			Help: "Requests atendidos por guardian, por app, ruta, método y status code.",
		}, []string{"app", "route", "method", "code"}),
		duration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "guardian_http_request_duration_seconds",
			Help:    "Latencia total del request dentro de guardian (incluye upstream).",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		}, []string{"app", "route", "method"}),
		inFlight: f.NewGauge(prometheus.GaugeOpts{
			Name: "guardian_http_requests_in_flight",
			Help: "Requests en curso en este momento.",
		}),
		decisions: f.NewCounterVec(prometheus.CounterOpts{
			Name: "guardian_decisions_total",
			Help: "Decisiones del scorer por app, modo y si quedaron en shadow.",
		}, []string{"app", "decision", "mode", "shadow"}),
		signals: f.NewCounterVec(prometheus.CounterOpts{
			Name: "guardian_signals_total",
			Help: "Veces que cada reason sumó al score, por app.",
		}, []string{"app", "reason"}),
		UnknownHost: f.NewCounter(prometheus.CounterOpts{
			Name: "guardian_unknown_host_total",
			Help: "Requests con un Host que no es de ninguna app (respondidos con 421).",
		}),
	}
}

// Middleware mide RED y, al volver de la cadena, lee el veredicto.
// Va justo después de Init para que el veredicto ya exista en el contexto.
func (m *Metrics) Middleware(route RouteFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			m.inFlight.Inc()
			defer m.inFlight.Dec()

			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)

			// El label app sale del veredicto (lo puso middleware.App con el
			// nombre validado de la config), NUNCA del Host crudo: así la
			// cardinalidad es la cantidad de apps, no lo que invente un cliente.
			v := verdict.From(r.Context())
			app := "none"
			if v != nil && v.App != "" {
				app = v.App
			}
			rt, method := route(r.URL.Path), normMethod(r.Method)
			m.requests.WithLabelValues(app, rt, method, strconv.Itoa(sw.status)).Inc()
			m.duration.WithLabelValues(app, rt, method).Observe(time.Since(start).Seconds())

			if v != nil {
				mode := v.Mode
				if mode == "" {
					mode = "none"
				}
				m.decisions.WithLabelValues(app, v.Decision.String(), mode, strconv.FormatBool(v.Shadowed)).Inc()
				for _, reason := range v.Reasons {
					m.signals.WithLabelValues(app, reason).Inc()
				}
			}
		})
	}
}

// normMethod evita que un atacante invente métodos ("FOO", "XYZ123"...)
// y te cree una serie temporal nueva por cada uno.
func normMethod(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return m
	}
	return "OTHER"
}

// statusWriter guarda el status code que escribe el handler.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status, s.wroteHeader = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

// Unwrap deja que http.ResponseController (que usa ReverseProxy para Flush)
// encuentre el ResponseWriter original. Sin esto, el streaming se rompe.
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
