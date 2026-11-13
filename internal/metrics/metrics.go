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
}

func New(reg prometheus.Registerer) *Metrics {
	f := promauto.With(reg)
	return &Metrics{
		requests: f.NewCounterVec(prometheus.CounterOpts{
			Name: "guardian_http_requests_total",
			Help: "Requests atendidos por guardian, por ruta, método y status code.",
		}, []string{"route", "method", "code"}),
		duration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "guardian_http_request_duration_seconds",
			Help:    "Latencia total del request dentro de guardian (incluye upstream).",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		}, []string{"route", "method"}),
		inFlight: f.NewGauge(prometheus.GaugeOpts{
			Name: "guardian_http_requests_in_flight",
			Help: "Requests en curso en este momento.",
		}),
		decisions: f.NewCounterVec(prometheus.CounterOpts{
			Name: "guardian_decisions_total",
			Help: "Decisiones del scorer por modo y si quedaron en shadow.",
		}, []string{"decision", "mode", "shadow"}),
		signals: f.NewCounterVec(prometheus.CounterOpts{
			Name: "guardian_signals_total",
			Help: "Veces que cada reason sumó al score.",
		}, []string{"reason"}),
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

			rt, method := route(r.URL.Path), normMethod(r.Method)
			m.requests.WithLabelValues(rt, method, strconv.Itoa(sw.status)).Inc()
			m.duration.WithLabelValues(rt, method).Observe(time.Since(start).Seconds())

			if v := verdict.From(r.Context()); v != nil {
				mode := v.Mode
				if mode == "" {
					mode = "none"
				}
				m.decisions.WithLabelValues(v.Decision.String(), mode, strconv.FormatBool(v.Shadowed)).Inc()
				for _, reason := range v.Reasons {
					m.signals.WithLabelValues(reason).Inc()
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
