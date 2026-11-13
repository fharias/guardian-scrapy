package middleware

import (
	"context"
	"net/http"
	"strconv"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/fharias/guardian-scrapy/internal/verdict"
)

type stepKey struct{}
type step struct {
	span   trace.Span // el span de este middleware
	parent trace.Span // el span que era el actual antes de abrirlo
}

type TraceOptions struct {
	Route         func(path string) string
	TrustIncoming func(r *http.Request) bool // nil = nunca
}

func Trace(tr trace.Tracer, o TraceOptions) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if o.TrustIncoming != nil && o.TrustIncoming(r) {
				ctx = otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(r.Header))
			}

			method, route := spanMethod(r.Method), o.Route(r.URL.Path)
			ctx, span := tr.Start(ctx, method+" "+route,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(
					attribute.String("http.request.method", method),
					attribute.String("http.route", route),
				),
			)
			defer span.End()

			sw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r.WithContext(ctx))

			span.SetAttributes(attribute.Int("http.response.status_code", sw.status))
			if sw.status >= http.StatusInternalServerError {
				span.SetStatus(codes.Error, strconv.Itoa(sw.status))
			}
			if v := verdict.From(ctx); v != nil {
				span.SetAttributes(
					attribute.String("guardian.decision", v.Decision.String()),
					attribute.Int("guardian.score", v.Score),
					attribute.String("guardian.mode", v.Mode),
					attribute.Bool("guardian.shadow", v.Shadowed),
					attribute.StringSlice("guardian.reasons", v.Reasons),
					attribute.String("guardian.ja4_source", v.JA4Source),
				)
			}
		})
	}
}
func Traced(tr trace.Tracer, name string, mw Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		inner := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if st, ok := r.Context().Value(stepKey{}).(*step); ok {
				st.span.End()
				r = r.WithContext(trace.ContextWithSpan(r.Context(), st.parent))
			}
			next.ServeHTTP(w, r)
		}))
		spanName := "mw." + name
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			parent := trace.SpanFromContext(r.Context())
			ctx, span := tr.Start(r.Context(), spanName)
			defer span.End()
			ctx = context.WithValue(ctx, stepKey{}, &step{span: span, parent: parent})
			inner.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func TracedUpstream(tr trace.Tracer, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := tr.Start(r.Context(), "upstream", trace.WithSpanKind(trace.SpanKindClient))
		defer span.End()
		sw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h.ServeHTTP(sw, r.WithContext(ctx))
		span.SetAttributes(attribute.Int("http.response.status_code", sw.status))
		if sw.status >= http.StatusInternalServerError {
			span.SetStatus(codes.Error, strconv.Itoa(sw.status))
		}
	})
}

func spanMethod(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return m
	}
	return "_OTHER"
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status, s.wroteHeader = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
