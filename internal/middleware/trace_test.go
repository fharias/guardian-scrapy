package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/fharias/guardian-scrapy/internal/tracing"
)

const incomingTP = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

func newRecorder(t *testing.T) (*tracetest.SpanRecorder, *sdktrace.TracerProvider) {
	t.Helper()
	otel.SetTextMapPropagator(propagation.TraceContext{})
	sr := tracetest.NewSpanRecorder()
	tp, err := tracing.NewProvider(t.Context(), tracing.Config{Enabled: true, SampleRatio: 1}, "test",
		sdktrace.WithSpanProcessor(sr))
	if err != nil {
		t.Fatal(err)
	}
	return sr, tp
}

func ok(w http.ResponseWriter, _ *http.Request)  { w.WriteHeader(http.StatusNoContent) }
func passthrough(next http.Handler) http.Handler { return next }

func TestTracedStepsAreSiblingsUnderRoot(t *testing.T) {
	sr, tp := newRecorder(t)
	tr := tp.Tracer("test")
	h := Chain(TracedUpstream(tr, http.HandlerFunc(ok)),
		Init,
		Trace(tr, TraceOptions{Route: func(string) string { return "/api" }}),
		Traced(tr, "uno", passthrough),
		Traced(tr, "dos", passthrough),
	)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/prices", nil))

	by := map[string]sdktrace.ReadOnlySpan{}
	for _, s := range sr.Ended() {
		by[s.Name()] = s
	}
	root := by["GET /api"]
	if root == nil {
		t.Fatal("falta el span raíz")
	}
	for _, name := range []string{"mw.uno", "mw.dos", "upstream"} {
		s := by[name]
		if s == nil {
			t.Fatalf("falta el span %q", name)
		}
		if s.Parent().SpanID() != root.SpanContext().SpanID() {
			t.Errorf("%s debería colgar del root", name)
		}
	}
	if by["mw.uno"].EndTime().After(by["mw.dos"].StartTime()) {
		t.Error("mw.uno debe terminar antes de que empiece mw.dos")
	}
}

func TestIncomingTraceparent(t *testing.T) {
	cases := []struct {
		name      string
		trust     func(*http.Request) bool
		sameTrace bool
	}{
		{"no confiable: trace nuevo", nil, false},
		{"confiable: continúa el trace", func(*http.Request) bool { return true }, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sr, tp := newRecorder(t)
			h := Chain(http.HandlerFunc(ok), Trace(tp.Tracer("test"),
				TraceOptions{Route: func(string) string { return "/" }, TrustIncoming: c.trust}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Traceparent", incomingTP)
			h.ServeHTTP(httptest.NewRecorder(), req)

			root := sr.Ended()[0]
			same := root.SpanContext().TraceID().String() == strings.Split(incomingTP, "-")[1]
			if same != c.sameTrace {
				t.Errorf("mismo trace = %v, quiero %v", same, c.sameTrace)
			}
		})
	}
}

func TestUpstreamGetsOurTraceparentOnly(t *testing.T) {
	_, tp := newRecorder(t)
	tr := tp.Tracer("test")
	var seen http.Header
	proxyLike := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		out := r.Clone(r.Context())
		tracing.InjectUpstream(out)
		seen = out.Header
	})
	h := Chain(TracedUpstream(tr, proxyLike),
		Trace(tr, TraceOptions{Route: func(string) string { return "/" }}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Traceparent", incomingTP)
	req.Header.Set("Tracestate", "vendor=falso")
	req.Header.Set("Baggage", "user=admin")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got := seen.Get("Traceparent"); got == "" || strings.Contains(got, "0af7651916cd43dd8448eb211c80319c") {
		t.Errorf("el upstream debe recibir nuestro traceparent, no el del cliente: %q", got)
	}
	if seen.Get("Tracestate") != "" || seen.Get("Baggage") != "" {
		t.Error("tracestate y baggage del cliente no deben llegar al upstream")
	}
}
