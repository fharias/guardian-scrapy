package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/fharias/guardian-scrapy/internal/events"
)

type captureSink struct{ got []events.Event }

func (c *captureSink) Emit(ev events.Event)        { c.got = append(c.got, ev) }
func (c *captureSink) Close(context.Context) error { return nil }

// El middleware de eventos va AFUERA de Trace, como en main. El trace_id
// tiene que llegar igual al evento (viaja en el Verdict, no en el ctx).
func TestEventCarriesTraceIDFromInnerTrace(t *testing.T) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	tr := tp.Tracer("test")
	h, err := events.NewHasher("0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{}
	route := func(string) string { return "/api" }

	srv := Chain(TracedUpstream(tr, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })),
		Init,
		events.Middleware(sink, h, route),
		Trace(tr, TraceOptions{Route: route}),
	)
	srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/prices", nil))

	if len(sink.got) != 1 {
		t.Fatalf("eventos = %d, want 1", len(sink.got))
	}
	var root string
	for _, s := range sr.Ended() {
		if s.Name() == "GET /api" {
			root = s.SpanContext().TraceID().String()
		}
	}
	if root == "" || sink.got[0].TraceID != root {
		t.Fatalf("trace_id del evento = %q, want %q (el del span raíz)", sink.got[0].TraceID, root)
	}
}
