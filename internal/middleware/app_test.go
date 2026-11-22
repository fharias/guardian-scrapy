package middleware

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/fharias/guardian-scrapy/internal/events"
)

// La app se fija UNA vez (middleware.App, justo después de Init) y de ahí la
// leen el evento, el span raíz y la línea de log. Nadie vuelve a mirar el Host.
func TestAppLlegaAEventoTraceYLog(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	h, err := events.NewHasher("0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{}
	var logs bytes.Buffer
	route := func(string) string { return "/api" }

	srv := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}),
		Init,
		App("api"),
		events.Middleware(sink, h, route),
		Trace(tp.Tracer("test"), TraceOptions{Route: route}),
		Logger(slog.New(slog.NewJSONHandler(&logs, nil))),
	)
	req := httptest.NewRequest(http.MethodGet, "/api/prices", nil)
	req.Host = "otro-host-que-no-importa.example"
	srv.ServeHTTP(httptest.NewRecorder(), req)

	if len(sink.got) != 1 || sink.got[0].App != "api" {
		t.Fatalf("evento = %+v", sink.got)
	}
	var app string
	for _, s := range sr.Ended() {
		for _, a := range s.Attributes() {
			if a.Key == "guardian.app" {
				app = a.Value.AsString()
			}
		}
	}
	if app != "api" {
		t.Fatalf("guardian.app = %q", app)
	}
	if !strings.Contains(logs.String(), `"app":"api"`) {
		t.Fatalf("log sin app: %s", logs.String())
	}
}
