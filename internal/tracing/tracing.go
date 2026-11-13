package tracing

import (
	"context"
	"errors"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

type Config struct {
	Enabled       bool    `yaml:"enabled"`
	Endpoint      string  `yaml:"endpoint"`       // host:puerto OTLP/HTTP, ej. localhost:4318
	Insecure      bool    `yaml:"insecure"`       // HTTP plano: solo local
	SampleRatio   float64 `yaml:"sample_ratio"`   // 0 a 1
	TrustIncoming bool    `yaml:"trust_incoming"` // ¿respetar traceparent de un trusted proxy?
}

func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	var errs []error
	if c.Endpoint == "" {
		errs = append(errs, errors.New("tracing.endpoint es obligatorio si tracing.enabled es true"))
	}
	if c.SampleRatio < 0 || c.SampleRatio > 1 {
		errs = append(errs, errors.New("tracing.sample_ratio debe estar entre 0 y 1"))
	}
	return errors.Join(errs...)
}

func NewProvider(ctx context.Context, c Config, version string, opts ...sdktrace.TracerProviderOption) (*sdktrace.TracerProvider, error) {
	res, err := resource.New(ctx,
		resource.WithTelemetrySDK(),
		resource.WithAttributes(semconv.ServiceName("guardian"), semconv.ServiceVersion(version)),
	)
	if err != nil {
		return nil, err
	}
	opts = append(opts,
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(c.SampleRatio))),
	)
	return sdktrace.NewTracerProvider(opts...), nil
}

func Setup(ctx context.Context, c Config, version string) (shutdown func(context.Context) error, err error) {
	otel.SetTextMapPropagator(propagation.TraceContext{})

	noop := func(context.Context) error { return nil }
	if !c.Enabled {
		return noop, nil
	}
	if err := c.Validate(); err != nil {
		return noop, err
	}
	clientOpts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(c.Endpoint),
		otlptracehttp.WithTimeout(5 * time.Second),
	}
	if c.Insecure {
		clientOpts = append(clientOpts, otlptracehttp.WithInsecure())
	}
	exp, err := otlptracehttp.New(ctx, clientOpts...)
	if err != nil {
		return noop, err
	}
	tp, err := NewProvider(ctx, c, version, sdktrace.WithBatcher(exp))
	if err != nil {
		return noop, err
	}
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}

func InjectUpstream(out *http.Request) {
	out.Header.Del("Traceparent")
	out.Header.Del("Tracestate")
	out.Header.Del("Baggage")
	otel.GetTextMapPropagator().Inject(out.Context(), propagation.HeaderCarrier(out.Header))
}
