package ratelimit

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var failOpenTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "guardian_fail_open_total",
	Help: "Peticiones resueltas con el limitador local porque Redis no respondió.",
}, []string{"reason"})

type FailoverStore struct {
	primary  RateStore
	fallback RateStore
	timeout  time.Duration
	maxFails int32
	cooldown time.Duration
	log      *slog.Logger

	fails     atomic.Int32
	openUntil atomic.Int64
}

var _ RateStore = (*FailoverStore)(nil)

func NewFailoverStore(primary, fallback RateStore, timeout time.Duration,
	maxFails int32, cooldown time.Duration, log *slog.Logger) *FailoverStore {
	return &FailoverStore{
		primary: primary, fallback: fallback, timeout: timeout,
		maxFails: maxFails, cooldown: cooldown, log: log,
	}
}

func markFailOpen(ctx context.Context, reason string) {
	trace.SpanFromContext(ctx).AddEvent("fail_open",
		trace.WithAttributes(attribute.String("reason", reason)))
}

func (f *FailoverStore) Allow(ctx context.Context, key string) (Result, error) {
	if time.Now().UnixNano() < f.openUntil.Load() {
		failOpenTotal.WithLabelValues("circuit_open").Inc()
		markFailOpen(ctx, "circuit_open")
		return f.fallback.Allow(ctx, key)
	}

	rctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	res, err := f.primary.Allow(rctx, key)
	if err == nil {
		f.fails.Store(0)
		return res, nil
	}

	reason := "error"
	if rctx.Err() != nil {
		reason = "timeout"
	}
	failOpenTotal.WithLabelValues(reason).Inc()
	markFailOpen(ctx, reason)
	if f.fails.Add(1) >= f.maxFails {
		f.openUntil.Store(time.Now().Add(f.cooldown).UnixNano())
		f.fails.Store(0)
		f.log.Warn("circuito abierto: usando limitador local",
			"cooldown", f.cooldown.String(), "err", err)
	}
	return f.fallback.Allow(ctx, key)
}
