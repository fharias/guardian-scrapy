package ratelimit

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

type countingPrimary struct{ created map[string]int }

func (c *countingPrimary) new(app string, rate float64, burst int) RateStore {
	c.created[app]++
	return NewMemoryStore(rate, burst)
}

func TestPoolReutilizaPorApp(t *testing.T) {
	cp := &countingPrimary{created: map[string]int{}}
	p := NewPool(cp.new, 50*time.Millisecond, 5, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))

	shop := p.Get("shop", 1, 2)
	if p.Get("shop", 1, 2) != shop {
		t.Fatal("mismo rate/burst debe devolver el MISMO store (el breaker sobrevive la recarga)")
	}
	api := p.Get("api", 20, 40)
	if api == shop {
		t.Fatal("cada app tiene su store")
	}
	if p.Get("shop", 5, 10) == shop {
		t.Fatal("si cambia el rate, el store se reemplaza")
	}
	if cp.created["shop"] != 2 || cp.created["api"] != 1 {
		t.Fatalf("creados = %v", cp.created)
	}
	if len(p.stores) != 2 {
		t.Fatalf("el pool crece por app, no por versión: %d", len(p.stores))
	}

	// Cada app consume SU burst: agotar shop no toca api.
	ctx := context.Background()
	shop = p.Get("shop", 5, 10)
	for range 10 {
		shop.Allow(ctx, "1.2.3.4")
	}
	if r, _ := shop.Allow(ctx, "1.2.3.4"); r.Allowed {
		t.Fatal("shop debía agotarse")
	}
	if r, _ := api.Allow(ctx, "1.2.3.4"); !r.Allowed {
		t.Fatal("api no comparte bucket con shop")
	}
}

func TestPoolJanitor(t *testing.T) {
	p := NewPool(func(string, float64, int) RateStore { return NewMemoryStore(1, 1) }, time.Millisecond, 1, time.Second,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	p.Get("shop", 1, 1)
	ctx, cancel := context.WithCancel(context.Background())
	p.StartJanitor(ctx, time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Recargas que piden stores mientras el janitor recorre el pool (-race).
	for i := range 200 {
		p.Get([]string{"shop", "api", "blog"}[i%3], float64(i%2+1), 1)
		if i%50 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
}
