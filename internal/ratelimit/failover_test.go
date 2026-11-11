package ratelimit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

type brokenStore struct{ calls int }

func (b *brokenStore) Allow(ctx context.Context, key string) (Result, error) {
	b.calls++
	return Result{}, errors.New("redis caído")
}

func TestFailoverOpensCircuit(t *testing.T) {
	broken := &brokenStore{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	f := NewFailoverStore(broken, NewMemoryStore(100, 100), 50*time.Millisecond, 3, time.Minute, log)

	for i := 0; i < 10; i++ {
		res, err := f.Allow(context.Background(), "1.2.3.4")
		if err != nil || !res.Allowed {
			t.Fatalf("petición %d: debió servirse con el local (err=%v)", i+1, err)
		}
	}
	if broken.calls != 3 {
		t.Fatalf("Redis se llamó %d veces, quiero 3: el circuito debió abrirse", broken.calls)
	}
}
