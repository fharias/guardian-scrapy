package ratelimit

import (
	"context"
	"testing"
	"time"
)

func runContract(t *testing.T, newStore func(t *testing.T) RateStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("burst y luego niega", func(t *testing.T) {
		s := newStore(t)
		for i, want := range []bool{true, true, false} {
			res, err := s.Allow(ctx, "1.2.3.4")
			if err != nil {
				t.Fatalf("petición %d: %v", i+1, err)
			}
			if res.Allowed != want {
				t.Fatalf("petición %d: allowed = %v, quiero %v", i+1, res.Allowed, want)
			}
		}
	})

	t.Run("recarga tras 1s", func(t *testing.T) {
		s := newStore(t)
		s.Allow(ctx, "k")
		s.Allow(ctx, "k")
		time.Sleep(1100 * time.Millisecond)
		if res, _ := s.Allow(ctx, "k"); !res.Allowed {
			t.Fatal("tras 1,1 s debía haber 1 token")
		}
	})

	t.Run("claves independientes", func(t *testing.T) {
		s := newStore(t)
		s.Allow(ctx, "A")
		s.Allow(ctx, "A")
		if res, _ := s.Allow(ctx, "B"); !res.Allowed {
			t.Fatal("B no debe heredar el consumo de A")
		}
	})
}
func TestMemoryStoreContract(t *testing.T) {
	runContract(t, func(t *testing.T) RateStore { return NewMemoryStore(1, 2) })
}
