package ratelimit

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type MemoryStore struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	rate     rate.Limit
	burst    int
}

var _ RateStore = (*MemoryStore)(nil)

func NewMemoryStore(r float64, burst int) *MemoryStore {
	return &MemoryStore{
		limiters: make(map[string]*rate.Limiter),
		rate:     rate.Limit(r),
		burst:    burst,
	}
}

func (s *MemoryStore) Allow(_ context.Context, key string) (Result, error) {
	s.mu.Lock()
	lim, ok := s.limiters[key]
	if !ok {
		lim = rate.NewLimiter(s.rate, s.burst)
		s.limiters[key] = lim
	}
	s.mu.Unlock()

	allowed := lim.Allow()
	return Result{Allowed: allowed, Remaining: int(lim.Tokens())}, nil
}

func (s *MemoryStore) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for key, lim := range s.limiters {
		if lim.Tokens() >= float64(s.burst) {
			delete(s.limiters, key)
			removed++
		}
	}
	return removed
}

func (s *MemoryStore) StartJanitor(ctx context.Context, every time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(every)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n := s.Cleanup(); n > 0 {
					log.Debug("limpieza de limitadores locales", "borrados", n)
				}
			}
		}
	}()
}
