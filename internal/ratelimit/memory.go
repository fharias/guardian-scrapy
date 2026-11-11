package ratelimit

import (
	"context"
	"sync"

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
