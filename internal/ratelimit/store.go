package ratelimit

import "context"

type Result struct {
	Allowed   bool
	Remaining int
}
type RateStore interface {
	Allow(ctx context.Context, key string) (Result, error)
}
