package ratelimit

import (
	"context"
	_ "embed"

	"fmt"

	"github.com/redis/go-redis/v9"
)

//go:embed token_bucket.lua
var tokenBucketLua string

var tokenBucket = redis.NewScript(tokenBucketLua)

type RedisStore struct {
	rdb   redis.UniversalClient
	app   string
	rate  float64
	burst int
}

var _ RateStore = (*RedisStore)(nil)

func NewRedisStore(rdb redis.UniversalClient, app string, rate float64, burst int) *RedisStore {
	return &RedisStore{rdb: rdb, app: app, rate: rate, burst: burst}
}

func (s *RedisStore) Allow(ctx context.Context, key string) (Result, error) {
	base := fmt.Sprintf("gd:%s:{%s}", s.app, key)
	keys := []string{base + ":tokens", base + ":ts"}
	res, err := tokenBucket.Run(ctx, s.rdb, keys, s.rate, s.burst).Int64Slice()
	if err != nil {
		return Result{}, fmt.Errorf("ratelimit redis: %w", err)
	}
	return Result{Allowed: res[0] == 1, Remaining: int(res[1])}, nil
}
