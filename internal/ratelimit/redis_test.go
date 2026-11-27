//go:build integration

package ratelimit

import (
	"context"
	"testing"

	"github.com/redis/go-redis/v9"

	"github.com/fharias/guardian-scrapy/internal/testutil"
)

func TestRedisStoreTokenBucket(t *testing.T) {
	ctx := context.Background()
	rdb := redis.NewClient(&redis.Options{Addr: testutil.Valkey(t)})
	t.Cleanup(func() { _ = rdb.Close() })

	runContract(t, func(t *testing.T) RateStore {
		if err := rdb.FlushAll(ctx).Err(); err != nil {
			t.Fatal(err)
		}
		return NewRedisStore(rdb, "test", 1, 2)
	})
}
