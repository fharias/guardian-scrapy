//go:build integration

package reputation

import (
	"context"
	"testing"

	"github.com/redis/go-redis/v9"

	"github.com/fharias/guardian-scrapy/internal/testutil"
)

// Mismo escenario que TestAggregatorPorApp, pero contra Valkey real:
// PFADD/PFCOUNT, hash tags y TTL los implementa el servidor de verdad,
// no la emulación de miniredis.
func TestAggregatorPorAppValkey(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: testutil.Valkey(t)})
	t.Cleanup(func() { _ = rdb.Close() })
	if err := rdb.FlushAll(context.Background()).Err(); err != nil {
		t.Fatal(err)
	}
	runAggregatorPorApp(t, rdb)
}
