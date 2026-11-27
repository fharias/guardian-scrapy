package reputation

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/fharias/guardian-scrapy/internal/events"
)

func TestValidate(t *testing.T) {
	ok := Config{Enabled: true}.WithDefaults()
	if err := ok.Validate(); err != nil {
		t.Fatalf("los defaults deben ser válidos: %v", err)
	}
	bad := Config{Enabled: true, Window: time.Hour, Bucket: 7 * time.Minute}.WithDefaults()
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "múltiplo") {
		t.Fatalf("esperaba error de múltiplo, obtuve %v", err)
	}
	if err := (Config{Enabled: false, Window: -1}).Validate(); err != nil {
		t.Fatalf("deshabilitado no valida nada: %v", err)
	}
}

func TestWindowKeysShareHashTag(t *testing.T) {
	cfg := Config{Window: time.Hour, Bucket: 10 * time.Minute}
	now := time.Date(2026, 11, 16, 12, 34, 0, 0, time.UTC)
	keys := cfg.windowKeys("shop", "t13d", now)
	if len(keys) != 6 {
		t.Fatalf("1h / 10m = 6 buckets, obtuve %d", len(keys))
	}
	for _, k := range keys {
		if !strings.Contains(k, "{t13d}") {
			t.Fatalf("la llave %q debe llevar el hash tag {t13d}", k)
		}
	}
	// el primero es el bucket actual: 12:30 UTC
	if want := hllKey("shop", "t13d", time.Date(2026, 11, 16, 12, 30, 0, 0, time.UTC)); keys[0] != want {
		t.Fatalf("keys[0] = %q, esperaba %q", keys[0], want)
	}
}

func TestReaderFailOpen(t *testing.T) {
	// Puerto 1: nadie escucha. Simula Valkey caído.
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	defer rdb.Close()
	r := NewReader(rdb, Config{Enabled: true, LookupTimeout: 50 * time.Millisecond})
	bad, _, err := r.Bad(context.Background(), "shop", "t13d1516h2_8daaf6152771_02713d6af862")
	if err == nil {
		t.Fatal("esperaba un error de conexión")
	}
	if bad {
		t.Fatal("fail-open: con Redis caído, Bad debe ser false")
	}
	if len(r.cache) != 0 {
		t.Fatal("un error no se cachea")
	}
}

// Cada evento cuenta en SU app: 3 IPs con el mismo JA4 en shop marcan el JA4
// en shop; las mismas 3 IPs repartidas en dos apps no marcan nada. Un evento
// sin app (versión anterior de guardian) cae en la app por defecto.
func TestAggregatorPorApp(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	runAggregatorPorApp(t, rdb)
}

// runAggregatorPorApp es el escenario compartido: corre igual contra
// miniredis (go test normal) y contra Valkey real (-tags=integration).
func runAggregatorPorApp(t *testing.T, rdb *redis.Client) {
	t.Helper()
	ctx := context.Background()
	const ja4 = "t13d1516h2_8daaf6152771_02713d6af862"
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	agg := NewAggregator(rdb, "shop", Config{Enabled: true, MinDistinctIPs: 3})
	agg.now = func() time.Time { return now }

	ev := func(app, ip string) events.Event {
		return events.Event{Time: now, App: app, IPHash: ip, JA4: ja4}
	}
	marked, err := agg.Apply(ctx, []events.Event{
		ev("api", "a"), ev("api", "b"), ev("api", "c"), // 3 IPs en api: marca
		ev("shop", "a"), ev("", "b"), // 2 en shop (una sin app -> shop): no marca
		ev("Mal:Nombre", "z"), // inválido -> shop: ahora son 3 en shop
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, m := range marked {
		got[m.App] = m.DistinctIPs
	}
	if got["api"] != 3 || got["shop"] != 3 || len(got) != 2 {
		t.Fatalf("marked = %+v", marked)
	}
	keys, err := rdb.Keys(ctx, "*").Result()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if !strings.HasPrefix(k, "gd:shop:") && !strings.HasPrefix(k, "gd:api:") {
			t.Errorf("llave fuera de prefijo: %s", k)
		}
		if strings.Contains(k, "Mal") {
			t.Errorf("un nombre inválido llegó a una llave: %s", k)
		}
	}

	r := NewReader(rdb, Config{Enabled: true, CacheTTL: time.Minute})
	if bad, _, _ := r.Bad(ctx, "api", ja4); !bad {
		t.Fatal("api debe ver la marca")
	}
	if bad, _, _ := r.Bad(ctx, "blog", ja4); bad {
		t.Fatal("blog no tiene marca: la caché no puede mezclar apps")
	}
	if bad, _, _ := r.Bad(ctx, "a:b", ja4); bad {
		t.Fatal("app inválida = sin reputación")
	}
}
