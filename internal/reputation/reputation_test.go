package reputation

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
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
	r := NewReader(rdb, "shop", Config{Enabled: true, LookupTimeout: 50 * time.Millisecond})
	bad, _, err := r.Bad(context.Background(), "t13d1516h2_8daaf6152771_02713d6af862")
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
