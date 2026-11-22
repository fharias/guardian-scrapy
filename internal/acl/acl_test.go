package acl

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

const testJA4 = "t13d4907h2_0d8feac7bc37_7395dae3b2f3"

// clock es un reloj manual: la caché local usa Options.Now y Redis (miniredis)
// avanza con FastForward. Los tests mueven los dos juntos con advance.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	mr  *miniredis.Miniredis
	rdb *redis.Client
	clk *clock
}

func newEnv(t *testing.T) *env {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	return &env{mr: mr, rdb: rdb, clk: &clock{t: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}}
}

// replica crea un Store con su PROPIA caché sobre el mismo Redis: eso es una
// réplica más de guardian.
func (e *env) replica(cacheTTL time.Duration) *Store {
	return New(e.rdb, "shop", Options{CacheTTL: cacheTTL, StaleTTL: time.Minute, LookupTimeout: time.Second, Now: e.clk.Now})
}

func (e *env) advance(d time.Duration) {
	e.clk.Add(d)
	e.mr.FastForward(d)
}

func put(t *testing.T, s *Store, list List, kind Kind, value string, ttl time.Duration) {
	t.Helper()
	v, err := Normalize(list, kind, value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(context.Background(), Entry{List: list, Kind: kind, Value: v, Reason: "test", Actor: "t"}, ttl); err != nil {
		t.Fatal(err)
	}
}

var ip = netip.MustParseAddr("203.0.113.10")

func TestNormalize(t *testing.T) {
	cases := []struct {
		list  List
		kind  Kind
		in    string
		want  string
		isErr bool
	}{
		{Block, KindIP, "203.0.113.10", "203.0.113.10", false},
		{Block, KindIP, "::ffff:203.0.113.10", "203.0.113.10", false}, // IPv4 mapeada = misma llave
		{Block, KindIP, "2001:0db8:0000::0001", "2001:db8::1", false},
		{Block, KindIP, "fe80::1%eth0", "", true}, // zona: no tiene sentido en una IP de cliente
		{Block, KindIP, "203.0.113.0/24", "", true},
		{Block, KindJA4, "T13D4907H2_0D8FEAC7BC37_7395DAE3B2F3", testJA4, false},
		{Block, KindJA4, "no-es-ja4", "", true},
		{Allow, KindJA4, testJA4, "", true}, // la allowlist no acepta JA4
		{Allow, KindIP, "10.0.0.1", "10.0.0.1", false},
		{Block, "fp", "abc", "", true},
		{"otra", KindIP, "10.0.0.1", "", true},
	}
	for _, c := range cases {
		got, err := Normalize(c.list, c.kind, c.in)
		if c.isErr {
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("Normalize(%s,%s,%q) err=%v, quería ErrInvalid", c.list, c.kind, c.in, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("Normalize(%s,%s,%q) = %q,%v; want %q", c.list, c.kind, c.in, got, err, c.want)
		}
	}
}

func TestPutCheckAndTTLExpiry(t *testing.T) {
	e := newEnv(t)
	s := e.replica(2 * time.Second)
	put(t, s, Block, KindIP, "203.0.113.10", 10*time.Minute)

	m, err := s.Check(context.Background(), ip, "")
	if err != nil || m.Block == nil || m.Block.SignalReason() != "bloqueo_admin_ip" {
		t.Fatalf("esperaba bloqueo por ip: %+v err=%v", m, err)
	}
	if ttl := e.mr.TTL("gd:shop:acl:block:ip:203.0.113.10"); ttl != 10*time.Minute {
		t.Fatalf("TTL en Redis = %s, want 10m", ttl)
	}

	e.advance(10*time.Minute + time.Second) // Redis borra la llave sola
	if e.mr.Exists("gd:shop:acl:block:ip:203.0.113.10") {
		t.Fatal("la llave debió expirar en Redis")
	}
	m, err = s.Check(context.Background(), ip, "")
	if err != nil || m.Block != nil {
		t.Fatalf("después del TTL no debe bloquear: %+v err=%v", m, err)
	}
}

func TestCachedEntryHonorsItsOwnExpiry(t *testing.T) {
	e := newEnv(t)
	s := e.replica(time.Hour) // caché absurda a propósito
	put(t, s, Block, KindJA4, testJA4, time.Second)
	if m, _ := s.Check(context.Background(), netip.Addr{}, testJA4); m.Block == nil {
		t.Fatal("esperaba bloqueo por ja4")
	}
	e.clk.Add(2 * time.Second) // sin FastForward: el dato sigue en la caché
	if m, _ := s.Check(context.Background(), netip.Addr{}, testJA4); m.Block != nil {
		t.Fatal("la caché no puede extender un bloqueo más allá de su expires_at")
	}
}

func TestTwoReplicasPropagation(t *testing.T) {
	e := newEnv(t)
	a, b := e.replica(2*time.Second), e.replica(2*time.Second)
	ctx := context.Background()

	if m, _ := b.Check(ctx, ip, testJA4); m.Block != nil {
		t.Fatal("al inicio no hay nada")
	} // B ya cacheó "no existe" para la IP y el JA4

	put(t, a, Block, KindJA4, testJA4, time.Hour) // el bloqueo entra por la réplica A
	if m, _ := a.Check(ctx, ip, testJA4); m.Block == nil {
		t.Fatal("A lo debe ver YA: Put invalida su propia caché")
	}
	if m, _ := b.Check(ctx, ip, testJA4); m.Block != nil {
		t.Fatal("B todavía confía en su caché (staleness acotada por cache_ttl)")
	}
	e.advance(2 * time.Second)
	m, _ := b.Check(ctx, ip, testJA4)
	if m.Block == nil || m.Block.SignalReason() != "bloqueo_admin_ja4" {
		t.Fatalf("pasado cache_ttl, B debe ver el bloqueo de A: %+v", m)
	}

	if ok, err := a.Delete(ctx, Block, KindJA4, testJA4); !ok || err != nil {
		t.Fatalf("Delete = %v, %v", ok, err)
	}
	e.advance(2 * time.Second)
	if m, _ := b.Check(ctx, ip, testJA4); m.Block != nil {
		t.Fatal("el desbloqueo también se propaga")
	}
}

func TestCacheAvoidsRoundTrips(t *testing.T) {
	e := newEnv(t)
	s := e.replica(2 * time.Second)
	s.Check(context.Background(), ip, testJA4) // llena la caché (IP allow, IP block, JA4 block)
	before := e.mr.CommandCount()
	for i := 0; i < 100; i++ {
		s.Check(context.Background(), ip, testJA4)
	}
	if n := e.mr.CommandCount() - before; n != 0 {
		t.Fatalf("con la caché fresca no debe tocar Redis; hizo %d comandos", n)
	}
	e.advance(2 * time.Second)
	before = e.mr.CommandCount()
	s.Check(context.Background(), ip, testJA4)
	if e.mr.CommandCount() == before {
		t.Fatal("vencida la caché, debe volver a preguntarle a Redis")
	}
}

func TestFailOpenServesStale(t *testing.T) {
	e := newEnv(t)
	s := e.replica(2 * time.Second)
	ctx := context.Background()
	put(t, s, Block, KindIP, ip.String(), time.Hour)
	if m, _ := s.Check(ctx, ip, ""); m.Block == nil {
		t.Fatal("esperaba bloqueo")
	}

	e.mr.SetError("LOADING simulado") // Redis responde error a todo
	e.clk.Add(5 * time.Second)        // caché vencida, pero dentro de stale_ttl
	m, err := s.Check(ctx, ip, "")
	if err == nil || m.Block == nil {
		t.Fatalf("con Redis caído, un bloqueo conocido se mantiene (stale-if-error): %+v err=%v", m, err)
	}

	other := netip.MustParseAddr("198.51.100.77")
	m, err = s.Check(ctx, other, "")
	if err == nil || m.Block != nil || m.Allow != nil {
		t.Fatalf("una IP que nunca vimos pasa (fail-open): %+v err=%v", m, err)
	}

	e.clk.Add(2 * time.Minute) // más allá de stale_ttl
	if m, _ := s.Check(ctx, ip, ""); m.Block != nil {
		t.Fatal("pasado stale_ttl ya no confiamos en el dato viejo")
	}
}

func TestBothListsMatch(t *testing.T) {
	e := newEnv(t)
	s := e.replica(0)
	put(t, s, Allow, KindIP, ip.String(), time.Hour)
	put(t, s, Block, KindJA4, testJA4, time.Hour)
	m, err := s.Check(context.Background(), ip, testJA4)
	if err != nil || m.Allow == nil || m.Block == nil {
		t.Fatalf("Check devuelve las dos y decide el scorer: %+v err=%v", m, err)
	}
	if m.Allow.SignalReason() != "allowlist_admin" {
		t.Fatalf("reason = %q", m.Allow.SignalReason())
	}
}

func TestMappedIPMatches(t *testing.T) {
	e := newEnv(t)
	s := e.replica(0)
	put(t, s, Block, KindIP, "::ffff:203.0.113.10", time.Hour)
	if m, _ := s.Check(context.Background(), ip, ""); m.Block == nil {
		t.Fatal("::ffff:203.0.113.10 y 203.0.113.10 son la misma IP")
	}
}

func TestListPrunesExpired(t *testing.T) {
	e := newEnv(t)
	s := e.replica(0)
	put(t, s, Block, KindIP, "203.0.113.1", time.Minute)
	put(t, s, Block, KindJA4, testJA4, time.Hour)
	put(t, s, Allow, KindIP, "10.0.0.1", time.Hour)

	e.advance(2 * time.Minute)
	got, err := s.List(context.Background(), Block)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Value != testJA4 {
		t.Fatalf("List(block) = %+v, want solo el ja4", got)
	}
	if n, _ := e.rdb.ZCard(context.Background(), "gd:shop:acl:index:block").Result(); n != 1 {
		t.Fatalf("el índice debió podarse a 1, tiene %d", n)
	}
}

func TestPutRejectsZeroTTL(t *testing.T) {
	e := newEnv(t)
	s := e.replica(0)
	_, err := s.Put(context.Background(), Entry{List: Block, Kind: KindIP, Value: "1.2.3.4"}, 0)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}
