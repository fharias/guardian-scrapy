package admin_test

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/fharias/guardian-scrapy/internal/acl"
	"github.com/fharias/guardian-scrapy/internal/admin"
	"github.com/fharias/guardian-scrapy/internal/challenge"
	"github.com/fharias/guardian-scrapy/internal/goodbot"
	"github.com/fharias/guardian-scrapy/internal/middleware"
	"github.com/fharias/guardian-scrapy/internal/policy"
	"github.com/fharias/guardian-scrapy/internal/rules"
	"github.com/fharias/guardian-scrapy/internal/scoring"
	"github.com/fharias/guardian-scrapy/internal/verdict"
)

const (
	token   = "token-de-prueba-0123456789abcdef0123456789abcdef"
	curlJA4 = "t13d4907h2_0d8feac7bc37_7395dae3b2f3"
)

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

// replica es una instancia de guardian: su propio acl.Store (su propia caché),
// su cadena de middlewares y su Admin API, todo sobre el MISMO Redis.
type replica struct {
	proxy http.Handler
	admin http.Handler
	last  *lastVerdict
}

// lastVerdict guarda el veredicto del último request para que el test lo
// inspeccione (lo escribe un middleware justo después de Init).
type lastVerdict struct {
	mu sync.Mutex
	v  *verdict.Verdict
}

func (l *lastVerdict) capture(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		l.v = verdict.From(r.Context())
		l.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

// fakeEdge reemplaza a ClientIP + JA4 de la cadena real: la IP y el JA4 los
// dicta el test por headers.
func fakeEdge(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := verdict.From(r.Context()); v != nil {
			v.ClientIP = netip.MustParseAddr(r.Header.Get("X-Test-IP"))
			v.JA4 = r.Header.Get("X-Test-JA4")
		}
		next.ServeHTTP(w, r)
	})
}

func newReplica(t *testing.T, rdb redis.UniversalClient, clk *clock) replica {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := acl.New(rdb, "shop", acl.Options{CacheTTL: 2 * time.Second, LookupTimeout: time.Second, Now: clk.Now})

	scorer, err := scoring.New(scoring.Config{
		Weights:    scoring.Weights{UATool: 90, HeadersIncomplete: 30},
		Thresholds: scoring.Thresholds{Challenge: 40, Block: 85},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := rules.New(rules.Config{DenyCIDRs: []string{"198.51.100.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	// Todo en monitor: un bloqueo manual se aplica igual (es negación dura).
	modes, err := policy.New(policy.Config{Default: policy.Monitor})
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	rand.Read(key)
	kr, err := challenge.ParseKeyring("k1:" + base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	ch := challenge.NewService(kr, 8, time.Minute, time.Hour)
	bots := goodbot.NewVerifier(nil, net.DefaultResolver, time.Hour)

	last := &lastVerdict{}
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "upstream") })
	proxy := middleware.Chain(upstream,
		middleware.Init,
		last.capture,
		fakeEdge,
		middleware.SuspiciousUA(),
		middleware.ACL(store, logger),
		middleware.Rules(engine, bots, 100*time.Millisecond),
		middleware.Score(scorer),
		middleware.Enforce(ch, modes, logger),
	)

	tokens, err := admin.ParseTokens(token)
	if err != nil {
		t.Fatal(err)
	}
	api, err := admin.NewHandler(admin.Options{Store: store, Tokens: tokens, MaxTTL: 24 * time.Hour, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	return replica{proxy: proxy, admin: api, last: last}
}

// get hace un request al proxy y devuelve el status y el veredicto final.
func (r replica) get(t *testing.T, ip, ja4, ua string) (int, *verdict.Verdict) {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/prices", nil)
	req.Header.Set("X-Test-IP", ip)
	req.Header.Set("X-Test-JA4", ja4)
	req.Header.Set("User-Agent", ua)
	rec := httptest.NewRecorder()
	r.proxy.ServeHTTP(rec, req)
	r.last.mu.Lock()
	defer r.last.mu.Unlock()
	return rec.Code, r.last.v
}

func (r replica) call(t *testing.T, method, path, body string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Guardian-Actor", "test")
	rec := httptest.NewRecorder()
	r.admin.ServeHTTP(rec, req)
	return rec.Code
}

func TestBlockJA4PropagatesToAllReplicas(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	clk := &clock{t: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	advance := func(d time.Duration) { clk.Add(d); mr.FastForward(d) }

	a, b := newReplica(t, rdb, clk), newReplica(t, rdb, clk)
	const browser = "Mozilla/5.0"

	// 1. Antes del bloqueo: B deja pasar el JA4 (y cachea "no existe").
	if code, _ := b.get(t, "203.0.113.10", curlJA4, browser); code != http.StatusOK {
		t.Fatalf("antes del bloqueo B = %d", code)
	}

	// 2. El operador bloquea el JA4 en la Admin API de la réplica A.
	if code := a.call(t, "PUT", "/v1/blocks/ja4/"+curlJA4, `{"ttl":"10m","reason":"scraper de precios"}`); code != http.StatusOK {
		t.Fatalf("PUT = %d", code)
	}

	// 3. A lo aplica de inmediato, desde OTRA IP: se bloquea el JA4, no la IP.
	code, v := a.get(t, "192.0.2.55", curlJA4, browser)
	if code != http.StatusForbidden || v.Signals.DenyReason != "bloqueo_admin_ja4" || v.Decision != verdict.Block {
		t.Fatalf("A = %d %+v", code, v)
	}
	if v.Shadowed {
		t.Fatal("la ruta está en monitor, pero un bloqueo manual NO queda en shadow")
	}

	// 4. B todavía usa su caché (máximo cache_ttl = 2s de atraso)...
	if code, _ := b.get(t, "203.0.113.10", curlJA4, browser); code != http.StatusOK {
		t.Fatalf("dentro de cache_ttl B aún deja pasar; got %d", code)
	}
	// ...y apenas vence, lo ve.
	advance(2 * time.Second)
	if code, v := b.get(t, "203.0.113.10", curlJA4, browser); code != http.StatusForbidden || v.Reasons[0] != "bloqueo_admin_ja4" {
		t.Fatalf("pasado cache_ttl B = %d %+v", code, v)
	}

	// 5. Un JA4 distinto no se ve afectado.
	other := "t13d1516h2_8daaf6152771_e5627efa2ab1"
	if code, _ := b.get(t, "203.0.113.10", other, browser); code != http.StatusOK {
		t.Fatalf("otro JA4 = %d", code)
	}

	// 6. El TTL vence en Redis y todas las réplicas vuelven a dejar pasar.
	advance(10 * time.Minute)
	for name, r := range map[string]replica{"A": a, "B": b} {
		if code, _ := r.get(t, "203.0.113.10", curlJA4, browser); code != http.StatusOK {
			t.Fatalf("después del TTL %s = %d", name, code)
		}
	}
}

func TestAllowlistSkipsHeuristicsButNotHardDenies(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	clk := &clock{t: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	a, b := newReplica(t, rdb, clk), newReplica(t, rdb, clk)

	// Un partner con curl: sin allowlist, ua_herramienta (90) -> Block.
	if code := a.call(t, "PUT", "/v1/allowlist/ip/10.20.30.40", `{"ttl":"1h","reason":"monitor del partner"}`); code != 200 {
		t.Fatalf("PUT allowlist = %d", code)
	}
	code, v := b.get(t, "10.20.30.40", "", "curl/8.7.1")
	if code != http.StatusOK || v.Reasons[0] != "allowlist_admin" || !v.Signals.UATool {
		t.Fatalf("allowlist: %d %+v (la señal se calcula, pero el scorer no la suma)", code, v)
	}

	// Deny gana: bloquear el JA4 que usa ese mismo partner lo bloquea igual.
	if code := a.call(t, "PUT", "/v1/blocks/ja4/"+curlJA4, `{"ttl":"1h","reason":"campaña"}`); code != 200 {
		t.Fatalf("PUT block = %d", code)
	}
	clk.Add(2 * time.Second)
	if code, v := b.get(t, "10.20.30.40", curlJA4, "curl/8.7.1"); code != http.StatusForbidden || v.Reasons[0] != "bloqueo_admin_ja4" {
		t.Fatalf("deny gana a allow: %d %+v", code, v)
	}

	// Y la allowlist tampoco abre un rango de deny_cidrs del YAML.
	if code := a.call(t, "PUT", "/v1/allowlist/ip/198.51.100.9", `{"ttl":"1h","reason":"x"}`); code != 200 {
		t.Fatal("PUT")
	}
	if code, v := b.get(t, "198.51.100.9", "", "Mozilla/5.0"); code != http.StatusForbidden || v.Reasons[0] != "ip_denegada" {
		t.Fatalf("deny_cidrs gana: %d %+v", code, v)
	}
}

func TestManualBlockIsNotOverwrittenByRules(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	clk := &clock{t: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
	a := newReplica(t, rdb, clk)

	if code := a.call(t, "PUT", "/v1/blocks/ip/203.0.113.66", `{"ttl":"1h","reason":"x"}`); code != 200 {
		t.Fatal("PUT")
	}
	// Rules corre DESPUÉS de ACL y esta IP no está en deny_cidrs: antes pisaba
	// DenyReason con "" y el bloqueo se perdía.
	if code, v := a.get(t, "203.0.113.66", "", "Mozilla/5.0"); code != http.StatusForbidden || v.Signals.DenyReason != "bloqueo_admin_ip" {
		t.Fatalf("%d %+v", code, v)
	}
}
