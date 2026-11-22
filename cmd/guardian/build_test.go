package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/fharias/guardian-scrapy/internal/acl"
	"github.com/fharias/guardian-scrapy/internal/apps"
	"github.com/fharias/guardian-scrapy/internal/challenge"
	"github.com/fharias/guardian-scrapy/internal/clientip"
	"github.com/fharias/guardian-scrapy/internal/configsource"
	"github.com/fharias/guardian-scrapy/internal/events"
	"github.com/fharias/guardian-scrapy/internal/goodbot"
	"github.com/fharias/guardian-scrapy/internal/ja4source"
	"github.com/fharias/guardian-scrapy/internal/metrics"
	"github.com/fharias/guardian-scrapy/internal/middleware"
	"github.com/fharias/guardian-scrapy/internal/ratelimit"
)

const curlUA = "curl/8.7.1"

// captureSink guarda los eventos que emite la cadena real.
type captureSink struct {
	mu  sync.Mutex
	evs []events.Event
}

func (c *captureSink) Emit(ev events.Event)        { c.mu.Lock(); c.evs = append(c.evs, ev); c.mu.Unlock() }
func (c *captureSink) Close(context.Context) error { return nil }
func (c *captureSink) len() int                    { c.mu.Lock(); defer c.mu.Unlock(); return len(c.evs) }
func (c *captureSink) last() events.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.evs[len(c.evs)-1]
}

// stack es guardian completo en memoria: la cadena REAL de build.go, con
// miniredis en vez de Valkey y dos upstreams de httptest.
type stack struct {
	t        *testing.T
	mr       *miniredis.Miniredis
	reg      *prometheus.Registry
	mets     *metrics.Metrics
	acl      *acl.Store
	sink     *captureSink
	path     string
	reloader *configsource.Reloader[*apps.Router]
	h        http.Handler
	shopURL  string
	apiURL   string
}

func upstream(t *testing.T, name string) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s host=%s", name, r.Host)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func newStack(t *testing.T, yml func(s *stack) string) *stack {
	t.Helper()
	s := &stack{t: t, mr: miniredis.RunT(t), reg: prometheus.NewRegistry(), sink: &captureSink{}}
	s.shopURL, s.apiURL = upstream(t, "shop-upstream"), upstream(t, "api-upstream")
	rdb := redis.NewClient(&redis.Options{Addr: s.mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	resolver, err := clientip.New([]string{"192.0.2.0/24"}, "X-Forwarded-For") // httptest usa 192.0.2.1 como peer
	if err != nil {
		t.Fatal(err)
	}
	ja4Src, err := ja4source.New("none", resolver.PeerIsTrusted)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	rand.Read(key)
	kr, err := challenge.ParseKeyring("k1:" + base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := events.NewHasher("sal-de-prueba-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	s.mets = metrics.New(s.reg)
	s.acl = acl.New(rdb, acl.Options{CacheTTL: -1, LookupTimeout: time.Second, Registerer: s.reg})
	deps := &chainDeps{
		logger:    logger,
		tracer:    noop.NewTracerProvider().Tracer("test"),
		clientip:  resolver,
		ja4Source: ja4Src,
		aclStore:  s.acl,
		bots:      goodbot.NewVerifier(nil, net.DefaultResolver, time.Hour),
		ch:        challenge.NewService(kr, 8, time.Minute, time.Hour),
		mets:      s.mets,
		emitFor: func(route events.RouteFunc) middleware.Middleware {
			return events.Middleware(s.sink, hasher, route)
		},
		rates: ratelimit.NewPool(func(app string, rate float64, burst int) ratelimit.RateStore {
			return ratelimit.NewRedisStore(rdb, app, rate, burst)
		}, time.Second, 5, 10*time.Second, logger),
		unknown: misdirected(s.mets, logger),
	}

	s.path = filepath.Join(t.TempDir(), "guardian.yml")
	s.write(yml(s))
	src := configsource.NewFileSource(s.path, 0, logger)
	cfg, version, err := configsource.LoadInitial(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	s.reloader, err = configsource.New(src, cfg, version, deps.build, configsource.Options{
		Logger: logger, Registerer: prometheus.NewRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.h = configsource.Handler(s.reloader)
	return s
}

func (s *stack) write(yml string) {
	s.t.Helper()
	if err := os.WriteFile(s.path, []byte(yml), 0o600); err != nil {
		s.t.Fatal(err)
	}
}

func (s *stack) reload(yml string) {
	s.t.Helper()
	s.write(yml)
	if err := s.reloader.Reload(context.Background(), "test"); err != nil {
		s.t.Fatal(err)
	}
}

// do manda un request como lo haría curl (sin headers de navegador) o como
// un navegador, desde la IP del cliente ip.
func (s *stack) do(host, ip string, browser bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/productos", nil)
	req.Host = host
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("User-Agent", curlUA)
	if browser {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/131.0 Safari/537.36")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Accept-Language", "es-CO")
		req.Header.Set("Accept-Encoding", "gzip")
	}
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, req)
	return rec
}

const baseYAML = `
upstream: %q
trusted_proxies: ["192.0.2.0/24"]
x_forwarded_for_header: "X-Forwarded-For"
challenge: {difficulty: 8}
rate: 100
burst: 100
ja4: {source: none}
scoring:
  weights: {ua_tool: 90, headers_incomplete: 30}
  thresholds: {challenge: 40, block: 85}
modes: {default: enforce}
`

func twoApps(s *stack) string {
	return fmt.Sprintf(baseYAML, s.shopURL) + fmt.Sprintf(`
apps:
  - name: shop
    hosts: ["shop.local", "*.shop.local"]
  - name: api
    hosts: ["api.local"]
    upstream: %q
    rate: 1000
    burst: 1000
    modes: {default: monitor}
`, s.apiURL)
}

// El criterio de "hecho": dos hosts, dos políticas, el MISMO proxy y el MISMO
// cliente (curl). shop.local está en enforce y lo bloquea; api.local está en
// monitor y lo deja pasar en shadow, hacia SU upstream.
func TestDosHostsDosPoliticas(t *testing.T) {
	s := newStack(t, twoApps)

	rec := s.do("shop.local", "203.0.113.7", false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("shop.local + curl = %d %s, want 403", rec.Code, rec.Body)
	}
	if ev := s.sink.last(); ev.App != "shop" || ev.Decision != "block" || ev.Shadow || ev.Mode != "enforce" {
		t.Fatalf("evento shop = %+v", ev)
	}

	rec = s.do("API.local:8080", "203.0.113.7", false) // puerto y mayúsculas
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "api-upstream") {
		t.Fatalf("api.local + curl = %d %q, want 200 desde api-upstream", rec.Code, rec.Body)
	}
	if ev := s.sink.last(); ev.App != "api" || ev.Decision != "block" || !ev.Shadow || ev.Mode != "monitor" {
		t.Fatalf("evento api = %+v (debe ser block en shadow)", ev)
	}

	// Comodín: www.shop.local es shop.
	if rec := s.do("www.shop.local", "203.0.113.8", false); rec.Code != http.StatusForbidden {
		t.Fatalf("www.shop.local = %d", rec.Code)
	}
	// Un navegador pasa en shop y llega al upstream de shop con su Host.
	rec = s.do("shop.local", "203.0.113.9", true)
	if rec.Code != 200 || !strings.HasPrefix(rec.Body.String(), "shop-upstream") {
		t.Fatalf("shop.local + navegador = %d %q", rec.Code, rec.Body)
	}
	// Host desconocido y sin default_app: 421, sin pasar por ninguna cadena.
	n := s.sink.len()
	if rec := s.do("evil.example", "203.0.113.7", true); rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("host desconocido = %d, want 421", rec.Code)
	}
	if s.sink.len() != n {
		t.Fatal("un host desconocido no debe emitir eventos: no es de ninguna app")
	}
	if got := testutil.ToFloat64(s.mets.UnknownHost); got != 1 {
		t.Fatalf("guardian_unknown_host_total = %v", got)
	}
}

// Las llaves de cada app viven bajo su prefijo: el rate limit de api no
// gasta tokens de shop, y un bloqueo manual en api no existe para shop.
func TestLlavesAisladasPorApp(t *testing.T) {
	s := newStack(t, twoApps)
	s.do("shop.local", "203.0.113.20", true)
	s.do("api.local", "203.0.113.20", true)

	var shopKeys, apiKeys int
	for _, k := range s.mr.Keys() {
		switch {
		case strings.HasPrefix(k, "gd:shop:{203.0.113.20}"):
			shopKeys++
		case strings.HasPrefix(k, "gd:api:{203.0.113.20}"):
			apiKeys++
		default:
			t.Errorf("llave fuera de los prefijos de app: %s", k)
		}
	}
	if shopKeys == 0 || apiKeys == 0 {
		t.Fatalf("cada app debe tener su bucket: %v", s.mr.Keys())
	}

	// Bloqueo manual SOLO en api. api está en monitor, pero un bloqueo de la
	// Admin API es negación dura: se aplica igual. En shop no existe.
	v, _ := acl.Normalize(acl.Block, acl.KindIP, "203.0.113.30")
	if _, err := s.acl.Put(context.Background(), "api", acl.Entry{List: acl.Block, Kind: acl.KindIP, Value: v, Reason: "test", Actor: "t"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if rec := s.do("api.local", "203.0.113.30", true); rec.Code != http.StatusForbidden {
		t.Fatalf("api.local con bloqueo en api = %d, want 403", rec.Code)
	}
	if rec := s.do("shop.local", "203.0.113.30", true); rec.Code != http.StatusOK {
		t.Fatalf("shop.local con bloqueo SOLO en api = %d, want 200", rec.Code)
	}
	if !s.mr.Exists("gd:api:acl:block:ip:203.0.113.30") {
		t.Fatalf("llaves: %v", s.mr.Keys())
	}
}

// El label app sale del veredicto: solo nombres de la config, nunca el Host.
func TestMetricasPorApp(t *testing.T) {
	s := newStack(t, twoApps)
	s.do("shop.local", "203.0.113.40", false)
	s.do("www.shop.local:8080", "203.0.113.40", false)
	s.do("api.local", "203.0.113.40", false)
	s.do("nadie.example", "203.0.113.40", false)

	got := map[string]float64{}
	mfs, err := s.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "guardian_http_requests_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "app" {
					got[l.GetValue()] += m.GetCounter().GetValue()
				}
			}
		}
	}
	if got["shop"] != 2 || got["api"] != 1 || len(got) != 2 {
		t.Fatalf("requests por app = %v (el host desconocido no es una app ni una serie)", got)
	}
	if got := testutil.ToFloat64(s.mets.UnknownHost); got != 1 {
		t.Fatalf("unknown = %v", got)
	}
}

// Sin sección apps todo sigue como antes: una sola app (app: shop) para
// cualquier Host, con las mismas llaves gd:shop:.
func TestConfigSinAppsEsLegacy(t *testing.T) {
	s := newStack(t, func(s *stack) string { return fmt.Sprintf(baseYAML, s.shopURL) })
	for _, host := range []string{"localhost:8080", "shop.local", "lo-que-sea.example", ""} {
		if rec := s.do(host, "203.0.113.50", true); rec.Code != 200 {
			t.Fatalf("%q = %d: sin apps, cualquier Host va a la única app", host, rec.Code)
		}
		if ev := s.sink.last(); ev.App != "shop" {
			t.Fatalf("app = %q", ev.App)
		}
	}
	if rec := s.do("x", "203.0.113.51", false); rec.Code != http.StatusForbidden {
		t.Fatalf("curl en enforce = %d", rec.Code)
	}
	for _, k := range s.mr.Keys() {
		if !strings.HasPrefix(k, "gd:shop:") {
			t.Fatalf("llave legacy = %s", k)
		}
	}
	if rt := s.reloader.Current().Value; rt.Default() != "shop" || len(rt.Names()) != 1 {
		t.Fatalf("legacy router = %v default=%q", rt.Names(), rt.Default())
	}
}

// Recarga en caliente bajo carga (correr con -race): agregar una app, mover
// un host y quitar la app. Cada request ve la tabla vieja completa o la nueva
// completa; nunca un estado intermedio ni un pánico.
func TestRecargaAgregaYQuitaApps(t *testing.T) {
	onlyShop := func(s *stack) string {
		return fmt.Sprintf(baseYAML, s.shopURL) + `
apps:
  - name: shop
    hosts: ["shop.local"]
`
	}
	s := newStack(t, onlyShop)
	if rec := s.do("api.local", "203.0.113.60", false); rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("antes de la recarga api.local = %d, want 421", rec.Code)
	}

	// Carga concurrente contra api.local y shop.local mientras se recarga.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var bad atomic.Int32
	var seen sync.Map
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := netip.AddrFrom4([4]byte{198, 18, 0, byte(i + 1)}).String()
			for {
				select {
				case <-stop:
					return
				default:
				}
				code := s.do("api.local", ip, false).Code
				seen.Store(code, true)
				if code != http.StatusMisdirectedRequest && code != http.StatusOK {
					bad.Add(1)
				}
				if c := s.do("shop.local", ip, true).Code; c != http.StatusOK {
					bad.Add(1)
				}
			}
		}()
	}

	time.Sleep(20 * time.Millisecond)
	s.reload(twoApps(s)) // agrega api (monitor, su upstream)
	if names := strings.Join(s.reloader.Current().Value.Names(), ","); names != "api,shop" {
		t.Fatalf("apps después de agregar = %s", names)
	}
	if rec := s.do("api.local", "203.0.113.61", false); rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), "api-upstream") {
		t.Fatalf("después de agregar api.local = %d %q", rec.Code, rec.Body)
	}
	time.Sleep(20 * time.Millisecond)

	// Mover un host de app: api.local pasa a shop (enforce).
	s.reload(fmt.Sprintf(baseYAML, s.shopURL) + `
apps:
  - name: shop
    hosts: ["shop.local", "api.local"]
`)
	close(stop)
	wg.Wait()
	if rec := s.do("api.local", "203.0.113.62", false); rec.Code != http.StatusForbidden {
		t.Fatalf("api.local ahora es de shop (enforce) = %d, want 403", rec.Code)
	}
	if ev := s.sink.last(); ev.App != "shop" {
		t.Fatalf("app = %q", ev.App)
	}
	if n := bad.Load(); n != 0 {
		t.Fatalf("%d respuestas fuera de lo esperado durante las recargas", n)
	}
	if _, ok := seen.Load(http.StatusOK); !ok {
		t.Fatal("la carga nunca vio api.local servido (la recarga no se aplicó en caliente)")
	}

	// Quitar el host: vuelve a 421.
	s.reload(onlyShop(s))
	if rec := s.do("api.local", "203.0.113.63", false); rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("después de quitar = %d, want 421", rec.Code)
	}
}

// Una recarga inválida (el mismo host en dos apps) se rechaza ENTERA: el
// router anterior sigue sirviendo.
func TestRecargaInvalidaNoPublica(t *testing.T) {
	s := newStack(t, twoApps)
	before := s.reloader.Current().Version
	s.write(fmt.Sprintf(baseYAML, s.shopURL) + `
apps:
  - name: shop
    hosts: ["shop.local"]
  - name: api
    hosts: ["SHOP.local"]
`)
	err := s.reloader.Reload(context.Background(), "test")
	if err == nil || !strings.Contains(err.Error(), "ya es de apps[shop]") {
		t.Fatalf("err = %v", err)
	}
	if s.reloader.Current().Version != before {
		t.Fatal("se publicó una config inválida")
	}
	if rec := s.do("api.local", "203.0.113.70", false); rec.Code != 200 {
		t.Fatalf("api.local con la config anterior = %d", rec.Code)
	}
}
