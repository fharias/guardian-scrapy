package events

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/fharias/guardian-scrapy/internal/verdict"
)

func testHasher(t *testing.T) *Hasher {
	t.Helper()
	h, err := NewHasher("0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestNewHasherRejectsShortSalt(t *testing.T) {
	if _, err := NewHasher("corto"); err == nil {
		t.Fatal("esperaba error con sal corta")
	}
}

func TestHasherIsDeterministicAndHidesIP(t *testing.T) {
	h := testHasher(t)
	ip := netip.MustParseAddr("192.0.2.1")
	a, b := h.Hash(ip), h.Hash(ip)
	if a == "" || a != b {
		t.Fatalf("hash inestable: %q vs %q", a, b)
	}
	if strings.Contains(a, "192.0.2") {
		t.Fatalf("el hash no debe contener la IP: %s", a)
	}
	other, err := NewHasher("0123456789abcdee")
	if err != nil {
		t.Fatal(err)
	}
	if other.Hash(ip) == a {
		t.Fatal("sales distintas deben producir hashes distintos")
	}
	if h.Hash(netip.Addr{}) != "" {
		t.Fatal("IP inválida debe hashear a vacío")
	}
}

func TestValidate(t *testing.T) {
	if err := (Config{Enabled: false, Sink: "sqs"}).Validate(); err != nil {
		t.Fatalf("disabled no debe validar el sink: %v", err)
	}
	if err := (Config{Enabled: true, Sink: "log", Buffer: 8}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Config{Enabled: true, Sink: "kinesis"}).Validate(); err == nil || !strings.Contains(err.Error(), "paso 19") {
		t.Fatalf("esperaba rechazo de kinesis, got %v", err)
	}
	if err := (Config{Enabled: true, Sink: "log", Buffer: -1}).Validate(); err == nil {
		t.Fatal("buffer negativo debe fallar")
	}
}

// blockingSink se queda en gate hasta que el test lo suelta.
type blockingSink struct {
	gate  chan struct{}
	got   []Event
	mu    sync.Mutex
	calls atomic.Int32
}

func (s *blockingSink) Emit(_ context.Context, ev Event) error {
	s.calls.Add(1)
	<-s.gate
	s.mu.Lock()
	s.got = append(s.got, ev)
	s.mu.Unlock()
	return nil
}
func (s *blockingSink) Close(context.Context) error { return nil }

func TestDropWhenBufferFull(t *testing.T) {
	reg := prometheus.NewRegistry()
	gate := make(chan struct{})
	dest := &blockingSink{gate: gate}
	async := NewAsync(dest, Config{Buffer: 2}, reg)

	// Primero un evento para que el worker quede bloqueado dentro de Emit.
	async.Emit(Event{Decision: "allow", Route: "default"})
	deadline := time.Now().Add(time.Second)
	for dest.calls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("el sink no recibió el primer evento")
		}
		time.Sleep(time.Millisecond)
	}
	// Buffer vacío y worker ocupado: caben 2 más; el resto se descarta.
	for i := 0; i < 5; i++ {
		async.Emit(Event{Decision: "allow", Route: "default"})
	}
	enqueued := testutil.ToFloat64(async.enqueued)
	dropped := testutil.ToFloat64(async.dropped.WithLabelValues("buffer_full"))
	if enqueued != 3 || dropped != 3 {
		t.Fatalf("enqueued=%v dropped=%v, quiero 3 y 3", enqueued, dropped)
	}

	close(gate)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := async.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if dest.calls.Load() != 3 {
		t.Fatalf("el sink debió ver 3 eventos, vio %d", dest.calls.Load())
	}
}

func TestSlowSinkDoesNotChangeProxyLatency(t *testing.T) {
	reg := prometheus.NewRegistry()
	slow := SinkFunc(func(context.Context, Event) error {
		time.Sleep(80 * time.Millisecond)
		return nil
	})
	async := NewAsync(slow, Config{Buffer: 64}, reg)
	h := Middleware(async, testHasher(t), func(string) string { return "/api" })(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := verdict.From(r.Context())
		v.ClientIP = netip.MustParseAddr("192.0.2.1")
		v.Decision = verdict.Block
		v.Mode = "monitor"
		v.Shadowed = true
		w.WriteHeader(http.StatusOK)
	}))
	h = withVerdict(h)

	const n = 20
	start := time.Now()
	for i := 0; i < n; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/prices?id=1", nil))
		if rec.Code != 200 {
			t.Fatalf("status %d", rec.Code)
		}
	}
	elapsed := time.Since(start)
	// Si Emit esperara al sink, 20 × 80 ms = 1.6 s. Con el buffer, debe
	// quedarse muy por debajo de 300 ms incluso en una máquina cargada.
	if elapsed > 300*time.Millisecond {
		t.Fatalf("la latencia del proxy cambió con el sink lento: %s (tope 300ms)", elapsed)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := async.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(async.enqueued); got != n {
		t.Fatalf("enqueued = %v, quiero %d", got, n)
	}
}

func TestMiddlewareHashesIPAndUsesRoute(t *testing.T) {
	reg := prometheus.NewRegistry()
	cap := &captureSink{}
	async := NewAsync(cap, Config{Buffer: 8}, reg)
	h := Middleware(async, testHasher(t), func(string) string { return "/api" })(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := verdict.From(r.Context())
		v.ClientIP = netip.MustParseAddr("192.0.2.10")
		v.Fingerprint = "abc"
		v.JA4 = "t13d4907h2_0d8feac7bc37_7395dae3b2f3"
		v.Decision = verdict.Challenge
		v.Reasons = []string{"ua_tool"}
		v.Mode = "enforce"
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	withVerdict(h).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/prices?id=secret", nil))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := async.Close(ctx); err != nil {
		t.Fatal(err)
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if len(cap.got) != 1 {
		t.Fatalf("eventos = %d, quiero 1", len(cap.got))
	}
	ev := cap.got[0]
	if ev.IPHash == "" || strings.Contains(ev.IPHash, "192.0.2") {
		t.Fatalf("ip_hash inválido: %q", ev.IPHash)
	}
	if ev.Route != "/api" {
		t.Fatalf("route = %q, no debe ser el path crudo", ev.Route)
	}
	if ev.Decision != "challenge" || ev.Mode != "enforce" || ev.Fingerprint != "abc" {
		t.Fatalf("event inesperado: %+v", ev)
	}
	if ev.IPHash != testHasher(t).Hash(netip.MustParseAddr("192.0.2.10")) {
		t.Fatalf("hash no coincide con el hasher")
	}
}

func TestEmitAfterCloseDropsWithoutPanic(t *testing.T) {
	reg := prometheus.NewRegistry()
	async := NewAsync(noopDest{}, Config{Buffer: 1}, reg)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := async.Close(ctx); err != nil {
		t.Fatal(err)
	}
	async.Emit(Event{Decision: "allow"})
	if got := testutil.ToFloat64(async.dropped.WithLabelValues("closed")); got != 1 {
		t.Fatalf("dropped closed = %v, quiero 1", got)
	}
}

func TestSinkErrorsAreCounted(t *testing.T) {
	reg := prometheus.NewRegistry()
	async := NewAsync(SinkFunc(func(context.Context, Event) error {
		return errSink
	}), Config{Buffer: 4}, reg)
	async.Emit(Event{Decision: "allow"})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := async.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(async.errors); got != 1 {
		t.Fatalf("errors = %v, quiero 1", got)
	}
}

var errSink = errString("sink down")

type errString string

func (e errString) Error() string { return string(e) }

type SinkFunc func(context.Context, Event) error

func (f SinkFunc) Emit(ctx context.Context, ev Event) error { return f(ctx, ev) }
func (SinkFunc) Close(context.Context) error                { return nil }

type captureSink struct {
	mu  sync.Mutex
	got []Event
}

func (s *captureSink) Emit(_ context.Context, ev Event) error {
	s.mu.Lock()
	s.got = append(s.got, ev)
	s.mu.Unlock()
	return nil
}
func (s *captureSink) Close(context.Context) error { return nil }

func withVerdict(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(verdict.WithVerdict(r.Context(), &verdict.Verdict{})))
	})
}
