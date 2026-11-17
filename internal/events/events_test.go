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
	sqsOK := SQSConfig{QueueURL: "https://sqs.us-east-1.amazonaws.com/123456789012/guardian-events"}
	cases := []struct {
		name    string
		cfg     Config
		wantErr string // vacío = debe validar
	}{
		{"disabled no valida el sink", Config{Enabled: false, Sink: "sqs"}, ""},
		{"log", Config{Enabled: true, Sink: "log", Buffer: 8}, ""},
		{"none", Config{Enabled: true, Sink: "none"}, ""},
		{"sqs completo", Config{Enabled: true, Sink: "sqs", SQS: sqsOK, BatchSize: 10, FlushInterval: time.Second}, ""},
		{"sqs sin queue_url", Config{Enabled: true, Sink: "sqs"}, "events.sqs.queue_url"},
		{"sqs con url sin esquema", Config{Enabled: true, Sink: "sqs", SQS: SQSConfig{QueueURL: "guardian-events"}}, "events.sqs.queue_url"},
		{"kinesis completo", Config{Enabled: true, Sink: "kinesis", Kinesis: KinesisConfig{StreamName: "guardian-events"}}, ""},
		{"kinesis sin stream_name", Config{Enabled: true, Sink: "kinesis"}, "events.kinesis.stream_name"},
		{"kafka completo", Config{Enabled: true, Sink: "kafka", Kafka: KafkaConfig{Brokers: []string{"kafka:9092"}, Topic: "guardian-events"}}, ""},
		{"kafka sin brokers ni topic", Config{Enabled: true, Sink: "kafka"}, "events.kafka.brokers"},
		{"sink desconocido", Config{Enabled: true, Sink: "rabbit"}, "no es válido"},
		{"buffer negativo", Config{Enabled: true, Sink: "log", Buffer: -1}, "events.buffer"},
		{"batch_size negativo", Config{Enabled: true, Sink: "log", BatchSize: -1}, "events.batch_size"},
		{"batch_size sobre el tope", Config{Enabled: true, Sink: "log", BatchSize: 501}, "events.batch_size"},
		{"flush_interval negativo", Config{Enabled: true, Sink: "log", FlushInterval: -time.Second}, "events.flush_interval"},
		{"max_retries negativo", Config{Enabled: true, Sink: "log", MaxRetries: -1}, "events.max_retries"},
		{"retry_backoff negativo", Config{Enabled: true, Sink: "log", RetryBackoff: -time.Millisecond}, "events.retry_backoff"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("no esperaba error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, quiero que contenga %q", err, c.wantErr)
			}
		})
	}
}

func TestWithDefaultsFillsBatchSettings(t *testing.T) {
	c := (Config{}).WithDefaults()
	if c.Sink != SinkLog || c.Buffer != DefaultBuffer || c.BatchSize != DefaultBatchSize ||
		c.FlushInterval != DefaultFlushInterval || c.MaxRetries != DefaultMaxRetries || c.RetryBackoff != DefaultRetryBackoff {
		t.Fatalf("defaults inesperados: %+v", c)
	}
	c = (Config{BatchSize: 7, FlushInterval: 3 * time.Second}).WithDefaults()
	if c.BatchSize != 7 || c.FlushInterval != 3*time.Second {
		t.Fatalf("WithDefaults pisó valores explícitos: %+v", c)
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
