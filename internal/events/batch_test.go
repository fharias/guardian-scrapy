package events

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// recordingSender guarda cada batch que recibe. Es seguro entre goroutines.
type recordingSender struct {
	mu      sync.Mutex
	batches [][]Event
	closed  bool
	result  func(batch []Event) (SendResult, error) // opcional
}

func (s *recordingSender) Name() string { return "fake" }

func (s *recordingSender) Send(_ context.Context, batch []Event) (SendResult, error) {
	s.mu.Lock()
	s.batches = append(s.batches, append([]Event(nil), batch...))
	s.mu.Unlock()
	if s.result != nil {
		return s.result(batch)
	}
	return SendResult{Sent: len(batch), Requests: 1}, nil
}

func (s *recordingSender) Close(context.Context) error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *recordingSender) sizes() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int, len(s.batches))
	for i, b := range s.batches {
		out[i] = len(b)
	}
	return out
}

func (s *recordingSender) total() int {
	n := 0
	for _, sz := range s.sizes() {
		n += sz
	}
	return n
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testBatcher(t *testing.T, s BatchSender, size int, interval time.Duration) (*Batcher, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry() // un registry por test: promauto entra en pánico si repites nombres
	b := NewBatcher(s, Config{BatchSize: size, FlushInterval: interval}, quietLogger(), reg)
	return b, reg
}

func closeBatcher(t *testing.T, b *Batcher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := b.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// eventually espera hasta 2 s a que cond sea verdadera.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("no se cumplió a tiempo: %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestBatcherFlushesBySize(t *testing.T) {
	s := &recordingSender{}
	// Intervalo de 1 hora: aquí solo puede vaciar por tamaño.
	b, _ := testBatcher(t, s, 3, time.Hour)
	for i := 0; i < 7; i++ {
		if err := b.Emit(context.Background(), Event{Route: "/api", Score: i}); err != nil {
			t.Fatal(err)
		}
	}
	// 7 eventos con batch de 3: dos batches completos ya salieron, queda 1 pendiente.
	if got := s.sizes(); len(got) != 2 || got[0] != 3 || got[1] != 3 {
		t.Fatalf("batches = %v, quiero [3 3] antes de Close", got)
	}
	closeBatcher(t, b)
	if got := s.sizes(); len(got) != 3 || got[2] != 1 {
		t.Fatalf("batches = %v, quiero [3 3 1] después de Close", got)
	}
}

func TestBatcherFlushesByInterval(t *testing.T) {
	s := &recordingSender{}
	b, _ := testBatcher(t, s, 100, 20*time.Millisecond)
	defer closeBatcher(t, b)
	_ = b.Emit(context.Background(), Event{Route: "/a"})
	_ = b.Emit(context.Background(), Event{Route: "/b"})
	// Nunca llega a 100: solo el ticker puede haberlos sacado.
	eventually(t, "el ticker debe vaciar el batch incompleto", func() bool { return s.total() == 2 })
	if got := s.sizes(); len(got) != 1 || got[0] != 2 {
		t.Fatalf("batches = %v, quiero un solo batch de 2", got)
	}
}

func TestBatcherCloseFlushesRemainderAndClosesSender(t *testing.T) {
	s := &recordingSender{}
	b, _ := testBatcher(t, s, 100, time.Hour)
	for i := 0; i < 5; i++ {
		_ = b.Emit(context.Background(), Event{Score: i})
	}
	if s.total() != 0 {
		t.Fatalf("no debía haber enviado nada antes de Close, envió %d", s.total())
	}
	closeBatcher(t, b)
	if got := s.sizes(); len(got) != 1 || got[0] != 5 {
		t.Fatalf("Close debía vaciar el resto en un batch de 5, got %v", got)
	}
	if !s.closed {
		t.Fatal("Close debía cerrar el sender")
	}
	if err := b.Emit(context.Background(), Event{}); !errors.Is(err, ErrBatcherClosed) {
		t.Fatalf("Emit después de Close = %v, quiero ErrBatcherClosed", err)
	}
	closeBatcher(t, b) // idempotente: una segunda llamada no entra en pánico ni reenvía
	if len(s.sizes()) != 1 {
		t.Fatal("el segundo Close reenvió algo")
	}
}

func TestBatcherConcurrentEmitKeepsEveryEvent(t *testing.T) {
	s := &recordingSender{}
	b, _ := testBatcher(t, s, 50, 5*time.Millisecond)
	const workers, perWorker = 8, 250
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				_ = b.Emit(context.Background(), Event{Route: "/api"})
			}
		}()
	}
	wg.Wait()
	closeBatcher(t, b)
	if got := s.total(); got != workers*perWorker {
		t.Fatalf("llegaron %d eventos, quiero %d", got, workers*perWorker)
	}
	for _, n := range s.sizes() {
		if n > 50 {
			t.Fatalf("un batch traía %d eventos, el tope es 50", n)
		}
	}
}

func TestBatcherRecordsMetrics(t *testing.T) {
	s := &recordingSender{result: func(batch []Event) (SendResult, error) {
		return SendResult{Sent: len(batch) - 1, Lost: 1, Retries: 2, Requests: 3}, errors.New("uno se perdió")
	}}
	b, reg := testBatcher(t, s, 4, time.Hour)
	for i := 0; i < 4; i++ {
		_ = b.Emit(context.Background(), Event{})
	}
	closeBatcher(t, b)

	if v := testutil.ToFloat64(b.m.batches.WithLabelValues("fake")); v != 1 {
		t.Fatalf("batches_total = %v, quiero 1", v)
	}
	if v := testutil.ToFloat64(b.m.retries.WithLabelValues("fake")); v != 2 {
		t.Fatalf("retries_total = %v, quiero 2", v)
	}
	if v := testutil.ToFloat64(b.m.failures.WithLabelValues("fake")); v != 1 {
		t.Fatalf("send_failures_total = %v, quiero 1", v)
	}
	if v := testutil.ToFloat64(b.m.requests.WithLabelValues("fake")); v != 3 {
		t.Fatalf("api_requests_total = %v, quiero 3", v)
	}
	// El histograma vio un batch de 4 eventos.
	n, err := testutil.GatherAndCount(reg, "guardian_events_batch_size")
	if err != nil || n != 1 {
		t.Fatalf("batch_size: series=%d err=%v", n, err)
	}
}

func TestChunkRespectsCountAndBytes(t *testing.T) {
	size := func(n int) int { return n }
	// Por cantidad: 7 items, máximo 3 por grupo.
	got := chunk([]int{1, 1, 1, 1, 1, 1, 1}, 3, 1000, size)
	if len(got) != 3 || len(got[0]) != 3 || len(got[1]) != 3 || len(got[2]) != 1 {
		t.Fatalf("por cantidad: %v", got)
	}
	// Por bytes: tope 10, items de 4: caben 2 por grupo (8), el tercero (12) no.
	got = chunk([]int{4, 4, 4, 4, 4}, 100, 10, size)
	if len(got) != 3 || len(got[0]) != 2 || len(got[2]) != 1 {
		t.Fatalf("por bytes: %v", got)
	}
	// Un item más grande que el tope queda solo, sin perderse.
	got = chunk([]int{1, 50, 1}, 100, 10, size)
	if len(got) != 3 || got[1][0] != 50 {
		t.Fatalf("item enorme: %v", got)
	}
	if got := chunk([]int(nil), 3, 10, size); len(got) != 0 {
		t.Fatalf("vacío: %v", got)
	}
}

func TestRetryPolicyDelayGrowsWithJitter(t *testing.T) {
	p := RetryPolicy{Backoff: 100 * time.Millisecond, MaxBackoff: 350 * time.Millisecond}
	for n, base := range map[int]time.Duration{1: 100 * time.Millisecond, 2: 200 * time.Millisecond, 3: 350 * time.Millisecond, 9: 350 * time.Millisecond} {
		for i := 0; i < 50; i++ {
			d := p.delay(n)
			if d < base/2 || d > base {
				t.Fatalf("delay(%d) = %s, quiero entre %s y %s", n, d, base/2, base)
			}
		}
	}
}

func TestAsyncWithBatcherDeliversEverythingOnClose(t *testing.T) {
	s := &recordingSender{}
	batcher, _ := testBatcher(t, s, 10, time.Hour)
	async := NewAsync(batcher, Config{Buffer: 256}, prometheus.NewRegistry())
	for i := 0; i < 95; i++ {
		async.Emit(Event{Route: "/api", Score: i})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Async.Close drena el canal hacia el Batcher y luego cierra el Batcher,
	// que vacía el resto: nada se queda en memoria.
	if err := async.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if got := s.total(); got != 95 {
		t.Fatalf("llegaron %d eventos, quiero 95 (batches %v)", got, s.sizes())
	}
	sizes := s.sizes()
	if len(sizes) != 10 || sizes[9] != 5 {
		t.Fatalf("batches = %v, quiero 9 de 10 y uno final de 5", sizes)
	}
}
