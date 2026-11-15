package events

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ErrBatcherClosed lo devuelve Emit si llega un evento después de Close.
var ErrBatcherClosed = errors.New("events: el batcher ya cerró")

// sendTimeout acota un batch completo: la llamada, los retries y sus esperas.
const sendTimeout = 5 * time.Second

// SendResult resume qué pasó con un batch al enviarlo.
type SendResult struct {
	Sent     int // eventos que el destino aceptó
	Lost     int // eventos que no se pudieron entregar tras los retries
	Retries  int // rondas de retry (cada una reenvía solo lo que falló)
	Requests int // llamadas a la API de AWS (lo que cobra SQS)
}

func (r *SendResult) add(o SendResult) {
	r.Sent += o.Sent
	r.Lost += o.Lost
	r.Retries += o.Retries
	r.Requests += o.Requests
}

// BatchSender es el contrato que cumplen los adaptadores de SQS y Kinesis.
// Send recibe un batch ya armado, lo parte según los límites de la API
// y hace retry SOLO de lo que falló. Devuelve error si algún evento se perdió.
type BatchSender interface {
	Name() string // valor del label sink en las métricas
	Send(ctx context.Context, batch []Event) (SendResult, error)
	Close(ctx context.Context) error
}

// RetryPolicy gobierna los retries de las entradas que fallaron.
type RetryPolicy struct {
	MaxRetries int           // retries después del primer intento
	Backoff    time.Duration // espera base; se duplica en cada ronda
	MaxBackoff time.Duration // tope de la espera
	// Sleep espera d o devuelve el error del ctx. Es nil en producción;
	// los tests lo reemplazan para no esperar de verdad.
	Sleep func(ctx context.Context, d time.Duration) error
}

func (c Config) retryPolicy() RetryPolicy {
	c = c.WithDefaults()
	return RetryPolicy{MaxRetries: c.MaxRetries, Backoff: c.RetryBackoff, MaxBackoff: 2 * time.Second}
}

// delay calcula la espera antes del retry número n (n empieza en 1):
// backoff * 2^(n-1), con tope, y "jitter" entre la mitad y el total para que
// varias réplicas no hagan retry todas en el mismo instante.
func (p RetryPolicy) delay(n int) time.Duration {
	d := p.Backoff << (n - 1)
	if p.MaxBackoff > 0 && (d > p.MaxBackoff || d <= 0) {
		d = p.MaxBackoff
	}
	if d <= 1 {
		return d
	}
	half := d / 2
	return half + rand.N(d-half+1)
}

func (p RetryPolicy) sleep(ctx context.Context, d time.Duration) error {
	if p.Sleep != nil {
		return p.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// attemptResult es lo que devuelve UN intento de envío.
type attemptResult[T any] struct {
	Retry   []T    // entradas que fallaron y vale la pena hacer retry
	Dropped int    // entradas rechazadas para siempre (ej. SenderFault de SQS)
	Reason  string // último código de error, para el log
}

// sendWithRetry llama a attempt con items y hace retry solo de lo que falló.
// Si attempt devuelve error, la llamada completa falló: el SDK de AWS ya
// hizo retry de los errores transitorios (red, 5xx, throttling) y aquí no se
// repite. Lo que el SDK NO repite son los fallos parciales (HTTP 200 con
// Failed / FailedRecordCount): de esos se encarga este bucle.
func sendWithRetry[T any](ctx context.Context, p RetryPolicy, items []T,
	attempt func(context.Context, []T) (attemptResult[T], error)) (SendResult, error) {

	var res SendResult
	pending := items
	reason := ""
	for try := 0; ; try++ {
		res.Requests++
		ar, err := attempt(ctx, pending)
		if err != nil {
			res.Lost += len(pending)
			return res, fmt.Errorf("falló la llamada con %d eventos: %w", len(pending), err)
		}
		res.Sent += len(pending) - len(ar.Retry) - ar.Dropped
		res.Lost += ar.Dropped
		if ar.Reason != "" {
			reason = ar.Reason
		}
		if len(ar.Retry) == 0 {
			break
		}
		if try >= p.MaxRetries {
			res.Lost += len(ar.Retry)
			break
		}
		res.Retries++
		if err := p.sleep(ctx, p.delay(try+1)); err != nil {
			res.Lost += len(ar.Retry)
			return res, fmt.Errorf("retry cancelado con %d eventos pendientes: %w", len(ar.Retry), err)
		}
		pending = ar.Retry
	}
	if res.Lost > 0 {
		return res, fmt.Errorf("%d eventos no se entregaron (último error: %s)", res.Lost, reason)
	}
	return res, nil
}

// chunk parte items en grupos que respeten el máximo de entradas Y de bytes
// de una llamada. Un item más grande que maxBytes queda solo en su grupo
// (la API lo rechazará y sendWithRetry lo contará como perdido).
func chunk[T any](items []T, maxCount, maxBytes int, size func(T) int) [][]T {
	var out [][]T
	var cur []T
	bytes := 0
	for _, it := range items {
		n := size(it)
		if len(cur) > 0 && (len(cur) >= maxCount || bytes+n > maxBytes) {
			out = append(out, cur)
			cur, bytes = nil, 0
		}
		cur = append(cur, it)
		bytes += n
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

type batcherMetrics struct {
	batches  *prometheus.CounterVec
	size     *prometheus.HistogramVec
	retries  *prometheus.CounterVec
	failures *prometheus.CounterVec
	requests *prometheus.CounterVec
}

func newBatcherMetrics(reg prometheus.Registerer, sink string) batcherMetrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	f := promauto.With(reg)
	m := batcherMetrics{
		batches: f.NewCounterVec(prometheus.CounterOpts{
			Name: "guardian_events_batches_total",
			Help: "Batches que el Batcher vació hacia el destino.",
		}, []string{"sink"}),
		size: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "guardian_events_batch_size",
			Help:    "Eventos por batch al momento de vaciarlo.",
			Buckets: []float64{1, 2, 5, 10, 20, 50, 100, 200, 500},
		}, []string{"sink"}),
		retries: f.NewCounterVec(prometheus.CounterOpts{
			Name: "guardian_events_retries_total",
			Help: "Rondas de retry de entradas que fallaron dentro de un batch.",
		}, []string{"sink"}),
		failures: f.NewCounterVec(prometheus.CounterOpts{
			Name: "guardian_events_send_failures_total",
			Help: "Eventos perdidos después de agotar los retries.",
		}, []string{"sink"}),
		requests: f.NewCounterVec(prometheus.CounterOpts{
			Name: "guardian_events_api_requests_total",
			Help: "Llamadas a la API del destino (SendMessageBatch o PutRecords). SQS cobra por esto.",
		}, []string{"sink"}),
	}
	// Las series existen desde el arranque, en cero.
	m.batches.WithLabelValues(sink)
	m.size.WithLabelValues(sink)
	m.retries.WithLabelValues(sink)
	m.failures.WithLabelValues(sink)
	m.requests.WithLabelValues(sink)
	return m
}

// Batcher implementa Sink acumulando eventos y enviándolos por batches.
// Vacía el batch cuando llega a BatchSize, cuando pasa FlushInterval
// y cuando se llama a Close. El mutex solo protege la lista pendiente:
// NUNCA se mantiene tomado mientras se habla con AWS.
type Batcher struct {
	sender   BatchSender
	name     string
	size     int
	interval time.Duration
	log      *slog.Logger
	m        batcherMetrics

	mu       sync.Mutex
	pending  []Event
	closed   bool
	inflight sync.WaitGroup // batches tomados que todavía se están enviando

	stop     chan struct{}
	loopDone chan struct{}
}

func NewBatcher(sender BatchSender, cfg Config, log *slog.Logger, reg prometheus.Registerer) *Batcher {
	cfg = cfg.WithDefaults()
	if log == nil {
		log = slog.Default()
	}
	b := &Batcher{
		sender:   sender,
		name:     sender.Name(),
		size:     cfg.BatchSize,
		interval: cfg.FlushInterval,
		log:      log,
		m:        newBatcherMetrics(reg, sender.Name()),
		stop:     make(chan struct{}),
		loopDone: make(chan struct{}),
	}
	b.pending = make([]Event, 0, b.size)
	go b.loop()
	return b
}

// Emit agrega el evento al batch. Si el batch se llenó, lo envía en esta
// misma goroutine (la del worker del Async); el buffer del Async absorbe
// los eventos que lleguen mientras tanto.
func (b *Batcher) Emit(ctx context.Context, ev Event) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return ErrBatcherClosed
	}
	b.pending = append(b.pending, ev)
	var full []Event
	if len(b.pending) >= b.size {
		full = b.takeLocked()
	}
	b.mu.Unlock()
	if full != nil {
		b.flush(ctx, full)
	}
	return nil
}

// takeLocked saca el batch pendiente. Debe llamarse con b.mu tomado.
// El inflight.Add va aquí, bajo el lock, para que Close no pueda llegar
// a Wait sin haber visto este batch.
func (b *Batcher) takeLocked() []Event {
	batch := b.pending
	b.pending = make([]Event, 0, b.size)
	b.inflight.Add(1)
	return batch
}

func (b *Batcher) loop() {
	defer close(b.loopDone)
	t := time.NewTicker(b.interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			var batch []Event
			b.mu.Lock()
			if len(b.pending) > 0 {
				batch = b.takeLocked()
			}
			b.mu.Unlock()
			if batch != nil {
				b.flush(context.Background(), batch)
			}
		case <-b.stop:
			return
		}
	}
}

// flush envía un batch ya tomado y registra las métricas.
func (b *Batcher) flush(ctx context.Context, batch []Event) {
	defer b.inflight.Done()
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()

	res, err := b.sender.Send(ctx, batch)
	b.m.batches.WithLabelValues(b.name).Inc()
	b.m.size.WithLabelValues(b.name).Observe(float64(len(batch)))
	b.m.requests.WithLabelValues(b.name).Add(float64(res.Requests))
	b.m.retries.WithLabelValues(b.name).Add(float64(res.Retries))
	b.m.failures.WithLabelValues(b.name).Add(float64(res.Lost))
	if err != nil {
		b.log.Warn("events: batch con pérdidas", "sink", b.name, "batch", len(batch),
			"sent", res.Sent, "lost", res.Lost, "retries", res.Retries, "err", err)
	}
}

// Close deja de aceptar eventos, envía lo que quede pendiente, espera a que
// terminen los envíos en curso y cierra el destino. Es idempotente.
func (b *Batcher) Close(ctx context.Context) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	var rest []Event
	if len(b.pending) > 0 {
		rest = b.takeLocked()
	}
	b.mu.Unlock()

	close(b.stop)
	select {
	case <-b.loopDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	if rest != nil {
		b.flush(ctx, rest)
	}

	done := make(chan struct{})
	go func() {
		b.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return b.sender.Close(ctx)
}
