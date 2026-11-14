package events

import (
	"context"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Async envuelve un Sink con un canal con buffer. Emit hace
// `select { case ch <- ev: default: }` y por eso no espera al destino.
// El mutex solo cubre la carrera con Close, no el trabajo del sink.
type Async struct {
	sink Sink
	ch   chan Event

	mu     sync.Mutex
	closed bool
	done   chan struct{}

	enqueued prometheus.Counter
	dropped  *prometheus.CounterVec
	errors   prometheus.Counter
}

func NewAsync(sink Sink, cfg Config, reg prometheus.Registerer) *Async {
	cfg = cfg.WithDefaults()
	if sink == nil {
		sink = noopDest{}
	}
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	f := promauto.With(reg)
	a := &Async{
		sink: sink,
		ch:   make(chan Event, cfg.Buffer),
		done: make(chan struct{}),
		enqueued: f.NewCounter(prometheus.CounterOpts{
			Name: "guardian_events_enqueued_total",
			Help: "Eventos que entraron al buffer del EventSink.",
		}),
		dropped: f.NewCounterVec(prometheus.CounterOpts{
			Name: "guardian_events_dropped_total",
			Help: "Eventos descartados porque el buffer estaba lleno o el sink ya cerró.",
		}, []string{"reason"}),
		errors: f.NewCounter(prometheus.CounterOpts{
			Name: "guardian_events_sink_errors_total",
			Help: "Errores del destino al persistir un evento ya desencolado.",
		}),
	}
	f.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "guardian_events_buffer_length",
		Help: "Eventos esperando en el buffer del EventSink.",
	}, func() float64 { return float64(len(a.ch)) })
	// Deja las series de dropped en cero para que existan desde el arranque.
	a.dropped.WithLabelValues("buffer_full")
	a.dropped.WithLabelValues("closed")
	go a.loop()
	return a
}

func (a *Async) Emit(ev Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		a.dropped.WithLabelValues("closed").Inc()
		return
	}
	select {
	case a.ch <- ev:
		a.enqueued.Inc()
	default:
		// Buffer lleno: descartamos en vez de frenar el request.
		a.dropped.WithLabelValues("buffer_full").Inc()
	}
}

func (a *Async) loop() {
	defer close(a.done)
	for ev := range a.ch {
		if err := a.sink.Emit(context.Background(), ev); err != nil {
			a.errors.Inc()
		}
	}
}

// Close deja de aceptar eventos, drena el buffer y cierra el destino.
// main debe llamarlo DESPUÉS de apagar el HTTP server: así no quedan
// requests en curso emitiendo mientras cerramos el canal.
func (a *Async) Close(ctx context.Context) error {
	a.mu.Lock()
	if !a.closed {
		a.closed = true
		close(a.ch)
	}
	a.mu.Unlock()

	select {
	case <-a.done:
		return a.sink.Close(ctx)
	case <-ctx.Done():
		return ctx.Err()
	}
}
