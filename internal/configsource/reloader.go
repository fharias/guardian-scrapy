package configsource

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/fharias/guardian-scrapy/internal/config"
)

// DefaultDebounce es cuánto silencio esperamos después del último aviso antes
// de recargar. Un "guardar" de un editor dispara 2 a 5 eventos seguidos.
const DefaultDebounce = 250 * time.Millisecond

// Snapshot es una config aplicada y lo que se construyó con ella.
// Es inmutable: nadie modifica un Snapshot después de publicarlo.
type Snapshot[T any] struct {
	Version  string         // hash del contenido de la fuente
	LoadedAt time.Time      // cuándo se publicó
	Config   *config.Config // config efectiva (lo recargable del archivo + lo que requiere reinicio del arranque)
	Value    T              // lo que construyó BuildFunc, ej. la cadena de middlewares
}

// BuildFunc construye el valor vivo a partir de una config ya validada.
// Si devuelve error, la config NO se aplica.
type BuildFunc[T any] func(cfg *config.Config, version string) (T, error)

// Options ajusta el Reloader. Los ceros toman defaults.
type Options struct {
	Debounce   time.Duration         // default DefaultDebounce
	Logger     *slog.Logger          // default slog.Default()
	Registerer prometheus.Registerer // default: registry propio (no se expone)
}

// Reloader mantiene la config activa y la reemplaza cuando la fuente cambia.
type Reloader[T any] struct {
	src      Source
	build    BuildFunc[T]
	log      *slog.Logger
	debounce time.Duration

	cur     atomic.Pointer[Snapshot[T]] // lo único que leen los requests
	mu      sync.Mutex                  // serializa recargas (fsnotify, SIGHUP, tests, mañana la Admin API)
	failed  string                      // última versión rechazada
	trigger chan string

	reloads    *prometheus.CounterVec
	lastOK     prometheus.Gauge
	lastOKTime prometheus.Gauge
	info       *prometheus.GaugeVec
}

// New construye el valor inicial con la config de arranque y la publica.
// initial y version vienen de LoadInitial.
func New[T any](src Source, initial *config.Config, version string, build BuildFunc[T], opts Options) (*Reloader[T], error) {
	if opts.Debounce <= 0 {
		opts.Debounce = DefaultDebounce
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Registerer == nil {
		opts.Registerer = prometheus.NewRegistry()
	}
	f := promauto.With(opts.Registerer)
	r := &Reloader[T]{
		src:      src,
		build:    build,
		log:      opts.Logger,
		debounce: opts.Debounce,
		trigger:  make(chan string, 1),
		reloads: f.NewCounterVec(prometheus.CounterOpts{
			Name: "guardian_config_reloads_total",
			Help: "Recargas de configuración intentadas, por resultado (ok o error).",
		}, []string{"result"}),
		lastOK: f.NewGauge(prometheus.GaugeOpts{
			Name: "guardian_config_last_reload_successful",
			Help: "1 si la última recarga se aplicó; 0 si se rechazó y sigue la config anterior.",
		}),
		lastOKTime: f.NewGauge(prometheus.GaugeOpts{
			Name: "guardian_config_last_reload_success_timestamp_seconds",
			Help: "Unix time de la última config aplicada (incluye la de arranque).",
		}),
		info: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "guardian_config_info",
			Help: "Siempre 1; el label version es el hash de la config activa.",
		}, []string{"version"}),
	}
	// Inicializa las series en 0 para que existan desde el arranque y las
	// alertas con rate()/increase() funcionen desde la primera falla.
	r.reloads.WithLabelValues("ok")
	r.reloads.WithLabelValues("error")

	value, err := build(initial, version)
	if err != nil {
		return nil, fmt.Errorf("config inicial: %w", err)
	}
	r.publish(&Snapshot[T]{Version: version, LoadedAt: time.Now(), Config: initial, Value: value})
	r.lastOK.Set(1)
	return r, nil
}

// Current devuelve el snapshot activo. Es una sola lectura atómica: sin locks,
// así que cuesta casi nada en el camino del request.
func (r *Reloader[T]) Current() *Snapshot[T] { return r.cur.Load() }

// Trigger pide una recarga (pasa por el debounce de Run). No bloquea: si ya hay
// una pendiente, esta se funde con ella.
func (r *Reloader[T]) Trigger(reason string) {
	select {
	case r.trigger <- reason:
	default:
	}
}

// Run vigila la fuente y recarga hasta que ctx termine.
func (r *Reloader[T]) Run(ctx context.Context) {
	go func() {
		if err := r.src.Watch(ctx, r.Trigger); err != nil && ctx.Err() == nil {
			r.log.Error("config_watch", "source", r.src.Name(), "err", err)
		}
	}()

	var (
		timer   *time.Timer
		timerC  <-chan time.Time
		pending string
	)
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case why := <-r.trigger:
			pending = why
			// Debounce: cada aviso nuevo reinicia la espera. Recargamos una sola
			// vez cuando la fuente lleva r.debounce sin moverse.
			if timer == nil {
				timer = time.NewTimer(r.debounce)
			} else {
				timer.Reset(r.debounce)
			}
			timerC = timer.C
		case <-timerC:
			timerC = nil
			_ = r.Reload(ctx, pending) // el error ya quedó en log y métricas
		}
	}
}

// Reload trae la config, la valida y, solo si todo sale bien, la publica.
// Si algo falla, la config activa sigue intacta y se devuelve el error.
func (r *Reloader[T]) Reload(ctx context.Context, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	start := time.Now()
	cur := r.cur.Load()

	data, err := r.src.Fetch(ctx)
	if err != nil {
		return r.fail(cur, "", reason, fmt.Errorf("leyendo %s: %w", r.src.Name(), err))
	}
	version := Version(data)
	if version == cur.Version {
		r.log.Debug("config_sin_cambios", "version", version, "reason", reason)
		return nil
	}
	if version == r.failed && reason == "poll" {
		return nil // ya la rechazamos y la logueamos; no repetir el error cada poll
	}

	incoming, err := config.Parse(data)
	if err != nil {
		return r.fail(cur, version, reason, err)
	}

	apply, restart := config.SplitChanges(config.Diff(cur.Config, incoming))
	if len(restart) > 0 {
		r.log.Warn("config_requiere_reinicio",
			"version", version,
			"campos", config.Paths(restart),
			"detalle", changeStrings(restart),
			"accion", "ignorados hasta reiniciar")
	}

	// Validar la config que REALMENTE vamos a aplicar: lo recargable del
	// archivo nuevo con lo que requiere reinicio de la config activa. El archivo
	// solo puede ser válido y la mezcla no (ver el caso de reputation).
	merged := config.MergeReloadable(cur.Config, incoming)
	if err := merged.Validate(); err != nil {
		return r.fail(cur, version, reason, fmt.Errorf("config mezclada inválida: %w", err))
	}
	value, err := r.build(merged, version)
	if err != nil {
		return r.fail(cur, version, reason, fmt.Errorf("construyendo: %w", err))
	}

	r.publish(&Snapshot[T]{Version: version, LoadedAt: time.Now(), Config: merged, Value: value})
	r.failed = ""
	r.reloads.WithLabelValues("ok").Inc()
	r.lastOK.Set(1)
	r.log.Info("config_recargada",
		"version_anterior", cur.Version,
		"version", version,
		"reason", reason,
		"cambios", changeStrings(apply),
		"dur_ms", time.Since(start).Milliseconds())
	return nil
}

// publish es el ÚNICO lugar donde cambia la config activa.
func (r *Reloader[T]) publish(s *Snapshot[T]) {
	r.cur.Store(s)
	r.info.Reset() // un solo label version vivo a la vez
	r.info.WithLabelValues(s.Version).Set(1)
	r.lastOKTime.Set(float64(s.LoadedAt.Unix()))
}

func (r *Reloader[T]) fail(cur *Snapshot[T], version, reason string, err error) error {
	r.failed = version
	r.reloads.WithLabelValues("error").Inc()
	r.lastOK.Set(0)
	r.log.Error("config_recarga_fallida",
		"version_rechazada", version,
		"version_activa", cur.Version,
		"reason", reason,
		"err", err)
	return errors.Join(ErrRejected, err)
}

// ErrRejected envuelve todo error de Reload: la config nueva no se aplicó.
var ErrRejected = errors.New("config rechazada: sigue la anterior")

func changeStrings(cs []config.Change) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.String()
	}
	return out
}
