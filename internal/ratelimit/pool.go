package ratelimit

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// PrimaryFunc crea el store "de verdad" (Redis) de una app. El Pool la llama
// solo cuando una app aparece o cambia su rate/burst.
type PrimaryFunc func(app string, rate float64, burst int) RateStore

// Pool entrega un RateStore por app (Redis con fallback local y circuit
// breaker) y lo REUTILIZA entre recargas mientras rate y burst no cambien.
//
// Por qué importa: la cadena se reconstruye en cada recarga, pero el
// FailoverStore tiene estado (el circuit breaker abierto o cerrado) y el
// MemoryStore tiene los buckets locales. Si cada recarga creara stores
// nuevos, una recarga en medio de una caída de Redis cerraría el breaker y
// los primeros requests volverían a esperar el timeout de Redis.
//
// Está indexado por nombre de app: si cambian rate o burst, el store de esa
// app se reemplaza (la cadena vieja sigue usando el viejo hasta que la nueva
// se publique). El tamaño queda acotado por la cantidad de apps.
type Pool struct {
	primary  PrimaryFunc
	timeout  time.Duration
	maxFails int32
	cooldown time.Duration
	log      *slog.Logger

	mu     sync.Mutex
	stores map[string]*pooled
}

type pooled struct {
	rate  float64
	burst int
	store RateStore
	local *MemoryStore
}

func NewPool(primary PrimaryFunc, timeout time.Duration, maxFails int32, cooldown time.Duration, log *slog.Logger) *Pool {
	return &Pool{
		primary: primary, timeout: timeout, maxFails: maxFails, cooldown: cooldown, log: log,
		stores: make(map[string]*pooled),
	}
}

// Get devuelve el store de la app con ese rate y burst. Seguro para llamar
// desde varios goroutines (el Reloader lo llama con su propio mutex, pero el
// janitor recorre el mapa al mismo tiempo).
func (p *Pool) Get(app string, rate float64, burst int) RateStore {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.stores[app]; ok && e.rate == rate && e.burst == burst {
		return e.store
	}
	local := NewMemoryStore(rate, burst)
	e := &pooled{
		rate: rate, burst: burst, local: local,
		store: NewFailoverStore(p.primary(app, rate, burst), local, p.timeout, p.maxFails, p.cooldown, p.log.With("app", app)),
	}
	p.stores[app] = e
	return e.store
}

// StartJanitor limpia periódicamente los buckets locales de todas las apps.
// Uno solo para todo el Pool: con una goroutine por app, cada recarga que
// cambia un rate dejaría una goroutine huérfana.
func (p *Pool) StartJanitor(ctx context.Context, every time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(every)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.mu.Lock()
				locals := make([]*MemoryStore, 0, len(p.stores))
				for _, e := range p.stores {
					locals = append(locals, e.local)
				}
				p.mu.Unlock()
				for _, l := range locals {
					if n := l.Cleanup(); n > 0 {
						log.Debug("limpieza de limitadores locales", "borrados", n)
					}
				}
			}
		}
	}()
}
