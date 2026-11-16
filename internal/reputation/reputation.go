// Package reputation agrega los eventos del pipeline de señales (paso 21):
// cuenta IPs distintas por JA4 con HyperLogLog y, si un JA4 aparece en
// demasiadas IPs, le deja una reputación con TTL en Redis/Valkey.
// El aggregator escribe (Aggregator) y el proxy lee (Reader).
package reputation

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/fharias/guardian-scrapy/internal/events"
	"github.com/redis/go-redis/v9"
)

const (
	DefaultWindow         = time.Hour
	DefaultBucket         = 10 * time.Minute
	DefaultMinDistinctIPs = 50
	DefaultTTL            = 30 * time.Minute
	DefaultCacheTTL       = 10 * time.Second
	DefaultLookupTimeout  = 20 * time.Millisecond
	maxBuckets            = 24 // PFCOUNT sobre más llaves ya no es barato
	maxCacheEntries       = 10000
)

// Config vive en el YAML bajo la clave `reputation`. La leen los dos
// binarios (guardian y aggregator) del MISMO archivo: una sola fuente de verdad.
type Config struct {
	Enabled        bool          `yaml:"enabled"`
	Window         time.Duration `yaml:"window"`           // ventana de IPs distintas; default 1h
	Bucket         time.Duration `yaml:"bucket"`           // tamaño de cada HLL; default 10m
	MinDistinctIPs int64         `yaml:"min_distinct_ips"` // umbral para marcar el JA4; default 50
	TTL            time.Duration `yaml:"ttl"`              // cuánto dura la mala reputación; default 30m
	CacheTTL       time.Duration `yaml:"cache_ttl"`        // caché local del proxy; default 10s
	LookupTimeout  time.Duration `yaml:"lookup_timeout"`   // presupuesto del GET en el proxy; default 20ms
}

func (c Config) WithDefaults() Config {
	if c.Window == 0 {
		c.Window = DefaultWindow
	}
	if c.Bucket == 0 {
		c.Bucket = DefaultBucket
	}
	if c.MinDistinctIPs == 0 {
		c.MinDistinctIPs = DefaultMinDistinctIPs
	}
	if c.TTL == 0 {
		c.TTL = DefaultTTL
	}
	if c.CacheTTL == 0 {
		c.CacheTTL = DefaultCacheTTL
	}
	if c.LookupTimeout == 0 {
		c.LookupTimeout = DefaultLookupTimeout
	}
	return c
}

// Validate espera la config YA con defaults (config.Load llama WithDefaults antes).
func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	var errs []error
	if c.Bucket <= 0 || c.Window <= 0 {
		errs = append(errs, errors.New("reputation.window y reputation.bucket deben ser > 0"))
	} else {
		if c.Window%c.Bucket != 0 {
			errs = append(errs, fmt.Errorf("reputation.window (%s) debe ser múltiplo de reputation.bucket (%s)", c.Window, c.Bucket))
		}
		if c.Window/c.Bucket > maxBuckets {
			errs = append(errs, fmt.Errorf("reputation.window/bucket da %d buckets; el máximo es %d", c.Window/c.Bucket, maxBuckets))
		}
	}
	if c.MinDistinctIPs < 2 {
		errs = append(errs, errors.New("reputation.min_distinct_ips debe ser >= 2"))
	}
	if c.TTL <= 0 || c.CacheTTL < 0 || c.LookupTimeout <= 0 {
		errs = append(errs, errors.New("reputation.ttl y reputation.lookup_timeout deben ser > 0; cache_ttl no puede ser negativo"))
	}
	return errors.Join(errs...)
}

// Llaves. El {ja4} entre llaves es un hash tag: en Redis Cluster todas las
// llaves de un mismo JA4 caen en el mismo slot, y así PFCOUNT puede unir
// varias llaves en una sola llamada (las llamadas multi-llave exigen un slot).
func hllKey(app, ja4 string, bucketStart time.Time) string {
	return fmt.Sprintf("gd:%s:ja4ips:{%s}:%d", app, ja4, bucketStart.Unix())
}

func repKey(app, ja4 string) string {
	return fmt.Sprintf("gd:%s:ja4rep:{%s}", app, ja4)
}

// windowKeys devuelve las llaves de los buckets que cubren la ventana que termina en now.
func (c Config) windowKeys(app, ja4 string, now time.Time) []string {
	n := int(c.Window / c.Bucket)
	cur := now.UTC().Truncate(c.Bucket)
	keys := make([]string, 0, n)
	for i := 0; i < n; i++ {
		keys = append(keys, hllKey(app, ja4, cur.Add(-time.Duration(i)*c.Bucket)))
	}
	return keys
}

// ---------------------------------------------------------------- Aggregator

// Aggregator aplica lotes de eventos. Todo lo que hace es idempotente:
// PFADD de un ip_hash repetido no cambia el HLL, EXPIRE y SET pisan el mismo
// valor. Por eso un mensaje que SQS entrega dos veces no infla nada.
type Aggregator struct {
	rdb redis.UniversalClient
	app string
	cfg Config
	now func() time.Time
}

func NewAggregator(rdb redis.UniversalClient, app string, cfg Config) *Aggregator {
	return &Aggregator{rdb: rdb, app: app, cfg: cfg.WithDefaults(), now: time.Now}
}

// Marked es un JA4 que cruzó el umbral en este lote.
type Marked struct {
	JA4         string
	DistinctIPs int64
}

// Apply hace a lo sumo tres viajes a Redis (tres pipelines), sin importar el tamaño del lote:
//  1. PFADD + EXPIRE de cada evento en el bucket de SU hora (ev.Time).
//  2. PFCOUNT de la ventana por cada JA4 tocado.
//  3. SET ... EX para los JA4 que cruzan el umbral.
//
// Si devuelve error, el caller NO debe borrar los mensajes: volverán a llegar
// y, como todo es idempotente, reaplicarlos es seguro.
func (a *Aggregator) Apply(ctx context.Context, evs []events.Event) ([]Marked, error) {
	touched := make(map[string]struct{})
	pipe := a.rdb.Pipeline()
	for _, ev := range evs {
		if ev.JA4 == "" || ev.IPHash == "" {
			continue // sin JA4 o sin IP no hay nada que agregar
		}
		t := ev.Time
		if t.IsZero() {
			t = a.now()
		}
		key := hllKey(a.app, ev.JA4, t.UTC().Truncate(a.cfg.Bucket))
		pipe.PFAdd(ctx, key, ev.IPHash)
		// El bucket vive la ventana completa más uno de holgura y se borra solo.
		pipe.Expire(ctx, key, a.cfg.Window+a.cfg.Bucket)
		touched[ev.JA4] = struct{}{}
	}
	if len(touched) == 0 {
		return nil, nil
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("reputation: PFADD: %w", err)
	}

	now := a.now()
	counts := make(map[string]*redis.IntCmd, len(touched))
	pipe = a.rdb.Pipeline()
	for ja4 := range touched {
		counts[ja4] = pipe.PFCount(ctx, a.cfg.windowKeys(a.app, ja4, now)...)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("reputation: PFCOUNT: %w", err)
	}

	var marked []Marked
	pipe = a.rdb.Pipeline()
	for ja4, cmd := range counts {
		n := cmd.Val()
		if n < a.cfg.MinDistinctIPs {
			continue
		}
		// Guardamos el conteo como valor: útil para depurar con valkey-cli GET.
		pipe.Set(ctx, repKey(a.app, ja4), n, a.cfg.TTL)
		marked = append(marked, Marked{JA4: ja4, DistinctIPs: n})
	}
	if len(marked) > 0 {
		if _, err := pipe.Exec(ctx); err != nil {
			return nil, fmt.Errorf("reputation: SET: %w", err)
		}
	}
	return marked, nil
}

// ---------------------------------------------------------------- Reader

// Reader lo usa el proxy en cada request. Un GET a Redis por request sería
// otro round trip como el de mw.ratelimit; por eso hay una caché local corta.
type Reader struct {
	rdb redis.UniversalClient
	app string
	cfg Config
	now func() time.Time

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	bad     bool
	expires time.Time
}

func NewReader(rdb redis.UniversalClient, app string, cfg Config) *Reader {
	return &Reader{rdb: rdb, app: app, cfg: cfg.WithDefaults(), now: time.Now, cache: make(map[string]cacheEntry)}
}

// Bad dice si el JA4 tiene mala reputación. Ante un error de Redis devuelve
// false y el error: fail-open, igual que el rate limit. Nunca bloqueamos a
// alguien porque nuestra base de datos esté caída.
func (r *Reader) Bad(ctx context.Context, ja4 string) (bool, int64, error) {
	if ja4 == "" {
		return false, 0, nil
	}
	now := r.now()
	r.mu.Lock()
	e, ok := r.cache[ja4]
	r.mu.Unlock()
	if ok && now.Before(e.expires) {
		return e.bad, 0, nil
	}

	ctx, cancel := context.WithTimeout(ctx, r.cfg.LookupTimeout)
	defer cancel()
	val, err := r.rdb.Get(ctx, repKey(r.app, ja4)).Result()
	switch {
	case errors.Is(err, redis.Nil):
		r.store(ja4, false, now)
		return false, 0, nil
	case err != nil:
		return false, 0, fmt.Errorf("reputation: GET: %w", err) // no se cachea: reintenta en el próximo request
	}
	n, _ := strconv.ParseInt(val, 10, 64)
	r.store(ja4, true, now)
	return true, n, nil
}

func (r *Reader) store(ja4 string, bad bool, now time.Time) {
	if r.cfg.CacheTTL == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) >= maxCacheEntries {
		// Tope de memoria: un atacante que rota JA4 no nos llena la RAM.
		// Vaciar todo es tosco pero O(1) y suficiente con un TTL de segundos.
		r.cache = make(map[string]cacheEntry)
	}
	r.cache[ja4] = cacheEntry{bad: bad, expires: now.Add(r.cfg.CacheTTL)}
}
