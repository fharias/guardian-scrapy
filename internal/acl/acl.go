// Package acl guarda los bloqueos y la allowlist que un operador crea desde la
// Admin API. Viven en Redis/Valkey para que TODAS las réplicas de guardian los
// vean; cada réplica mantiene una caché local corta para no pagar un round trip
// extra por request.
//
// Modelo:
//   - Lista "block": por IP o por JA4. Un match es una negación dura: el scorer
//     devuelve Block aunque la ruta esté en monitor.
//   - Lista "allow": solo por IP. Un match salta la heurística del scorer, pero
//     NUNCA gana a una negación dura (deny gana, como en IAM).
//   - Toda entrada tiene TTL. Lo permanente va en el YAML (rules.deny_cidrs),
//     versionado en git y con code review.
//   - Toda entrada es de UNA app: vive bajo gd:<app>:acl:. Bloquear una IP en
//     "shop" no la bloquea en "api". Un solo Store atiende a todas las apps
//     (una caché, un juego de métricas); la app viaja en cada llamada.
package acl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"

	"github.com/fharias/guardian-scrapy/internal/apps"
	"github.com/fharias/guardian-scrapy/internal/fingerprint"
)

// List es la lista a la que pertenece una entrada.
type List string

const (
	Block List = "block"
	Allow List = "allow"
)

// Kind es el tipo de valor que identifica al cliente.
type Kind string

const (
	KindIP  Kind = "ip"
	KindJA4 Kind = "ja4"
)

const (
	DefaultCacheTTL      = 2 * time.Second
	DefaultStaleTTL      = time.Minute
	DefaultLookupTimeout = 20 * time.Millisecond
	maxCacheEntries      = 10000
	MaxReasonLen         = 200
	MaxActorLen          = 64
)

// ErrInvalid envuelve todo error de validación: la Admin API lo traduce a 400.
var ErrInvalid = errors.New("acl: entrada inválida")

// Entry es lo que se guarda en Redis como JSON, una llave por entrada.
type Entry struct {
	App       string    `json:"app"`
	List      List      `json:"list"`
	Kind      Kind      `json:"kind"`
	Value     string    `json:"value"`
	Reason    string    `json:"reason"`
	Actor     string    `json:"actor"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SignalReason es el texto FIJO que llega a verdict.Reasons, al log y al label
// reason de guardian_signals_total. Nunca el Reason libre del operador: eso
// rompería la cardinalidad de Prometheus.
func (e *Entry) SignalReason() string {
	if e == nil {
		return ""
	}
	if e.List == Allow {
		return "allowlist_admin"
	}
	return "bloqueo_admin_" + string(e.Kind)
}

// Normalize valida y deja en forma canónica el valor. Dos formas de escribir la
// misma IP (::ffff:1.2.3.4 y 1.2.3.4, o un IPv6 con ceros) deben dar la MISMA
// llave en Redis; si no, el bloqueo no matchearía.
func Normalize(list List, kind Kind, value string) (string, error) {
	switch list {
	case Block, Allow:
	default:
		return "", fmt.Errorf("%w: lista %q (usa block o allow)", ErrInvalid, list)
	}
	switch kind {
	case KindIP:
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.Zone() != "" {
			return "", fmt.Errorf("%w: ip %q no es una IP válida", ErrInvalid, value)
		}
		return ip.Unmap().String(), nil
	case KindJA4:
		if list == Allow {
			// Un JA4 lo comparten millones de clientes (todo Chrome de una versión):
			// "confiar en un JA4" es confiar en cualquiera que use ese navegador.
			return "", fmt.Errorf("%w: la allowlist solo acepta ip", ErrInvalid)
		}
		v := strings.ToLower(value)
		if !fingerprint.ValidJA4(v) {
			return "", fmt.Errorf("%w: ja4 %q no tiene la forma a_b_c (10_12_12)", ErrInvalid, value)
		}
		return v, nil
	}
	return "", fmt.Errorf("%w: kind %q (usa ip o ja4)", ErrInvalid, kind)
}

// Options ajusta el Store. Los ceros toman defaults.
type Options struct {
	CacheTTL      time.Duration         // cuánto confía una réplica en lo que ya leyó; default 2s
	StaleTTL      time.Duration         // si Redis falla, hasta cuánto sirve lo viejo; default 1m
	LookupTimeout time.Duration         // presupuesto del GET en el camino del request; default 20ms
	Registerer    prometheus.Registerer // default: registry propio (no se expone)
	Now           func() time.Time      // default time.Now; los tests lo controlan
}

// Store lee (proxy) y escribe (Admin API) las entradas de todas las apps.
type Store struct {
	rdb  redis.UniversalClient
	opts Options

	mu    sync.Mutex
	cache map[string]cached

	matches *prometheus.CounterVec
	errors  prometheus.Counter
	stale   prometheus.Counter
}

type cached struct {
	entry   *Entry // nil = no existe
	fetched time.Time
}

func New(rdb redis.UniversalClient, opts Options) *Store {
	if opts.CacheTTL == 0 {
		opts.CacheTTL = DefaultCacheTTL
	}
	if opts.CacheTTL < 0 {
		opts.CacheTTL = 0 // negativo = sin caché (útil en tests)
	}
	if opts.StaleTTL <= 0 {
		opts.StaleTTL = DefaultStaleTTL
	}
	if opts.LookupTimeout <= 0 {
		opts.LookupTimeout = DefaultLookupTimeout
	}
	if opts.Registerer == nil {
		opts.Registerer = prometheus.NewRegistry()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	f := promauto.With(opts.Registerer)
	return &Store{
		rdb:   rdb,
		opts:  opts,
		cache: make(map[string]cached),
		matches: f.NewCounterVec(prometheus.CounterOpts{
			Name: "guardian_acl_matches_total",
			Help: "Requests que matchearon una entrada de la Admin API, por app, lista y tipo.",
		}, []string{"app", "list", "kind"}),
		errors: f.NewCounter(prometheus.CounterOpts{
			Name: "guardian_acl_lookup_errors_total",
			Help: "Lecturas de la ACL que fallaron contra Redis (el request siguió: fail-open).",
		}),
		stale: f.NewCounter(prometheus.CounterOpts{
			Name: "guardian_acl_stale_served_total",
			Help: "Veces que Redis falló y se usó una entrada vieja de la caché local.",
		}),
	}
}

// Llaves. Una llave por entrada para que Redis borre cada una sola con su TTL:
// no hay job de limpieza. Sin hash tag a propósito: las llaves se reparten en
// todos los slots del cluster y un ataque con IPs rotativas no calienta un
// solo shard. El GET por request va en un pipeline (go-redis lo reparte por nodo).
func entryKey(app string, list List, kind Kind, value string) string {
	return fmt.Sprintf("gd:%s:acl:%s:%s:%s", app, list, kind, value)
}

// indexKey es un ZSET por lista (score = expires_at en ms). Solo lo usa el
// listado de la Admin API: SCAN en Redis Cluster recorre un solo nodo, el ZSET no.
func indexKey(app string, list List) string {
	return fmt.Sprintf("gd:%s:acl:index:%s", app, list)
}

func indexMember(kind Kind, value string) string { return string(kind) + ":" + value }

// checkApp: el nombre va dentro de la llave. Uno inválido (con ':' o llaves)
// podría escribir en el espacio de OTRA app o cambiar el hash tag.
func checkApp(app string) error {
	if !apps.ValidName(app) {
		return fmt.Errorf("%w: app %q", ErrInvalid, app)
	}
	return nil
}

// Match es lo que encontró Check. Pueden venir las dos: el scorer decide.
type Match struct {
	Block *Entry
	Allow *Entry
}

// Check busca la IP y el JA4 del request. Hace como mucho UN round trip
// (pipeline) y solo por las llaves que no están frescas en la caché.
//
// Ante un error de Redis devuelve lo que pueda de la caché (aunque esté
// vencida, si tiene menos de StaleTTL) y el error: fail-open. Un bloqueo activo
// no desaparece por un parpadeo de Redis, pero tampoco bloqueamos a nadie
// porque Redis esté caído.
func (s *Store) Check(ctx context.Context, app string, ip netip.Addr, ja4 string) (Match, error) {
	if err := checkApp(app); err != nil {
		return Match{}, err
	}
	type lookup struct {
		list List
		kind Kind
		key  string
	}
	var want []lookup
	if ip.IsValid() {
		v := ip.Unmap().String()
		want = append(want,
			lookup{Allow, KindIP, entryKey(app, Allow, KindIP, v)},
			lookup{Block, KindIP, entryKey(app, Block, KindIP, v)})
	}
	if ja4 != "" {
		want = append(want, lookup{Block, KindJA4, entryKey(app, Block, KindJA4, ja4)})
	}
	if len(want) == 0 {
		return Match{}, nil
	}

	now := s.opts.Now()
	found := make(map[string]*Entry, len(want))
	var miss []string
	s.mu.Lock()
	for _, l := range want {
		c, ok := s.cache[l.key]
		if ok && now.Sub(c.fetched) < s.opts.CacheTTL {
			found[l.key] = c.entry
			continue
		}
		miss = append(miss, l.key)
	}
	s.mu.Unlock()

	var lookupErr error
	if len(miss) > 0 {
		lctx, cancel := context.WithTimeout(ctx, s.opts.LookupTimeout)
		got, err := s.fetch(lctx, miss)
		cancel()
		if err != nil {
			lookupErr = err
			s.errors.Inc()
			s.mu.Lock()
			for _, k := range miss {
				if c, ok := s.cache[k]; ok && now.Sub(c.fetched) < s.opts.StaleTTL {
					found[k] = c.entry
					s.stale.Inc()
				}
			}
			s.mu.Unlock()
		} else {
			s.remember(got, now)
			for k, e := range got {
				found[k] = e
			}
		}
	}

	var m Match
	for _, l := range want {
		e := found[l.key]
		if e == nil || !now.Before(e.ExpiresAt) {
			continue // ausente, o la caché guardó algo que ya expiró
		}
		switch {
		case l.list == Allow && m.Allow == nil:
			m.Allow = e
			s.matches.WithLabelValues(app, string(l.list), string(l.kind)).Inc()
		case l.list == Block && m.Block == nil:
			m.Block = e
			s.matches.WithLabelValues(app, string(l.list), string(l.kind)).Inc()
		}
	}
	return m, lookupErr
}

// fetch hace un pipeline de GETs. Devuelve un valor por llave (nil = no existe).
func (s *Store) fetch(ctx context.Context, keys []string) (map[string]*Entry, error) {
	pipe := s.rdb.Pipeline()
	cmds := make([]*redis.StringCmd, len(keys))
	for i, k := range keys {
		cmds[i] = pipe.Get(ctx, k)
	}
	// Exec devuelve el primer error de los comandos, y para un GET de una llave
	// que no existe ese error es redis.Nil: eso NO es una falla.
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("acl: GET: %w", err)
	}
	out := make(map[string]*Entry, len(keys))
	for i, cmd := range cmds {
		raw, err := cmd.Bytes()
		switch {
		case errors.Is(err, redis.Nil):
			out[keys[i]] = nil
		case err != nil:
			return nil, fmt.Errorf("acl: GET %s: %w", keys[i], err)
		default:
			var e Entry
			if err := json.Unmarshal(raw, &e); err != nil {
				out[keys[i]] = nil // basura en la llave: la ignoramos, no tumbamos el request
				continue
			}
			out[keys[i]] = &e
		}
	}
	return out, nil
}

func (s *Store) remember(got map[string]*Entry, now time.Time) {
	if s.opts.CacheTTL == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cache)+len(got) > maxCacheEntries {
		// Tope de memoria: un atacante que rota IPs no nos llena la RAM.
		s.cache = make(map[string]cached)
	}
	for k, e := range got {
		s.cache[k] = cached{entry: e, fetched: now}
	}
}

func (s *Store) forget(key string) {
	s.mu.Lock()
	delete(s.cache, key)
	s.mu.Unlock()
}

// ---------------------------------------------------------------- escritura (Admin API)

// Put crea o reemplaza una entrada con su TTL. El valor ya debe venir de
// Normalize. Escribe la llave y el índice en un pipeline (no MULTI: en Redis
// Cluster las dos llaves pueden caer en slots distintos). Si se cae entre los
// dos comandos, el índice queda desfasado; List lo tolera.
func (s *Store) Put(ctx context.Context, app string, e Entry, ttl time.Duration) (Entry, error) {
	if err := checkApp(app); err != nil {
		return Entry{}, err
	}
	if ttl <= 0 {
		return Entry{}, fmt.Errorf("%w: ttl debe ser > 0", ErrInvalid)
	}
	now := s.opts.Now().UTC()
	e.App = app
	e.CreatedAt = now
	e.ExpiresAt = now.Add(ttl)
	raw, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	key := entryKey(app, e.List, e.Kind, e.Value)
	pipe := s.rdb.Pipeline()
	pipe.Set(ctx, key, raw, ttl)
	pipe.ZAdd(ctx, indexKey(app, e.List), redis.Z{
		Score:  float64(e.ExpiresAt.UnixMilli()),
		Member: indexMember(e.Kind, e.Value),
	})
	if _, err := pipe.Exec(ctx); err != nil {
		return Entry{}, fmt.Errorf("acl: SET: %w", err)
	}
	s.forget(key) // esta réplica lo ve ya; las demás, en máximo CacheTTL
	return e, nil
}

// Get lee directo de Redis, sin caché: la Admin API siempre muestra la verdad.
func (s *Store) Get(ctx context.Context, app string, list List, kind Kind, value string) (*Entry, error) {
	if err := checkApp(app); err != nil {
		return nil, err
	}
	raw, err := s.rdb.Get(ctx, entryKey(app, list, kind, value)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("acl: GET: %w", err)
	}
	var e Entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("acl: entrada corrupta: %w", err)
	}
	return &e, nil
}

// Delete borra la entrada. Devuelve false si no existía.
func (s *Store) Delete(ctx context.Context, app string, list List, kind Kind, value string) (bool, error) {
	if err := checkApp(app); err != nil {
		return false, err
	}
	key := entryKey(app, list, kind, value)
	pipe := s.rdb.Pipeline()
	del := pipe.Del(ctx, key)
	pipe.ZRem(ctx, indexKey(app, list), indexMember(kind, value))
	if _, err := pipe.Exec(ctx); err != nil {
		return false, fmt.Errorf("acl: DEL: %w", err)
	}
	s.forget(key)
	return del.Val() > 0, nil
}

// List devuelve las entradas vigentes de una lista. Primero poda del índice lo
// vencido (ZREMRANGEBYSCORE) y luego trae cada llave; si una ya no existe
// (expiró o la borraron a medias) simplemente no aparece.
func (s *Store) List(ctx context.Context, app string, list List) ([]Entry, error) {
	if err := checkApp(app); err != nil {
		return nil, err
	}
	idx := indexKey(app, list)
	nowMs := s.opts.Now().UnixMilli()
	if err := s.rdb.ZRemRangeByScore(ctx, idx, "-inf", fmt.Sprint(nowMs)).Err(); err != nil {
		return nil, fmt.Errorf("acl: ZREMRANGEBYSCORE: %w", err)
	}
	members, err := s.rdb.ZRange(ctx, idx, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("acl: ZRANGE: %w", err)
	}
	out := make([]Entry, 0, len(members))
	if len(members) == 0 {
		return out, nil
	}
	keys := make([]string, 0, len(members))
	for _, m := range members {
		kind, value, ok := strings.Cut(m, ":")
		if !ok {
			continue
		}
		keys = append(keys, entryKey(app, list, Kind(kind), value))
	}
	got, err := s.fetch(ctx, keys)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if e := got[k]; e != nil {
			out = append(out, *e)
		}
	}
	return out, nil
}
