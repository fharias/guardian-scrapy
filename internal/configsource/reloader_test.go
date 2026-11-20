package configsource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/fharias/guardian-scrapy/internal/config"
	"github.com/fharias/guardian-scrapy/internal/scoring"
	"github.com/fharias/guardian-scrapy/internal/verdict"
)

// cfgYAML es una config mínima válida. extra se agrega al final.
func cfgYAML(headersWeight, challenge, block int, extra string) string {
	return fmt.Sprintf(`upstream: "http://localhost:9000"
challenge:
  difficulty: 16
modes:
  default: enforce
scoring:
  weights:
    headers_incomplete: %d
    ja4_reputation: 50
  thresholds:
    challenge: %d
    block: %d
%s`, headersWeight, challenge, block, extra)
}

// scoreBuild construye un handler que responde "<score> <decision>" para un
// request con headers incompletos, usando el scorer REAL de guardian.
func scoreBuild(builds *atomic.Int32) BuildFunc[http.Handler] {
	return func(cfg *config.Config, version string) (http.Handler, error) {
		builds.Add(1)
		s, err := scoring.New(cfg.Scoring)
		if err != nil {
			return nil, err
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			score, _, dec := s.Evaluate(verdict.Signals{HeadersIncomplete: true})
			w.Header().Set("X-Config-Version", version)
			fmt.Fprintf(w, "%d %s", score, dec)
		}), nil
	}
}

type fixture struct {
	path   string
	r      *Reloader[http.Handler]
	reg    *prometheus.Registry
	builds atomic.Int32
}

func newFixture(t *testing.T, initial string) *fixture {
	t.Helper()
	f := &fixture{path: filepath.Join(t.TempDir(), "guardian.yml"), reg: prometheus.NewRegistry()}
	write(t, f.path, initial)
	src := NewFileSource(f.path, 0, quietLogger())
	cfg, version, err := LoadInitial(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	f.r, err = New(src, cfg, version, scoreBuild(&f.builds), Options{
		Logger: quietLogger(), Registerer: f.reg, Debounce: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// get hace un request contra el snapshot vigente y devuelve el body.
func (f *fixture) get(t *testing.T) string {
	t.Helper()
	rec := httptest.NewRecorder()
	Handler(f.r).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec.Body.String()
}

func TestReload(t *testing.T) {
	cases := []struct {
		name        string
		initial     string
		next        string
		wantErr     string // "" = se aplica
		wantBody    string // respuesta después de la recarga
		wantVersion bool   // ¿cambia la versión activa?
		wantBuilds  int32  // builds DESPUÉS del inicial
		check       func(t *testing.T, cfg *config.Config)
	}{
		{
			name: "cambiar un peso se aplica", initial: cfgYAML(30, 40, 85, ""), next: cfgYAML(45, 40, 85, ""),
			wantBody: "45 challenge", wantVersion: true, wantBuilds: 1,
		},
		{
			// config.Parse no valida scoring: lo valida scoring.New dentro del
			// build. Por eso hay 1 build: falla y NO se publica nada.
			name: "challenge >= block se rechaza", initial: cfgYAML(30, 40, 85, ""), next: cfgYAML(45, 90, 85, ""),
			wantErr: "debe ser menor que block", wantBody: "30 allow", wantBuilds: 1,
		},
		{
			name: "YAML roto se rechaza", initial: cfgYAML(30, 40, 85, ""), next: "scoring: [\n",
			wantErr: "parseando YAML", wantBody: "30 allow",
		},
		{
			name: "archivo vacío (editor a mitad de guardar) se rechaza", initial: cfgYAML(30, 40, 85, ""), next: "",
			wantErr: "EOF", wantBody: "30 allow",
		},
		{
			name: "campo con typo se rechaza (KnownFields)", initial: cfgYAML(30, 40, 85, ""), next: cfgYAML(45, 40, 85, "scorng: {}\n"),
			wantErr: "scorng", wantBody: "30 allow",
		},
		{
			name:    "lo que requiere reinicio se ignora y lo recargable se aplica",
			initial: cfgYAML(30, 40, 85, ""), next: cfgYAML(45, 40, 85, "rate: 5\nlisten: \":9999\"\n"),
			wantBody: "45 challenge", wantVersion: true, wantBuilds: 1,
			check: func(t *testing.T, cfg *config.Config) {
				if cfg.Rate != 1 || cfg.Listen != ":8080" {
					t.Fatalf("rate=%v listen=%q: se aplicó algo que requiere reinicio", cfg.Rate, cfg.Listen)
				}
			},
		},
		{
			name: "mismo contenido no reconstruye", initial: cfgYAML(30, 40, 85, ""), next: cfgYAML(30, 40, 85, ""),
			wantBody: "30 allow",
		},
		{
			// El archivo nuevo, solo, es válido: apaga reputation y pone su peso
			// en 0. Pero reputation.enabled requiere reinicio, así que la config
			// mezclada queda con reputation encendida y peso 0: inválida.
			name:    "válida sola pero inválida mezclada se rechaza",
			initial: cfgYAML(30, 40, 85, "reputation:\n  enabled: true\n"),
			next:    strings.Replace(cfgYAML(30, 40, 85, "reputation:\n  enabled: false\n"), "ja4_reputation: 50", "ja4_reputation: 0", 1),
			wantErr: "config mezclada inválida", wantBody: "30 allow",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, c.initial)
			before := f.r.Current()
			f.builds.Store(0)

			writeAtomic(t, f.path, c.next)
			err := f.r.Reload(context.Background(), "test")

			if c.wantErr == "" && err != nil {
				t.Fatalf("Reload: %v", err)
			}
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) || !errors.Is(err, ErrRejected) {
					t.Fatalf("err = %v, want ErrRejected que contenga %q", err, c.wantErr)
				}
			}
			if got := f.get(t); got != c.wantBody {
				t.Fatalf("body = %q, want %q", got, c.wantBody)
			}
			if changed := f.r.Current().Version != before.Version; changed != c.wantVersion {
				t.Fatalf("versión cambió = %v, want %v", changed, c.wantVersion)
			}
			if got := f.builds.Load(); got != c.wantBuilds {
				t.Fatalf("builds = %d, want %d", got, c.wantBuilds)
			}
			if c.check != nil {
				c.check(t, f.r.Current().Config)
			}
		})
	}
}

func TestConfigInvalidaNoSeAplica(t *testing.T) {
	f := newFixture(t, cfgYAML(30, 40, 85, ""))
	good := f.r.Current()

	writeAtomic(t, f.path, cfgYAML(45, 90, 85, "")) // challenge >= block
	if err := f.r.Reload(context.Background(), "test"); !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
	if f.r.Current() != good {
		t.Fatal("el snapshot activo cambió con una config inválida")
	}
	if got := f.get(t); got != "30 allow" {
		t.Fatalf("body = %q: se aplicó el peso de una config inválida", got)
	}
	if v := testutil.ToFloat64(f.r.lastOK); v != 0 {
		t.Fatalf("last_reload_successful = %v, want 0", v)
	}
	if v := testutil.ToFloat64(f.r.reloads.WithLabelValues("error")); v != 1 {
		t.Fatalf("reloads{error} = %v, want 1", v)
	}
	if v := testutil.ToFloat64(f.r.info.WithLabelValues(good.Version)); v != 1 {
		t.Fatalf("config_info{version=%s} = %v, want 1 (la activa sigue siendo la buena)", good.Version, v)
	}

	// El poll vuelve a ver el mismo archivo malo: no repite el error.
	if err := f.r.Reload(context.Background(), "poll"); err != nil {
		t.Fatalf("poll sobre la misma versión rechazada: %v", err)
	}
	if v := testutil.ToFloat64(f.r.reloads.WithLabelValues("error")); v != 1 {
		t.Fatalf("reloads{error} = %v tras el poll, want 1", v)
	}

	// Se arregla el archivo: se aplica y las métricas vuelven a verde.
	writeAtomic(t, f.path, cfgYAML(45, 40, 85, ""))
	if err := f.r.Reload(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
	if got := f.get(t); got != "45 challenge" {
		t.Fatalf("body = %q, want \"45 challenge\"", got)
	}
	if v := testutil.ToFloat64(f.r.lastOK); v != 1 {
		t.Fatalf("last_reload_successful = %v, want 1", v)
	}
	if n := testutil.CollectAndCount(f.r.info); n != 1 {
		t.Fatalf("guardian_config_info tiene %d series, want 1", n)
	}
}

// Corre con -race. Muchos clientes pegándole al server mientras el archivo se
// reescribe y se recarga 40 veces: ningún request falla y cada respuesta es
// coherente con UNA de las dos configs, nunca una mezcla.
func TestRecargaConRequestsConcurrentes(t *testing.T) {
	f := newFixture(t, cfgYAML(30, 40, 85, ""))
	srv := httptest.NewServer(Handler(f.r))
	defer srv.Close()

	var (
		stop    atomic.Bool
		total   atomic.Int64
		failed  atomic.Int64
		wg      sync.WaitGroup
		seenMu  sync.Mutex
		seen    = map[string]int{}
		allowed = map[string]bool{"30 allow": true, "45 challenge": true}
	)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				resp, err := srv.Client().Get(srv.URL)
				if err != nil {
					failed.Add(1)
					continue
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				total.Add(1)
				if resp.StatusCode != http.StatusOK || !allowed[string(body)] {
					failed.Add(1)
					continue
				}
				seenMu.Lock()
				seen[string(body)]++
				seenMu.Unlock()
			}
		}()
	}

	for i := 0; i < 40; i++ {
		w := 30
		if i%2 == 0 {
			w = 45
		}
		writeAtomic(t, f.path, cfgYAML(w, 40, 85, ""))
		if err := f.r.Reload(context.Background(), "test"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	stop.Store(true)
	wg.Wait()

	if failed.Load() != 0 {
		t.Fatalf("%d de %d requests fallaron durante las recargas", failed.Load(), total.Load())
	}
	if len(seen) != 2 {
		t.Fatalf("respuestas vistas = %v, want las dos configs", seen)
	}
	t.Logf("%d requests, 0 errores, %v", total.Load(), seen)
}

// Un request que empezó con la config vieja termina con ella aunque en la
// mitad se publique otra.
func TestRequestEnVueloTerminaConSuSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardian.yml")
	write(t, path, cfgYAML(30, 40, 85, ""))
	src := NewFileSource(path, 0, quietLogger())
	cfg, version, err := LoadInitial(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	build := func(cfg *config.Config, version string) (http.Handler, error) {
		w := cfg.Scoring.Weights.HeadersIncomplete
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/lento" {
				close(entered)
				<-release
			}
			fmt.Fprint(rw, strconv.Itoa(w))
		}), nil
	}
	r, err := New(src, cfg, version, build, Options{Logger: quietLogger()})
	if err != nil {
		t.Fatal(err)
	}
	h := Handler(r)

	slow := make(chan string)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/lento", nil))
		slow <- rec.Body.String()
	}()
	<-entered // el request lento ya tomó el snapshot con peso 30

	writeAtomic(t, path, cfgYAML(45, 40, 85, ""))
	if err := r.Reload(context.Background(), "test"); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Body.String() != "45" {
		t.Fatalf("request nuevo = %q, want 45", rec.Body.String())
	}

	close(release)
	if got := <-slow; got != "30" {
		t.Fatalf("request en vuelo = %q, want 30 (el snapshot con el que empezó)", got)
	}
}

// De punta a punta: Run + fsnotify + debounce. Guardas el archivo y, sin
// llamar Reload a mano, el peso nuevo queda aplicado.
func TestRunRecargaAlGuardar(t *testing.T) {
	f := newFixture(t, cfgYAML(30, 40, 85, ""))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.r.Run(ctx)
	time.Sleep(150 * time.Millisecond) // que el watcher quede registrado

	writeAtomic(t, f.path, cfgYAML(45, 40, 85, ""))

	deadline := time.Now().Add(3 * time.Second)
	for f.get(t) != "45 challenge" {
		if time.Now().After(deadline) {
			t.Fatalf("no se aplicó el peso nuevo; body = %q", f.get(t))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// fakeSource cuenta los Fetch y no avisa sola: los avisos los da el test.
type fakeSource struct {
	data    atomic.Value // string
	fetches atomic.Int32
}

func (s *fakeSource) Name() string { return "fake" }
func (s *fakeSource) Fetch(context.Context) ([]byte, error) {
	s.fetches.Add(1)
	return []byte(s.data.Load().(string)), nil
}
func (s *fakeSource) Watch(ctx context.Context, _ func(string)) error {
	<-ctx.Done()
	return nil
}

func TestDebounceAgrupaRafagas(t *testing.T) {
	src := &fakeSource{}
	src.data.Store(cfgYAML(30, 40, 85, ""))
	cfg, version, err := LoadInitial(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	var builds atomic.Int32
	r, err := New(src, cfg, version, scoreBuild(&builds), Options{Logger: quietLogger(), Debounce: 80 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	src.data.Store(cfgYAML(45, 40, 85, ""))
	src.fetches.Store(0)
	for i := 0; i < 10; i++ { // un "guardar" que dispara 10 eventos seguidos
		r.Trigger("fsnotify WRITE")
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)

	if n := src.fetches.Load(); n != 1 {
		t.Fatalf("Fetch se llamó %d veces, want 1 (debounce)", n)
	}
	if n := builds.Load(); n != 2 {
		t.Fatalf("builds = %d, want 2 (arranque + una recarga)", n)
	}
}
