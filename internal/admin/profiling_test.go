package admin

import (
	"net/http"
	"runtime"
	"testing"
	"time"
)

func TestApplyProfilingApagadoPorDefecto(t *testing.T) {
	before := runtime.SetMutexProfileFraction(-1) // -1 solo lee, no cambia
	restore := Config{Enabled: true}.ApplyProfiling()
	defer restore()
	if got := runtime.SetMutexProfileFraction(-1); got != before {
		t.Fatalf("con 0 no debe tocar el runtime: fraction = %d, antes %d", got, before)
	}
}

func TestApplyProfilingEnciendeYRestaura(t *testing.T) {
	before := runtime.SetMutexProfileFraction(-1)
	cfg := Config{Enabled: true, MutexProfileFraction: 7, BlockProfileRate: time.Millisecond}
	restore := cfg.ApplyProfiling()
	if got := runtime.SetMutexProfileFraction(-1); got != 7 {
		t.Fatalf("mutex fraction = %d, want 7", got)
	}
	restore()
	if got := runtime.SetMutexProfileFraction(-1); got != before {
		t.Fatalf("restore: fraction = %d, want %d", got, before)
	}
}

func TestApplyProfilingConAdminApagadoNoHaceNada(t *testing.T) {
	before := runtime.SetMutexProfileFraction(-1)
	restore := Config{Enabled: false, MutexProfileFraction: 7}.ApplyProfiling()
	defer restore()
	if got := runtime.SetMutexProfileFraction(-1); got != before {
		t.Fatalf("admin apagada: fraction = %d, want %d", got, before)
	}
}

func TestProfilingValidaNegativos(t *testing.T) {
	for name, c := range map[string]Config{
		"fraction negativa": {Enabled: true, MutexProfileFraction: -1},
		"rate negativo":     {Enabled: true, BlockProfileRate: -time.Millisecond},
	} {
		t.Run(name, func(t *testing.T) {
			if err := c.WithDefaults().Validate(); err == nil {
				t.Fatal("esperaba error")
			}
		})
	}
}

// Cada perfil que usa el Reto 4 responde 200 con token y 401 sin él.
func TestPprofPerfilesDelReto4(t *testing.T) {
	a := newAPI(t, nil)
	for _, name := range []string{"allocs", "goroutine", "mutex", "block", "heap"} {
		path := "/debug/pprof/" + name
		if rec := a.do(t, "GET", path, "", ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s sin token: code = %d, want 401", path, rec.Code)
		}
		rec := a.do(t, "GET", path, tokenA, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s con token: code = %d, want 200", path, rec.Code)
		}
	}
}
