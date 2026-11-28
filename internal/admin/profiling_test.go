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

	// Una tasa distinta de 0, como la que dejaría un test anterior.
	// El runtime no deja leerla; el spy comprueba que restore no la pisa con 0.
	const previo = int(2 * time.Millisecond)
	blockProfileMu.Lock()
	savedNS := blockProfileNS
	blockProfileNS = previo
	blockProfileMu.Unlock()
	var calls []int
	origSet := setBlockProfileRate
	setBlockProfileRate = func(rate int) { calls = append(calls, rate) }
	t.Cleanup(func() {
		setBlockProfileRate = origSet
		blockProfileMu.Lock()
		blockProfileNS = savedNS
		blockProfileMu.Unlock()
	})

	cfg := Config{Enabled: true, MutexProfileFraction: 7, BlockProfileRate: time.Millisecond}
	restore := cfg.ApplyProfiling()
	if got := runtime.SetMutexProfileFraction(-1); got != 7 {
		t.Fatalf("mutex fraction = %d, want 7", got)
	}
	restore()
	if got := runtime.SetMutexProfileFraction(-1); got != before {
		t.Fatalf("restore: fraction = %d, want %d", got, before)
	}
	if len(calls) != 2 || calls[0] != int(time.Millisecond) || calls[1] != previo {
		t.Fatalf("block rate = %v, want [%d %d]", calls, int(time.Millisecond), previo)
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
