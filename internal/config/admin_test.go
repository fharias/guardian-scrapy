package config

import (
	"strings"
	"testing"
	"time"
)

func TestAdminDefaults(t *testing.T) {
	cfg := mustParse(t, base)
	if cfg.Admin.Enabled || cfg.Admin.Listen != "127.0.0.1:9091" || cfg.Admin.CacheTTL != 2*time.Second {
		t.Fatalf("defaults = %+v", cfg.Admin)
	}
	cfg = mustParse(t, base+`
admin:
  enabled: true
  listen: ":9091"
  max_ttl: 24h
  cache_ttl: 1s
`)
	if !cfg.Admin.Enabled || cfg.Admin.MaxTTL != 24*time.Hour || cfg.Admin.StaleTTL != time.Minute {
		t.Fatalf("admin = %+v", cfg.Admin)
	}
}

func TestAdminProfilingYAML(t *testing.T) {
	cfg := mustParse(t, base+`
admin:
  enabled: true
  listen: ":9091"
  mutex_profile_fraction: 5
  block_profile_rate: 1ms
`)
	if cfg.Admin.MutexProfileFraction != 5 || cfg.Admin.BlockProfileRate != time.Millisecond {
		t.Fatalf("admin = %+v", cfg.Admin)
	}
	// Sin las claves, ambos quedan apagados (0).
	off := mustParse(t, base+"admin:\n  enabled: true\n  listen: \":9091\"\n")
	if off.Admin.MutexProfileFraction != 0 || off.Admin.BlockProfileRate != 0 {
		t.Fatalf("default debe ser 0 (apagado): %+v", off.Admin)
	}
	if _, err := Parse([]byte(base + "admin:\n  enabled: true\n  mutex_profile_fraction: -1\n")); err == nil {
		t.Fatal("fraction negativa debe fallar")
	}
}

func TestAdminValidation(t *testing.T) {
	cases := map[string]string{
		"mismo puerto que el proxy": "admin:\n  enabled: true\n  listen: \"127.0.0.1:8080\"\n",
		"mismo puerto que /metrics": "admin:\n  enabled: true\n  listen: \":2112\"\n",
		"stale menor que cache":     "admin:\n  enabled: true\n  cache_ttl: 5s\n  stale_ttl: 1s\n",
		"el token NO va en el YAML": "admin:\n  enabled: true\n  token: \"secreto\"\n",
		"lookup_timeout negativo":   "admin:\n  enabled: true\n  lookup_timeout: -1s\n",
	}
	for name, yml := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(base + yml))
			if err == nil {
				t.Fatal("esperaba error")
			}
			if strings.Contains(err.Error(), "secreto") {
				t.Fatalf("el error no repite el valor: %v", err)
			}
		})
	}
	// Apagada, nada se valida (igual que reputation).
	if _, err := Parse([]byte(base + "admin:\n  enabled: false\n  listen: \":8080\"\n")); err != nil {
		t.Fatalf("deshabilitada no valida: %v", err)
	}
}

func TestAdminRequiresRestart(t *testing.T) {
	a := mustParse(t, reloadBase)
	b := mustParse(t, reloadBase)
	b.Admin.Enabled = true
	b.Admin.CacheTTL = 5 * time.Second
	apply, restart := SplitChanges(Diff(a, b))
	if len(apply) != 0 || len(restart) != 2 {
		t.Fatalf("apply=%v restart=%v: admin.* requiere reinicio", apply, restart)
	}
}
