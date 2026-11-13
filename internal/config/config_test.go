package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// base es la configuración mínima válida; cada caso le agrega un bloque ja4.
const base = `
upstream: "http://localhost:9000"
trusted_proxies: ["10.0.0.0/8"]
challenge:
  difficulty: 16
modes:
  default: enforce
`

func TestLoadJA4Source(t *testing.T) {
	cases := []struct {
		name       string
		extra      string
		noTrusted  bool
		wantSource string
		wantErr    string
	}{
		{"sin bloque ja4: default tls", "", false, "tls", ""},
		{"bloque ja4 sin source: default tls", "ja4:\n  tools: []\n", false, "tls", ""},
		{"cloudfront", "ja4:\n  source: cloudfront\n", false, "cloudfront", ""},
		{"none", "ja4:\n  source: none\n", false, "none", ""},
		{"valor inválido", "ja4:\n  source: akamai\n", false, "", "ja4.source"},
		{"cloudfront sin trusted_proxies", "ja4:\n  source: cloudfront\n", true, "", "trusted_proxies"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			yml := base + c.extra
			if c.noTrusted {
				yml = strings.Replace(yml, `trusted_proxies: ["10.0.0.0/8"]`, "", 1)
			}
			path := filepath.Join(t.TempDir(), "guardian.yml")
			if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want que contenga %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.JA4.Source != c.wantSource {
				t.Fatalf("source = %q, want %q", cfg.JA4.Source, c.wantSource)
			}
		})
	}
}
