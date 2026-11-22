package config

import (
	"strings"
	"testing"

	"github.com/fharias/guardian-scrapy/internal/fingerprint"
	"github.com/fharias/guardian-scrapy/internal/policy"
)

func mustParse(t *testing.T, yml string) *Config {
	t.Helper()
	cfg, err := Parse([]byte(yml))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

const reloadBase = base + `
scoring:
  weights:
    headers_incomplete: 30
  thresholds:
    challenge: 40
    block: 85
`

func TestDiff(t *testing.T) {
	cases := []struct {
		name      string
		edit      func(*Config)
		wantPaths []string
		wantText  string
	}{
		{"sin cambios", func(*Config) {}, nil, ""},
		{"un peso", func(c *Config) { c.Scoring.Weights.HeadersIncomplete = 45 },
			[]string{"scoring.weights.headers_incomplete"}, "scoring.weights.headers_incomplete: 30 -> 45"},
		{"un umbral y el rate", func(c *Config) { c.Scoring.Thresholds.Block = 90; c.Rate = 5 },
			[]string{"rate", "scoring.thresholds.block"}, "rate: 1 -> 5"},
		{"slice de rutas", func(c *Config) {
			c.Modes.Routes = append(c.Modes.Routes, policy.RouteMode{Prefix: "/api", Mode: policy.Monitor})
		}, []string{"modes.routes"}, "modes.routes: [] -> [{/api monitor}]"},
		{"duration", func(c *Config) { c.ReadTimeout *= 2 }, []string{"read_timeout"}, "read_timeout: 10s -> 20s"},
		{"string con comillas", func(c *Config) { c.Listen = ":9090" }, []string{"listen"}, `listen: ":8080" -> ":9090"`},
		{"ja4.tools", func(c *Config) {
			c.JA4.Tools = []fingerprint.KnownJA4{{Name: "curl", JA4: "t13d"}}
		}, []string{"ja4.tools"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := mustParse(t, reloadBase)
			b := mustParse(t, reloadBase)
			c.edit(b)
			got := Diff(a, b)
			paths := Paths(got)
			if strings.Join(paths, ",") != strings.Join(c.wantPaths, ",") {
				t.Fatalf("paths = %v, want %v", paths, c.wantPaths)
			}
			if c.wantText != "" {
				var all []string
				for _, ch := range got {
					all = append(all, ch.String())
				}
				if !strings.Contains(strings.Join(all, "\n"), c.wantText) {
					t.Fatalf("diff = %v, want que contenga %q", all, c.wantText)
				}
			}
		})
	}
}

func TestIsReloadable(t *testing.T) {
	cases := map[string]bool{
		"scoring":                        true,
		"scoring.weights.ja4_reputation": true,
		"scoring.thresholds.challenge":   true,
		"rules.deny_cidrs":               true,
		"rules.routes":                   true,
		"modes.routes":                   true,
		"ja4.tools":                      true,
		"ja4.source":                     false, // depende del resolver de trusted_proxies
		"ja4":                            false,
		"scoringx":                       false, // prefijo de texto, no de ruta
		"rate":                           false,
		"listen":                         false,
		"tls.cert_file":                  false,
		"trusted_proxies":                false,
		"events.kafka.brokers":           false,
		"reputation.enabled":             false,
		"challenge.difficulty":           false,
		"good_bots":                      false,
	}
	for path, want := range cases {
		if got := IsReloadable(path); got != want {
			t.Errorf("IsReloadable(%q) = %v, want %v", path, got, want)
		}
	}
}

// Si agregas una ruta a Reloadable y no la copias en MergeReloadable (o no la
// cambias aquí en incoming), este test falla.
func TestMergeReloadableCubreLaLista(t *testing.T) {
	running := mustParse(t, reloadBase)
	incoming := mustParse(t, reloadBase)

	incoming.Scoring.Weights.HeadersIncomplete = 45
	incoming.Rules.Honeypots = []string{"/.env"}
	incoming.Modes.Default = policy.Monitor
	incoming.JA4.Tools = []fingerprint.KnownJA4{{Name: "curl", JA4: "t13d"}}
	incoming.Apps = []AppConfig{{Name: "api", Hosts: []string{"api.local"}}}
	incoming.DefaultApp = "api"
	// y cosas que requieren reinicio:
	incoming.Rate = 50
	incoming.Listen = ":9999"
	incoming.JA4.Source = fingerprint.SourceNone

	merged := MergeReloadable(running, incoming)

	applied := Diff(running, merged)
	for _, c := range applied {
		if !IsReloadable(c.Path) {
			t.Errorf("se aplicó %q, que requiere reinicio", c.Path)
		}
	}
	for _, p := range Reloadable {
		found := false
		for _, c := range applied {
			if c.Path == p || strings.HasPrefix(c.Path, p+".") || strings.HasPrefix(c.Path, p+"[") {
				found = true
			}
		}
		if !found {
			t.Errorf("Reloadable incluye %q pero MergeReloadable no lo aplicó (o este test no lo cambia)", p)
		}
	}
	for _, c := range Diff(merged, incoming) {
		if IsReloadable(c.Path) {
			t.Errorf("%q es recargable y quedó sin aplicar", c.Path)
		}
	}
	if running.Scoring.Weights.HeadersIncomplete != 30 {
		t.Fatal("MergeReloadable modificó running")
	}
}

func TestDiffNoMuestraSecretos(t *testing.T) {
	a := mustParse(t, reloadBase)
	b := mustParse(t, reloadBase)
	b.TLS.KeyFile = "/secreto/llave.pem"
	for _, c := range Diff(a, b) {
		if strings.Contains(c.String(), "llave") {
			t.Fatalf("el diff expone la ruta de la llave: %s", c)
		}
	}
}
