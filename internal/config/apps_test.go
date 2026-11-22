package config

import (
	"strings"
	"testing"

	"github.com/fharias/guardian-scrapy/internal/policy"
)

const appsBase = reloadBase + `
rate: 1
burst: 2
apps:
  - name: shop
    hosts: ["shop.local", "*.shop.local"]
  - name: api
    hosts: ["api.local"]
    upstream: "http://api-upstream:9001"
    rate: 20
    burst: 40
    modes:
      default: monitor
    scoring:
      weights:
        ua_tool: 10
      thresholds:
        challenge: 60
        block: 95
`

func TestLegacySinAppsEsUnaSolaApp(t *testing.T) {
	c := mustParse(t, reloadBase)
	if c.MultiApp() {
		t.Fatal("sin apps no es multi-app")
	}
	got := c.ResolveApps()
	if len(got) != 1 || got[0].Name != "shop" || len(got[0].Hosts) != 0 {
		t.Fatalf("legacy = %+v", got)
	}
	if c.EffectiveDefaultApp() != "shop" {
		t.Fatalf("default legacy = %q, want la única app", c.EffectiveDefaultApp())
	}
	if got[0].UpstreamURL == nil || got[0].UpstreamURL.Host != "localhost:9000" || got[0].Rate != c.Rate {
		t.Fatalf("legacy no hereda: %+v", got[0])
	}
}

func TestResolveAppsHerencia(t *testing.T) {
	c := mustParse(t, appsBase)
	if !c.MultiApp() || c.EffectiveDefaultApp() != "" {
		t.Fatalf("multi=%v default=%q", c.MultiApp(), c.EffectiveDefaultApp())
	}
	got := c.ResolveApps()
	if len(got) != 2 {
		t.Fatalf("apps = %d", len(got))
	}
	shop, api := got[0], got[1]

	// shop no define nada: hereda TODO del nivel superior.
	if shop.UpstreamURL.Host != "localhost:9000" || shop.Rate != 1 || shop.Burst != 2 {
		t.Errorf("shop no heredó upstream/rate/burst: %+v", shop)
	}
	if shop.Modes.Default != policy.Enforce || shop.Scoring.Thresholds.Block != 85 {
		t.Errorf("shop no heredó modes/scoring: %+v", shop)
	}
	// api define lo suyo.
	if api.UpstreamURL.Host != "api-upstream:9001" || api.Rate != 20 || api.Burst != 40 {
		t.Errorf("api: %+v", api)
	}
	if api.Modes.Default != policy.Monitor {
		t.Errorf("api.modes = %v", api.Modes.Default)
	}
	// La herencia es por sección: api puso scoring, así que headers_incomplete
	// (que solo está en el global) NO se mezcla: queda en 0.
	if api.Scoring.Weights.UATool != 10 || api.Scoring.Weights.HeadersIncomplete != 0 || api.Scoring.Thresholds.Block != 95 {
		t.Errorf("api.scoring = %+v", api.Scoring)
	}
	// rules no está en api: hereda el global.
	if len(api.Rules.Honeypots) != len(c.Rules.Honeypots) {
		t.Errorf("api.rules no heredó")
	}
	if names := strings.Join(c.AppNames(), ","); names != "shop,api" {
		t.Errorf("AppNames = %s", names)
	}
}

func TestUpstreamGlobalOpcionalConApps(t *testing.T) {
	yml := `
trusted_proxies: ["10.0.0.0/8"]
challenge:
  difficulty: 16
modes:
  default: enforce
apps:
  - name: shop
    hosts: ["shop.local"]
    upstream: "http://shop:9000"
`
	c := mustParse(t, yml)
	if c.ResolveApps()[0].UpstreamURL.Host != "shop:9000" {
		t.Fatal("upstream de la app")
	}
}

func TestValidateApps(t *testing.T) {
	const head = reloadBase + "\n"
	tests := []struct {
		name string
		yml  string
		want string
	}{
		{"host repetido entre apps", `
apps:
  - {name: shop, hosts: ["shop.local"]}
  - {name: api, hosts: ["SHOP.local."]}
`, `"SHOP.local." ya es de apps[shop]`},
		{"comodín repetido", `
apps:
  - {name: shop, hosts: ["*.shop.local"]}
  - {name: api, hosts: ["*.Shop.Local"]}
`, "ya es de apps[shop]"},
		{"name repetido", `
apps:
  - {name: shop, hosts: ["a.local"]}
  - {name: shop, hosts: ["b.local"]}
`, "apps[shop]: name repetido"},
		{"name con mayúsculas", `
apps:
  - {name: Shop, hosts: ["a.local"]}
`, `name "Shop" inválido`},
		{"name con dos puntos", `
apps:
  - {name: "a:b", hosts: ["a.local"]}
`, "inválido"},
		{"name con llaves", `
apps:
  - {name: "{x}", hosts: ["a.local"]}
`, "inválido"},
		{"name vacío", `
apps:
  - {hosts: ["a.local"]}
`, `apps[0]: name "" inválido`},
		{"host con puerto", `
apps:
  - {name: shop, hosts: ["shop.local:8080"]}
`, "sin puerto"},
		{"comodín en el medio", `
apps:
  - {name: shop, hosts: ["shop.*.local"]}
`, "comodín solo va al principio"},
		{"comodín de TLD", `
apps:
  - {name: shop, hosts: ["*.local"]}
`, "dos etiquetas"},
		{"app sin hosts que no es default", `
apps:
  - {name: shop, hosts: ["shop.local"]}
  - {name: api}
`, "apps[api]: sin hosts"},
		{"default_app que no existe", `
default_app: nope
apps:
  - {name: shop, hosts: ["shop.local"]}
`, `default_app "nope" no está en apps`},
		{"default_app sin apps", `
default_app: shop
`, "default_app sin apps"},
		{"upstream inválido", `
apps:
  - {name: shop, hosts: ["shop.local"], upstream: "shop:9000"}
`, "apps[shop].upstream"},
		{"scoring propio inválido", `
apps:
  - name: shop
    hosts: ["shop.local"]
    scoring:
      thresholds: {challenge: 90, block: 85}
`, "apps[shop].scoring.thresholds: challenge (90) debe ser menor que block (85)"},
		{"modes propio inválido", `
apps:
  - name: shop
    hosts: ["shop.local"]
    modes: {default: bloquear}
`, "apps[shop].modes"},
		{"rules propio inválido", `
apps:
  - name: shop
    hosts: ["shop.local"]
    rules: {deny_cidrs: ["no-es-cidr"]}
`, "apps[shop].rules.deny_cidrs"},
		{"rate negativo", `
apps:
  - {name: shop, hosts: ["shop.local"], rate: -1}
`, "rate y burst"},
		{"app legacy inválida", `
app: "Shop"
`, `app "Shop"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(head + tt.yml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v\nquería algo con %q", err, tt.want)
			}
		})
	}
}

func TestDefaultAppSinHosts(t *testing.T) {
	c := mustParse(t, reloadBase+`
default_app: web
apps:
  - {name: web}
  - {name: api, hosts: ["api.local"]}
`)
	if c.EffectiveDefaultApp() != "web" {
		t.Fatal(c.EffectiveDefaultApp())
	}
}

func TestDiffAppsPorNombre(t *testing.T) {
	a := mustParse(t, appsBase)
	b := mustParse(t, appsBase)
	// Reordenar no es un cambio.
	b.Apps = []AppConfig{b.Apps[1], b.Apps[0]}
	if d := Diff(a, b); len(d) != 0 {
		t.Fatalf("reordenar dio cambios: %v", d)
	}
	// api cambia de modo, shop se va, blog llega.
	b.Apps = []AppConfig{b.Apps[0], {Name: "blog", Hosts: []string{"blog.local"}}}
	b.Apps[0].Modes.Default = policy.Enforce
	got := Diff(a, b)
	if paths := strings.Join(Paths(got), ","); paths != "apps[api].modes.default,apps[blog],apps[shop]" {
		t.Fatalf("paths = %s", paths)
	}
	if s := got[0].String(); s != `apps[api].modes.default: "monitor" -> "enforce"` {
		t.Errorf("texto = %s", s)
	}
	if got[2].New != "(eliminada)" || got[1].Old != "(no existe)" {
		t.Errorf("alta/baja: %v", got)
	}
	apply, restart := SplitChanges(got)
	if len(apply) != 3 || len(restart) != 0 {
		t.Errorf("apps debe ser recargable: apply=%v restart=%v", apply, restart)
	}
}
