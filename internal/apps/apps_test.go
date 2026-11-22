package apps

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidName(t *testing.T) {
	for name, want := range map[string]bool{
		"shop": true, "api": true, "api-v2": true, "a1": true, "0x": true,
		strings.Repeat("a", MaxNameLen):   true,
		"":                                false,
		strings.Repeat("a", MaxNameLen+1): false,
		"Shop":                            false, // mayúsculas: dos series para lo mismo
		"-api":                            false,
		"a:b":                             false, // rompe gd:<app>:
		"{x}":                             false, // cambia el hash tag
		"a/b":                             false, // rompe /v1/apps/{app}
		"a_b":                             false,
		"tienda-café":                     false,
		"a b":                             false,
	} {
		if got := ValidName(name); got != want {
			t.Errorf("ValidName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	for in, want := range map[string]string{
		"shop.example":          "shop.example",
		"shop.example:8080":     "shop.example",
		"SHOP.Example:8080":     "shop.example",
		"shop.example.":         "shop.example",
		"shop.example.:443":     "shop.example",
		"127.0.0.1:8080":        "127.0.0.1",
		"[2001:db8::1]:443":     "2001:db8::1",
		"[::1]":                 "::1",
		"[::1":                  "",
		"":                      "",
		"xn--tienda-caf-k7a.co": "xn--tienda-caf-k7a.co",
	} {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizePattern(t *testing.T) {
	tests := []struct {
		in       string
		host     string
		wildcard bool
		wantErr  string
	}{
		{in: "shop.example", host: "shop.example"},
		{in: "Shop.Example.", host: "shop.example"},
		{in: "*.shop.example", host: ".shop.example", wildcard: true},
		{in: "*.SHOP.example", host: ".shop.example", wildcard: true},
		{in: "tienda-café.example", host: "xn--tienda-caf-k7a.example"},
		{in: "*.café.example", host: ".xn--caf-dma.example", wildcard: true},
		{in: "127.0.0.1", host: "127.0.0.1"},
		{in: "[::1]", host: "::1"},
		{in: "localhost", host: "localhost"},
		{in: "", wantErr: "vacío"},
		{in: "http://shop.example", wantErr: "sin esquema"},
		{in: "shop.example/x", wantErr: "sin esquema"},
		{in: "shop.example:8080", wantErr: "sin puerto"},
		{in: "shop.*.example", wantErr: "comodín solo va al principio"},
		{in: "*", wantErr: "comodín solo va al principio"},
		{in: "*.local", wantErr: "dos etiquetas"},
		{in: "*.10.0.0.1", wantErr: "no aplica a una IP"},
		{in: "-shop.example", wantErr: "no es un nombre DNS válido"},
		{in: "shop_x.example", wantErr: "no es un nombre DNS válido"},
		{in: "*.[::1]", wantErr: "no aplica a una IP"},
		{in: "a..b", wantErr: "no es un nombre DNS válido"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			host, wild, err := NormalizePattern(tt.in)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, quería algo con %q (host=%q)", err, tt.wantErr, host)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if host != tt.host || wild != tt.wildcard {
				t.Fatalf("= (%q, %v), want (%q, %v)", host, wild, tt.host, tt.wildcard)
			}
		})
	}
}

func handlerNamed(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, name) })
}

func newTestRouter(t *testing.T, def string) *Router {
	t.Helper()
	rt, err := NewRouter([]Route{
		{Name: "shop", Hosts: []string{"shop.example", "*.shop.example"}, Handler: handlerNamed("shop")},
		{Name: "admin", Hosts: []string{"admin.shop.example"}, Handler: handlerNamed("admin")},
		{Name: "eu", Hosts: []string{"*.eu.shop.example"}, Handler: handlerNamed("eu")},
		{Name: "api", Hosts: []string{"api.example", "127.0.0.1", "::1"}, Handler: handlerNamed("api")},
	}, def, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func TestRouterResolve(t *testing.T) {
	tests := []struct {
		host string
		def  string
		want string // "" = desconocido
	}{
		// exacto, con puerto, mayúsculas y punto final
		{host: "shop.example", want: "shop"},
		{host: "shop.example:8080", want: "shop"},
		{host: "SHOP.EXAMPLE:8080", want: "shop"},
		{host: "shop.example.", want: "shop"},
		{host: "api.example", want: "api"},
		{host: "127.0.0.1:8080", want: "api"},
		{host: "[::1]:8080", want: "api"},
		// comodín: cualquier profundidad, pero no el apex
		{host: "www.shop.example", want: "shop"},
		{host: "a.b.shop.example:443", want: "shop"},
		// exacto gana al comodín aunque el comodín también matchee
		{host: "admin.shop.example", want: "admin"},
		{host: "x.admin.shop.example", want: "shop"}, // el exacto no es comodín
		// el comodín más específico gana
		{host: "fr.eu.shop.example", want: "eu"},
		{host: "eu.shop.example", want: "shop"}, // apex de *.eu => cae en *.shop
		// desconocidos
		{host: "example", want: ""},
		{host: "evilshop.example", want: ""}, // sufijo sin punto: NO es subdominio
		{host: "shop.example.evil.com", want: ""},
		{host: "", want: ""},
		{host: strings.Repeat("a.", 130) + "shop.example", want: ""}, // > 253
		// con default, lo desconocido cae ahí; lo conocido no cambia
		{host: "otro.example", def: "api", want: "api"},
		{host: "", def: "api", want: "api"},
		{host: "www.shop.example", def: "api", want: "shop"},
	}
	for _, tt := range tests {
		t.Run(tt.host+"|"+tt.def, func(t *testing.T) {
			rt := newTestRouter(t, tt.def)
			got, ok := rt.Resolve(tt.host)
			if ok != (tt.want != "") || got != tt.want {
				t.Fatalf("Resolve(%q) = (%q, %v), want %q", tt.host, got, ok, tt.want)
			}
		})
	}
}

func TestRouterServeHTTP(t *testing.T) {
	rt := newTestRouter(t, "")
	for host, want := range map[string]string{"www.shop.example": "shop", "api.example:8080": "api"} {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		rt.ServeHTTP(rec, req)
		if rec.Code != 200 || rec.Body.String() != want {
			t.Errorf("%s -> %d %q, want 200 %q", host, rec.Code, rec.Body.String(), want)
		}
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "nadie.example"
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, req)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("host desconocido sin default -> %d, want 421", rec.Code)
	}
}

func TestNewRouterRechaza(t *testing.T) {
	h := handlerNamed("x")
	tests := map[string]struct {
		routes []Route
		def    string
	}{
		"host repetido entre apps": {routes: []Route{
			{Name: "a", Hosts: []string{"x.example"}, Handler: h},
			{Name: "b", Hosts: []string{"X.Example."}, Handler: h},
		}},
		"comodín repetido": {routes: []Route{
			{Name: "a", Hosts: []string{"*.x.example"}, Handler: h},
			{Name: "b", Hosts: []string{"*.X.example"}, Handler: h},
		}},
		"app repetida":          {routes: []Route{{Name: "a", Handler: h}, {Name: "a", Handler: h}}},
		"nombre inválido":       {routes: []Route{{Name: "A", Handler: h}}},
		"sin handler":           {routes: []Route{{Name: "a"}}},
		"default que no existe": {routes: []Route{{Name: "a", Handler: h}}, def: "b"},
		"sin apps":              {},
		"host inválido":         {routes: []Route{{Name: "a", Hosts: []string{"a:80"}, Handler: h}}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRouter(tt.routes, tt.def, nil); err == nil {
				t.Fatal("quería error")
			}
		})
	}
}

func TestRouterNamesHas(t *testing.T) {
	rt := newTestRouter(t, "shop")
	if got := strings.Join(rt.Names(), ","); got != "admin,api,eu,shop" {
		t.Fatalf("Names = %s", got)
	}
	if !rt.Has("eu") || rt.Has("nope") || rt.Default() != "shop" {
		t.Fatal("Has/Default")
	}
}

// El camino del request: NormalizeHost + Lookup. Con el Host en minúsculas
// (lo normal) no debe reservar memoria, ni para exactos ni para comodines.
func TestLookupCeroAllocations(t *testing.T) {
	rt := newTestRouter(t, "")
	for _, host := range []string{"shop.example", "shop.example:8080", "a.b.shop.example:443", "fr.eu.shop.example", "nadie.example", "[::1]:8080"} {
		allocs := testing.AllocsPerRun(1000, func() {
			_, _ = rt.table.Lookup(NormalizeHost(host))
		})
		if allocs != 0 {
			t.Errorf("%s: %.1f allocations por lookup, want 0", host, allocs)
		}
	}
}

func BenchmarkLookup(b *testing.B) {
	rt, _ := NewRouter([]Route{
		{Name: "shop", Hosts: []string{"shop.example", "*.shop.example"}, Handler: handlerNamed("shop")},
		{Name: "api", Hosts: []string{"api.example"}, Handler: handlerNamed("api")},
	}, "", nil)
	for _, host := range []string{"api.example:8080", "www.shop.example", "Www.Shop.Example"} {
		b.Run(host, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, _ = rt.table.Lookup(NormalizeHost(host))
			}
		})
	}
}
