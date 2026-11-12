package policy

import "testing"

func TestFor(t *testing.T) {
	m, err := New(Config{
		Default: Enforce,
		Routes: []RouteMode{
			{Prefix: "/api", Mode: Monitor},
			{Prefix: "/api/checkout/", Mode: Enforce},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path string
		want Mode
	}{
		{"/", Enforce},
		{"/api", Monitor},
		{"/api/precios", Monitor},
		{"/api/checkout", Enforce},
		{"/api/checkout/pagar", Enforce},
		{"/apiv2", Enforce},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			if got := m.For(c.path); got != c.want {
				t.Errorf("For(%q) = %q, want %q", c.path, got, c.want)
			}
		})
	}
}

func TestNewRejectsMissingDefault(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("esperaba error sin modes.default")
	}
	if _, err := New(Config{Default: "shadow"}); err == nil {
		t.Fatal("esperaba error con modo inválido")
	}
}
