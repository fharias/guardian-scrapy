package fingerprint

import "testing"

// Estos JA4 son valores de ejemplo para la prueba, no huellas reales de curl.
const (
	toolJA4  = "t13d1812h2_aaaaaaaaaaaa_bbbbbbbbbbbb"
	otherJA4 = "t13d1517h2_8daaf6152771_cccccccccccc"
	chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

func TestJA4PolicyMismatch(t *testing.T) {
	p, err := NewJA4Policy(JA4Config{Tools: []KnownJA4{{Name: "curl", JA4: toolJA4}}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		ua, ja4  string
		wantName string
		want     bool
	}{
		{"UA de Chrome con JA4 de curl", chromeUA, toolJA4, "curl", true},
		{"UA de Chrome con otro JA4", chromeUA, otherJA4, "", false},
		{"UA de curl con JA4 de curl: ya lo cubre ua_tool", "curl/8.7.1", toolJA4, "", false},
		{"sin JA4 (HTTP plano)", chromeUA, "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			name, got := p.Mismatch(c.ua, c.ja4)
			if got != c.want || name != c.wantName {
				t.Fatalf("got (%q, %v), want (%q, %v)", name, got, c.wantName, c.want)
			}
		})
	}
}

func TestJA4PolicyNilIsSilent(t *testing.T) {
	var p *JA4Policy
	if _, bad := p.Mismatch(chromeUA, toolJA4); bad {
		t.Fatal("una política nil no debe acusar")
	}
}

func TestNewJA4PolicyRejectsBadConfig(t *testing.T) {
	cases := []struct {
		name  string
		tools []KnownJA4
	}{
		{"formato", []KnownJA4{{Name: "curl", JA4: "t13d1812h2"}}},
		{"sin nombre", []KnownJA4{{JA4: toolJA4}}},
		{"repetido", []KnownJA4{{Name: "a", JA4: toolJA4}, {Name: "b", JA4: toolJA4}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NewJA4Policy(JA4Config{Tools: c.tools}); err == nil {
				t.Fatal("esperaba error")
			}
		})
	}
}
func TestValidJA4(t *testing.T) {
	cases := []struct {
		name, in string
		want     bool
	}{
		{"el de Chrome", "t13d1517h2_8daaf6152771_cb7bf5808d99", true},
		{"c todo ceros (lista vacía)", "t13d1517h2_8daaf6152771_000000000000", true},
		{"muy corto", "t13d1517h2", false},
		{"largo de b incorrecto", "t13d1517h2_8daaf615277_cb7bf5808d99", false},
		{"b con caracteres no hex", "t13d1517h2_8daaf615277z_cb7bf5808d99", false},
		{"mayúsculas", "T13D1517H2_8DAAF6152771_CB7BF5808D99", false},
		{"espacio", "t13d1517h2_8daaf6152771_cb7bf580 d99", false},
		{"vacío", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ValidJA4(c.in); got != c.want {
				t.Fatalf("ValidJA4(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestJA4ConfigValidate(t *testing.T) {
	cases := []struct {
		source  string
		wantErr bool
	}{
		{"", false}, {"tls", false}, {"cloudfront", false}, {"none", false},
		{"CloudFront", true}, {"akamai", true},
	}
	for _, c := range cases {
		t.Run(c.source, func(t *testing.T) {
			err := JA4Config{Source: c.source}.Validate()
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}
