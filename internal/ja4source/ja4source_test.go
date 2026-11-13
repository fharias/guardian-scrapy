package ja4source

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fharias/guardian-scrapy/internal/clientip"
	"github.com/fharias/guardian-scrapy/internal/tlshello"
)

const (
	cfJA4  = "t13d1517h2_8daaf6152771_cb7bf5808d99" // el de Chrome que mediste en el paso 14
	tlsJA4 = "t13d4907h2_0d8feac7bc37_7395dae3b2f3" // el de tu curl
)

func newRequest(remote string, header ...string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	for _, v := range header {
		r.Header.Add(CloudFrontHeader, v)
	}
	return r
}

func withTLS(r *http.Request, ja4 string) *http.Request {
	return r.WithContext(tlshello.WithHello(r.Context(), &tlshello.Hello{JA4: ja4}))
}

func TestCloudFrontSource(t *testing.T) {
	res, err := clientip.New([]string{"10.0.0.0/8"}, "X-Forwarded-For")
	if err != nil {
		t.Fatal(err)
	}
	src, err := New("cloudfront", res.PeerIsTrusted)
	if err != nil {
		t.Fatal(err)
	}

	long := cfJA4[:10] + "_" + strings.Repeat("a", 100)

	cases := []struct {
		name         string
		req          *http.Request
		want         string
		wantSource   string
		wantRejected string
	}{
		{"peer confiable con header válido", newRequest("10.0.1.5:443", cfJA4), cfJA4, "cloudfront", ""},
		{"header falso desde IP pública", newRequest("203.0.113.7:5000", cfJA4), "", "", RejectedUntrusted},
		{"header falso desde IP pública, pero con TLS propio", withTLS(newRequest("203.0.113.7:5000", cfJA4), tlsJA4), tlsJA4, "tls", RejectedUntrusted},
		{"peer confiable sin header cae a tls", withTLS(newRequest("10.0.1.5:443"), tlsJA4), tlsJA4, "tls", ""},
		{"peer confiable sin header y sin TLS", newRequest("10.0.1.5:443"), "", "", ""},
		{"formato inválido", newRequest("10.0.1.5:443", "no-soy-un-ja4"), "", "", RejectedBadFormat},
		{"mayúsculas no son JA4", newRequest("10.0.1.5:443", strings.ToUpper(cfJA4)), "", "", RejectedBadFormat},
		{"header repetido", newRequest("10.0.1.5:443", cfJA4, cfJA4), "", "", RejectedMultiple},
		{"inválido pero con TLS propio cae a tls", withTLS(newRequest("10.0.1.5:443", "xx"), tlsJA4), tlsJA4, "tls", RejectedBadFormat},
		{"header larguísimo se rechaza", newRequest("10.0.1.5:443", long), "", "", RejectedBadFormat},
		{"RemoteAddr basura no es confiable", newRequest("basura", cfJA4), "", "", RejectedUntrusted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := src.JA4(c.req)
			if got.JA4 != c.want || got.Source != c.wantSource || got.Rejected != c.wantRejected {
				t.Fatalf("got JA4=%q source=%q rejected=%q; want %q %q %q",
					got.JA4, got.Source, got.Rejected, c.want, c.wantSource, c.wantRejected)
			}
			if len(got.Header) > 70 {
				t.Fatalf("el header de log debe recortarse, mide %d", len(got.Header))
			}
		})
	}
}

func TestTLSSourceIgnoresHeader(t *testing.T) {
	src, _ := New("tls", nil)
	got := src.JA4(withTLS(newRequest("10.0.1.5:443", cfJA4), tlsJA4))
	if got.JA4 != tlsJA4 || got.Source != "tls" {
		t.Fatalf("tls debe usar el ClientHello, got %+v", got)
	}
	if got := src.JA4(newRequest("10.0.1.5:443", cfJA4)); got.JA4 != "" {
		t.Fatalf("sin TLS y con header, tls no debe inventar JA4: %+v", got)
	}
}

func TestNoneSource(t *testing.T) {
	src, _ := New("none", nil)
	got := src.JA4(withTLS(newRequest("10.0.1.5:443", cfJA4), tlsJA4))
	if got.JA4 != "" || got.Source != "none" {
		t.Fatalf("none no debe devolver JA4, got %+v", got)
	}
}

func TestNew(t *testing.T) {
	trusted := func(*http.Request) bool { return true }
	cases := []struct {
		name, source string
		trusted      func(*http.Request) bool
		wantErr      bool
	}{
		{"vacío es tls", "", nil, false},
		{"tls", "tls", nil, false},
		{"none", "none", nil, false},
		{"cloudfront con peers", "cloudfront", trusted, false},
		{"cloudfront sin peers", "cloudfront", nil, true},
		{"desconocido", "akamai", trusted, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(c.source, c.trusted)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}
