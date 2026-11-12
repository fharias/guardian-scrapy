package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fharias/guardian-scrapy/internal/fingerprint"
	"github.com/fharias/guardian-scrapy/internal/tlshello"
	"github.com/fharias/guardian-scrapy/internal/verdict"
)

func TestJA4MismatchMiddleware(t *testing.T) {
	const toolJA4 = "t13d1812h2_aaaaaaaaaaaa_bbbbbbbbbbbb"
	const chromeUA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0.0.0 Safari/537.36"
	policy, err := fingerprint.NewJA4Policy(fingerprint.JA4Config{
		Tools: []fingerprint.KnownJA4{{Name: "curl", JA4: toolJA4}},
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name         string
		ua           string
		hello        *tlshello.Hello // nil = HTTP plano
		wantMismatch bool
		wantJA4      string
	}{
		{"Chrome con JA4 de curl", chromeUA, &tlshello.Hello{JA4: toolJA4}, true, toolJA4},
		{"Chrome con JA4 distinto", chromeUA, &tlshello.Hello{JA4: "t13d1517h2_8daaf6152771_cccccccccccc"}, false, "t13d1517h2_8daaf6152771_cccccccccccc"},
		{"HTTP plano no opina", chromeUA, nil, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got *verdict.Verdict
			h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = verdict.From(r.Context())
			}), Init, JA4Mismatch(policy))

			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("User-Agent", c.ua)
			if c.hello != nil {
				req = req.WithContext(tlshello.WithHello(req.Context(), c.hello))
			}
			h.ServeHTTP(httptest.NewRecorder(), req)

			if got == nil {
				t.Fatal("el handler final no corrió")
			}
			if got.Signals.JA4Mismatch != c.wantMismatch {
				t.Errorf("JA4Mismatch = %v, want %v", got.Signals.JA4Mismatch, c.wantMismatch)
			}
			if got.JA4 != c.wantJA4 {
				t.Errorf("v.JA4 = %q, want %q", got.JA4, c.wantJA4)
			}
		})
	}
}
