package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fharias/guardian-scrapy/internal/clientip"
	"github.com/fharias/guardian-scrapy/internal/fingerprint"
	"github.com/fharias/guardian-scrapy/internal/ja4source"
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
			}), Init, JA4(ja4source.TLS{}, slog.New(slog.DiscardHandler)), JA4Mismatch(policy))

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
func TestJA4SourceMiddleware(t *testing.T) {
	const toolJA4 = "t13d1812h2_aaaaaaaaaaaa_bbbbbbbbbbbb" // el JA4 "de herramienta" de la política
	const chromeUA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0.0.0 Safari/537.36"
	policy, err := fingerprint.NewJA4Policy(fingerprint.JA4Config{
		Tools: []fingerprint.KnownJA4{{Name: "curl", JA4: toolJA4}},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := clientip.New([]string{"10.0.0.0/8"}, "X-Forwarded-For")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name           string
		source         string
		remote         string
		header         string
		wantJA4        string
		wantSource     string
		wantMismatch   bool
		wantLogRejects bool
	}{
		{"CloudFront real con JA4 de herramienta", "cloudfront", "10.0.1.5:443", toolJA4, toolJA4, "cloudfront", true, false},
		{"header falso desde IP pública se ignora", "cloudfront", "203.0.113.7:5000", toolJA4, "", "", false, true},
		{"modo tls ignora el header", "tls", "10.0.1.5:443", toolJA4, "", "", false, false},
		{"modo none apaga la señal", "none", "10.0.1.5:443", toolJA4, "", "none", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src, err := ja4source.New(c.source, res.PeerIsTrusted)
			if err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&logs, nil))

			var got *verdict.Verdict
			var headerUpstream string
			h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = verdict.From(r.Context())
				headerUpstream = r.Header.Get(ja4source.CloudFrontHeader)
			}), Init, JA4(src, log), JA4Mismatch(policy))

			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = c.remote
			req.Header.Set("User-Agent", chromeUA)
			req.Header.Set(ja4source.CloudFrontHeader, c.header)
			h.ServeHTTP(httptest.NewRecorder(), req)

			if got == nil {
				t.Fatal("el handler final no corrió")
			}
			if got.JA4 != c.wantJA4 || got.JA4Source != c.wantSource {
				t.Errorf("JA4=%q source=%q; want %q %q", got.JA4, got.JA4Source, c.wantJA4, c.wantSource)
			}
			if got.Signals.JA4Mismatch != c.wantMismatch {
				t.Errorf("JA4Mismatch = %v, want %v", got.Signals.JA4Mismatch, c.wantMismatch)
			}
			if headerUpstream != "" {
				t.Errorf("el header debe borrarse antes del upstream, llegó %q", headerUpstream)
			}
			if rejected := strings.Contains(logs.String(), "ja4_header_rechazado"); rejected != c.wantLogRejects {
				t.Errorf("log de rechazo = %v, want %v; logs: %s", rejected, c.wantLogRejects, logs.String())
			}
		})
	}
}
