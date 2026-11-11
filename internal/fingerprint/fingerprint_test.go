package fingerprint

import (
	"net/http"
	"testing"
)

func chrome() http.Header {
	h := http.Header{}
	h.Set("User-Agent", "Mozilla/5.0 (Macintosh) Chrome/131.0")
	h.Set("Accept", "text/html,application/xhtml+xml")
	h.Set("Accept-Language", "es-CO,es;q=0.9")
	h.Set("Accept-Encoding", "gzip, deflate, br")
	return h
}

func TestFingerprintCompute(t *testing.T) {
	base := Compute(chrome()).Hash

	cases := []struct {
		name     string
		mutate   func(http.Header)
		sameHash bool
		missing  int
	}{
		{"mismos headers", func(h http.Header) {}, true, 0},
		{"mayúsculas y espacios extra", func(h http.Header) {
			h.Set("Accept-Language", "  ES-co,es;q=0.9 ")
		}, true, 0},
		{"cookie no cambia la huella", func(h http.Header) { h.Set("Cookie", "sesion=abc") }, true, 0},
		{"otro idioma", func(h http.Header) { h.Set("Accept-Language", "en-US") }, false, 0},
		{"header extra", func(h http.Header) { h.Set("X-Scraper", "1") }, false, 0},
		{"UA de navegador sin Accept-Language", func(h http.Header) { h.Del("Accept-Language") }, false, 1},
		{"curl", func(h http.Header) {
			for k := range h {
				h.Del(k)
			}
			h.Set("User-Agent", "curl/8.7.1")
			h.Set("Accept", "*/*")
		}, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := chrome()
			tc.mutate(h)
			r := Compute(h)
			if (r.Hash == base) != tc.sameHash {
				t.Fatalf("hash %s vs base %s, sameHash esperado=%v", r.Hash, base, tc.sameHash)
			}
			if len(r.Missing) != tc.missing {
				t.Fatalf("missing=%v, esperaba %d", r.Missing, tc.missing)
			}
			if len(r.Hash) != 16 {
				t.Fatalf("hash de largo %d", len(r.Hash))
			}
		})
	}
}
