package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fharias/guardian-scrapy/internal/scoring"
)

func TestEnforceBlocksCurl(t *testing.T) {
	called := false
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	scorer, err := scoring.New(scoring.Config{
		Weights: scoring.Weights{
			UATool:            90,
			HeadersIncomplete: 30,
			Honeypot:          50,
			RateExceeded:      100,
			LowBrowserRatio:   15,
		},
		Thresholds: scoring.Thresholds{
			Challenge: 40,
			Block:     85,
		},
		BrowserRatioMin: 0.3,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := Chain(final,
		Init,
		SuspiciousUA(),
		Honeypot("/admin-oculto", "/robots.txt", "/favicon.ico"),
		Score(scorer),
		Enforce(),
	)
	req := httptest.NewRequest(http.MethodGet, "/admin-oculto", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("código = %d, quiero %d", rec.Code, http.StatusForbidden)
	}
	if called {
		t.Error("el handler final se ejecutó, y Enforce debió cortar la cadena")
	}
}
