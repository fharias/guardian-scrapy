package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fharias/guardian-scrapy/internal/goodbot"
	"github.com/fharias/guardian-scrapy/internal/rules"
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

	engine, err := rules.New(rules.Config{
		Honeypots: []string{"/admin-oculto"},
		DenyCIDRs: []string{"198.51.100.0/24"},
		Routes: []rules.Route{
			{
				Prefix:     "/interno",
				AllowCIDRs: []string{"10.0.0.0/8", "127.0.0.1/32", "::1/128"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	bots := goodbot.NewVerifier([]goodbot.Bot{
		{
			Name:       "googlebot",
			UAContains: "Googlebot",
			Domains:    []string{"googlebot.com", "google.com"},
		},
	}, nil, time.Hour)
	h := Chain(final,
		Init,
		SuspiciousUA(),
		Rules(engine, bots, 1*time.Second),
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
