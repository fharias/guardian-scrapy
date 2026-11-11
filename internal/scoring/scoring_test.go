package scoring

import (
	"slices"
	"testing"

	"github.com/fharias/guardian-scrapy/internal/verdict"
)

func ptr(f float64) *float64 { return &f }

func testConfig() Config {
	return Config{
		Weights: Weights{
			UATool: 90, HeadersIncomplete: 30, Honeypot: 50,
			RateExceeded: 100, LowBrowserRatio: 15,
		},
		Thresholds:      Thresholds{Challenge: 40, Block: 85},
		BrowserRatioMin: 0.3,
	}
}

func TestEvaluate(t *testing.T) {
	s, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		sig      verdict.Signals
		score    int
		reasons  []string
		decision verdict.Decision
	}{
		{"humano limpio", verdict.Signals{}, 0, nil, verdict.Allow},
		{"sin dato de ratio no suma", verdict.Signals{BrowserRatio: nil}, 0, nil, verdict.Allow},
		{"ratio 0.0 sí suma", verdict.Signals{BrowserRatio: ptr(0)}, 15, []string{"ratio_navegador_bajo"}, verdict.Allow},
		{"ratio alto no suma", verdict.Signals{BrowserRatio: ptr(0.8)}, 0, nil, verdict.Allow},
		{"honeypot solo desafía", verdict.Signals{Honeypot: true}, 50, []string{"honeypot"}, verdict.Challenge},
		{"curl bloquea", verdict.Signals{UATool: true}, 90, []string{"ua_herramienta"}, verdict.Block},
		{"señales débiles sumadas bloquean", verdict.Signals{
			HeadersIncomplete: true, Honeypot: true, BrowserRatio: ptr(0.1),
		}, 95, []string{"headers_incompletos", "honeypot", "ratio_navegador_bajo"}, verdict.Block},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			score, reasons, d := s.Evaluate(tc.sig)
			if score != tc.score || d != tc.decision || !slices.Equal(reasons, tc.reasons) {
				t.Fatalf("got (%d, %v, %s), want (%d, %v, %s)",
					score, reasons, d, tc.score, tc.reasons, tc.decision)
			}
		})
	}
}

func TestNewRejectsBadThresholds(t *testing.T) {
	cfg := testConfig()
	cfg.Thresholds = Thresholds{Challenge: 90, Block: 85}
	if _, err := New(cfg); err == nil {
		t.Fatal("esperaba error con challenge >= block")
	}
}
