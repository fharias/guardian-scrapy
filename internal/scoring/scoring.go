package scoring

import (
	"errors"
	"fmt"

	"github.com/fharias/guardian-scrapy/internal/verdict"
)

type Weights struct {
	UATool            int `yaml:"ua_tool"`
	HeadersIncomplete int `yaml:"headers_incomplete"`
	Honeypot          int `yaml:"honeypot"`
	RateExceeded      int `yaml:"rate_exceeded"`
	LowBrowserRatio   int `yaml:"low_browser_ratio"`
	FakeBot           int `yaml:"fake_bot"`
}

type Thresholds struct {
	Challenge int `yaml:"challenge"`
	Block     int `yaml:"block"`
}

type Config struct {
	Weights         Weights    `yaml:"weights"`
	Thresholds      Thresholds `yaml:"thresholds"`
	BrowserRatioMin float64    `yaml:"browser_ratio_min"`
}

func (c Config) Validate() error {
	var errs []error
	if c.Thresholds.Challenge <= 0 || c.Thresholds.Block <= 0 {
		errs = append(errs, errors.New("scoring.thresholds deben ser > 0"))
	}
	if c.Thresholds.Challenge >= c.Thresholds.Block {
		errs = append(errs, fmt.Errorf("scoring.thresholds: challenge (%d) debe ser menor que block (%d)",
			c.Thresholds.Challenge, c.Thresholds.Block))
	}
	if c.BrowserRatioMin < 0 || c.BrowserRatioMin > 1 {
		errs = append(errs, errors.New("scoring.browser_ratio_min debe estar entre 0 y 1"))
	}
	return errors.Join(errs...)
}

type Scorer struct {
	cfg Config
}

func New(cfg Config) (*Scorer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Scorer{cfg: cfg}, nil
}

func (s *Scorer) Evaluate(sig verdict.Signals) (int, []string, verdict.Decision) {
	if sig.DenyReason != "" {
		return s.cfg.Thresholds.Block, []string{sig.DenyReason}, verdict.Block
	}
	if sig.VerifiedBot {
		return 0, []string{"bot_verificado"}, verdict.Allow
	}
	w := s.cfg.Weights
	score := 0
	var reasons []string
	add := func(on bool, points int, reason string) {
		if on && points > 0 {
			score += points
			reasons = append(reasons, reason)
		}
	}
	add(sig.FakeBot, w.FakeBot, "bot_falso")
	add(sig.UATool, w.UATool, "ua_herramienta")
	add(sig.HeadersIncomplete, w.HeadersIncomplete, "headers_incompletos")
	add(sig.Honeypot, w.Honeypot, "honeypot")
	add(sig.RateExceeded, w.RateExceeded, "rate_limit")
	add(sig.BrowserRatio != nil && *sig.BrowserRatio < s.cfg.BrowserRatioMin,
		w.LowBrowserRatio, "ratio_navegador_bajo")
	return score, reasons, s.decide(score)
}

func (s *Scorer) decide(score int) verdict.Decision {
	switch {
	case score >= s.cfg.Thresholds.Block:
		return verdict.Block
	case score >= s.cfg.Thresholds.Challenge:
		return verdict.Challenge
	default:
		return verdict.Allow
	}
}
