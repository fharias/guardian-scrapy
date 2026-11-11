package verdict

import (
	"context"
	"net/netip"
)

type Decision int

const (
	Allow Decision = iota
	Challenge
	Block
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Challenge:
		return "challenge"
	case Block:
		return "block"
	}
	return "unknown"
}

type Signals struct {
	UATool            bool
	HeadersIncomplete bool
	Honeypot          bool
	RateExceeded      bool
	BrowserRatio      *float64
}

type Verdict struct {
	ClientIP    netip.Addr
	Score       int
	Signals     Signals
	Reasons     []string
	Decision    Decision
	Fingerprint string
}

func (v *Verdict) Add(points int, reason string) {
	v.Score += points
	v.Reasons = append(v.Reasons, reason)
}

type ctxKey struct{}

func WithVerdict(ctx context.Context, v *Verdict) context.Context {
	return context.WithValue(ctx, ctxKey{}, v)
}
func From(ctx context.Context) *Verdict {
	v, _ := ctx.Value(ctxKey{}).(*Verdict)
	return v
}
