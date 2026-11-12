package goodbot

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type Bot struct {
	Name       string   `yaml:"name"`
	UAContains string   `yaml:"ua_contains"`
	Domains    []string `yaml:"domains"`
}

type cacheKey struct {
	ip  netip.Addr
	bot string
}

type entry struct {
	ok  bool
	exp time.Time
}

type Verifier struct {
	bots  []Bot
	res   Resolver
	ttl   time.Duration
	now   func() time.Time
	mu    sync.Mutex
	cache map[cacheKey]entry
}

func NewVerifier(bots []Bot, res Resolver, ttl time.Duration) *Verifier {
	return &Verifier{
		bots:  bots,
		res:   res,
		ttl:   ttl,
		now:   time.Now,
		cache: make(map[cacheKey]entry),
	}
}

func (v *Verifier) Claimed(ua string) (Bot, bool) {
	for _, b := range v.bots {
		if strings.Contains(ua, b.UAContains) {
			return b, true
		}
	}
	return Bot{}, false
}

func (v *Verifier) Verify(ctx context.Context, ua string, ip netip.Addr) (claimed, verified bool) {
	bot, ok := v.Claimed(ua)
	if !ok {
		return false, false
	}
	ip = ip.Unmap()
	key := cacheKey{ip: ip, bot: bot.Name}
	v.mu.Lock()
	e, hit := v.cache[key]
	v.mu.Unlock()
	if hit && v.now().Before(e.exp) {
		return true, e.ok
	}
	ok, err := v.lookup(ctx, bot, ip)
	if err != nil {
		return true, false
	}
	v.mu.Lock()
	v.cache[key] = entry{ok: ok, exp: v.now().Add(v.ttl)}
	v.mu.Unlock()
	return true, ok
}
func (v *Verifier) lookup(ctx context.Context, bot Bot, ip netip.Addr) (bool, error) {
	names, err := v.res.LookupAddr(ctx, ip.String())
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, nil
		}
		return false, err
	}
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		if !matchesDomain(name, bot.Domains) {
			continue
		}
		addrs, err := v.res.LookupIPAddr(ctx, name)
		if err != nil {
			return false, err
		}
		for _, a := range addrs {
			if got, ok := netip.AddrFromSlice(a.IP); ok && got.Unmap() == ip {
				return true, nil
			}
		}
	}
	return false, nil
}

func matchesDomain(name string, domains []string) bool {
	for _, d := range domains {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}
