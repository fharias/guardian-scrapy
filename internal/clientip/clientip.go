package clientip

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

type Resolver struct {
	trusted []netip.Prefix
	header  string
}

func New(trustedCIDRs []string, header string) (*Resolver, error) {
	r := &Resolver{header: header}
	for _, c := range trustedCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("trusted_proxies: %q no es un CIDR válido: %w", c, err)
		}
		r.trusted = append(r.trusted, p.Masked())
	}
	return r, nil
}

func (r *Resolver) isTrusted(ip netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// PeerIsTrusted dice si quien abrió la conexión TCP (RemoteAddr, el vecino
// inmediato) está en la lista de proxies confiables. Otros paquetes lo usan
// para decidir si creen en un header que ese vecino agregó (paso 15).
func (r *Resolver) PeerIsTrusted(request *http.Request) bool {
	ap, err := netip.ParseAddrPort(request.RemoteAddr)
	if err != nil {
		return false
	}
	return r.isTrusted(ap.Addr().Unmap())
}

func (r *Resolver) ClientIP(request *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(request.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	peer := ap.Addr().Unmap()
	if r.header == "" || !r.isTrusted(peer) {
		return peer
	}
	hops := strings.Split(strings.Join(request.Header.Values(r.header), ","), ",")
	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		a = a.Unmap()
		client = a
		if !r.isTrusted(a) {
			break
		}
	}
	return client
}
