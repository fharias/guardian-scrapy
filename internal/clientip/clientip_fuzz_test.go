package clientip

import (
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func FuzzClientIP(f *testing.F) {
	r, err := New([]string{"10.0.0.0/8", "::1/128"}, "X-Forwarded-For")
	if err != nil {
		f.Fatal(err)
	}

	f.Add("10.0.1.5:5000", "198.51.100.9, 10.0.2.8")
	f.Add("10.0.1.5:5000", "::ffff:1.2.3.4")
	f.Add("[::1]:5000", "fe80::1%eth0")
	f.Add("203.0.113.7:5000", "1.2.3.4")
	f.Add("no-es-una-ip", "")

	f.Fuzz(func(t *testing.T, remote, xff string) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = remote
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		got := r.ClientIP(req)

		// RemoteAddr roto: no hay IP, y quien llama debe tratarlo como tal.
		ap, err := netip.ParseAddrPort(remote)
		if err != nil {
			if got.IsValid() {
				t.Fatalf("RemoteAddr %q no parsea, pero ClientIP = %v", remote, got)
			}
			return
		}
		peer := ap.Addr().Unmap()

		// Un cliente directo nunca puede spoofear su IP con el header.
		if !r.PeerIsTrusted(req) && got != peer {
			t.Fatalf("peer no confiable %v, pero ClientIP = %v (xff=%q)", peer, got, xff)
		}

		// Guardian jamás inventa una IP: o es el peer o es uno de los hops.
		if got == peer {
			return
		}
		for _, h := range strings.Split(xff, ",") {
			if a, err := netip.ParseAddr(strings.TrimSpace(h)); err == nil && a.Unmap() == got {
				return
			}
		}
		t.Fatalf("ClientIP = %v no es el peer (%v) ni un hop de %q", got, peer, xff)
	})
}
