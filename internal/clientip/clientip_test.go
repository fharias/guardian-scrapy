package clientip

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	r, err := New([]string{"10.0.0.0/8", "::1/128", "127.0.0.0/8"}, "X-Forwarded-For")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, remote, xff, want string
	}{
		{"sin proxy, sin XFF", "203.0.113.7:5000", "", "203.0.113.7"},
		{"cliente directo falsifica XFF", "203.0.113.7:5000", "1.2.3.4", "203.0.113.7"},
		{"detrás de proxy confiable", "10.0.1.5:5000", "198.51.100.9", "198.51.100.9"},
		{"hop falso a la izquierda", "10.0.1.5:5000", "6.6.6.6, 198.51.100.9", "198.51.100.9"},
		{"dos proxies confiables", "10.0.1.5:5000", "198.51.100.9, 10.0.2.8", "198.51.100.9"},
		{"XFF basura", "10.0.1.5:5000", "no-soy-ip", "10.0.1.5"},
		{"IPv6 localhost", "[::1]:5000", "", "::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tc.remote
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := r.ClientIP(req).String(); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}
