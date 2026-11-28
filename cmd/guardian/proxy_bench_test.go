package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

// discardWriter es un http.ResponseWriter que tira el body. Con
// httptest.ResponseRecorder el benchmark mediría también el crecimiento de su
// bytes.Buffer, y eso no es lo que queremos comparar.
type discardWriter struct {
	h      http.Header
	status int
	n      int
}

func (d *discardWriter) Header() http.Header         { return d.h }
func (d *discardWriter) WriteHeader(code int)        { d.status = code }
func (d *discardWriter) Write(p []byte) (int, error) { d.n += len(p); return len(p), nil }
func (d *discardWriter) reset() {
	clear(d.h)
	d.status, d.n = 0, 0
}

// BenchmarkUpstreamProxy mide una vuelta completa por el ReverseProxy real de
// newUpstreamProxy: Rewrite, Transport (keep-alive hacia un httptest.Server) y
// copyResponse. Los allocs/op incluyen al servidor del upstream, que vive en el
// mismo proceso; lo que importa es la DIFERENCIA entre antes y después.
//
//	go test ./cmd/guardian -run '^$' -bench BenchmarkUpstreamProxy -benchmem -count=10
func BenchmarkUpstreamProxy(b *testing.B) {
	for _, size := range []int{256, 16 << 10, 64 << 10} {
		b.Run(fmt.Sprintf("body=%dB", size), func(b *testing.B) {
			body := bytes.Repeat([]byte("x"), size)
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", strconv.Itoa(size))
				w.Write(body)
			}))
			defer up.Close()
			target, err := url.Parse(up.URL)
			if err != nil {
				b.Fatal(err)
			}
			proxy := newUpstreamProxy(target, false)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := &discardWriter{h: http.Header{}}

			// Una vuelta fuera del loop: valida que el benchmark mide lo correcto
			// y calienta la conexión keep-alive.
			proxy.ServeHTTP(w, req)
			if w.status != http.StatusOK || w.n != size {
				b.Fatalf("status=%d bytes=%d, want 200 y %d", w.status, w.n, size)
			}

			b.ReportAllocs()
			for b.Loop() {
				w.reset()
				proxy.ServeHTTP(w, req)
			}
		})
	}
}
