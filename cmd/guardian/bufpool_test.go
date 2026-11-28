package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestBufPoolEntregaBuffersDe32KB(t *testing.T) {
	bp := newBufPool()
	for i := 0; i < 5; i++ {
		b := bp.Get()
		if len(b) != 32<<10 {
			t.Fatalf("len(Get()) = %d, want %d", len(b), 32<<10)
		}
		bp.Put(b[:10]) // devuelto "acortado": el pool lo reextiende
	}
	// Un buffer de otro tamaño se descarta; nunca sale en un Get.
	bp.Put(make([]byte, 100))
	for i := 0; i < 50; i++ {
		if got := len(bp.Get()); got != 32<<10 {
			t.Fatalf("Get devolvió un buffer de %d bytes", got)
		}
	}
}

func TestUpstreamProxyUsaElPoolYCopiaElBody(t *testing.T) {
	for _, size := range []int{0, 1, 1000, 32 << 10, 32<<10 + 1, 200 << 10} {
		want := bytes.Repeat([]byte("abc"), size/3+1)[:size]
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(want)
		}))
		target, _ := url.Parse(up.URL)
		proxy := newUpstreamProxy(target, false)
		if proxy.BufferPool == nil {
			up.Close()
			t.Fatal("newUpstreamProxy debe fijar BufferPool")
		}
		front := httptest.NewServer(proxy)
		// Dos vueltas: la segunda reutiliza el buffer que devolvió la primera.
		for round := 0; round < 2; round++ {
			resp, err := http.Get(front.URL)
			if err != nil {
				t.Fatalf("size=%d: %v", size, err)
			}
			got, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK || !bytes.Equal(got, want) {
				t.Fatalf("size=%d ronda %d: status=%d, body de %d bytes distinto al original (%d)",
					size, round, resp.StatusCode, len(got), len(want))
			}
		}
		front.Close()
		up.Close()
	}
}

// El Get/Put del pool no debe reservar un buffer de 32 KB por vuelta. Quedan
// los 24 B del encabezado del slice (ver el comentario en Put), de ahí el <= 1.
func TestBufPoolNoReservaBuffersNuevos(t *testing.T) {
	bp := newBufPool()
	allocs := testing.AllocsPerRun(1000, func() {
		bp.Put(bp.Get())
	})
	if allocs > 1 {
		t.Fatalf("allocs por Get+Put = %v, want <= 1", allocs)
	}
}
