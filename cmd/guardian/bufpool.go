package main

import (
	"net/http/httputil"
	"sync"
)

// proxyBufSize es el mismo tamaño que httputil.ReverseProxy usa cuando no
// tiene BufferPool: make([]byte, 32*1024) en CADA respuesta.
const proxyBufSize = 32 << 10

// bufPool implementa httputil.BufferPool con un sync.Pool.
type bufPool struct{ p sync.Pool }

func newBufPool() *bufPool {
	return &bufPool{p: sync.Pool{New: func() any { return make([]byte, proxyBufSize) }}}
}

// Get devuelve un buffer de len == proxyBufSize. ReverseProxy usa len(buf):
// si fuera 0 crearía uno propio y el pool no serviría de nada.
func (bp *bufPool) Get() []byte { return bp.p.Get().([]byte) }

// Put devuelve el buffer al pool. Descarta los que no son del tamaño esperado
// para que el pool nunca entregue un buffer corto.
//
// Tradeoff (staticcheck SA6002): sync.Pool guarda `any`, y meter un []byte en
// un `any` reserva el encabezado del slice (24 bytes) en cada Put. Lo ideal
// sería un *[]byte, pero la interfaz httputil.BufferPool fija Put([]byte): no
// recibimos el puntero, y crear uno nuevo costaría la misma alloc. Son 24 B
// contra los 32 KB que ahorramos por respuesta; lo aceptamos a propósito.
func (bp *bufPool) Put(b []byte) {
	if cap(b) != proxyBufSize {
		return
	}
	bp.p.Put(b[:proxyBufSize]) //nolint:staticcheck // SA6002: ver comentario arriba
}

// proxyBufferPool es UNO para todo el proceso. newUpstreamProxy crea un
// ReverseProxy nuevo en cada build (cada recarga), pero el pool vive aquí y
// sobrevive a todas, igual que http.DefaultTransport.
var proxyBufferPool httputil.BufferPool = newBufPool()
