package main

import (
	"bufio"
	"bytes"
	"net"
	"testing"

	"github.com/pires/go-proxyproto"
)

func FuzzProxyProtoRead(f *testing.F) {
	src := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51000}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.10"), Port: 8080}
	v2, err := proxyproto.HeaderProxyFromAddrs(2, src, dst).Format()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(v2)
	f.Add([]byte("PROXY TCP4 203.0.113.7 10.0.0.10 51000 8080\r\n"))
	f.Add([]byte("PROXY UNKNOWN\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))

	f.Fuzz(func(t *testing.T, in []byte) {
		// Nunca panic con bytes arbitrarios de Internet.
		hdr, err := proxyproto.Read(bufio.NewReader(bytes.NewReader(in)))
		if err != nil {
			return
		}
		out, err := hdr.Format()
		if err != nil {
			return // headers que se leen pero no se re-serializan: válido
		}
		// Roundtrip: lo que escribimos se vuelve a leer igual.
		again, err := proxyproto.Read(bufio.NewReader(bytes.NewReader(out)))
		if err != nil {
			t.Fatalf("Format produjo bytes que Read rechaza: %v\nin=%x\nout=%x", err, in, out)
		}
		if !hdr.EqualsTo(again) {
			t.Fatalf("roundtrip distinto:\n first=%+v\nsecond=%+v", hdr, again)
		}
	})
}
