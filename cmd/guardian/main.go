package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

func main() {
	upstream, err := url.Parse("http://localhost:9000")
	if err != nil {
		log.Fatalf("URL de upstream inválida: %v", err)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("error hacia upstream: %v", err)
			http.Error(w, "upstream no disponible", http.StatusBadGateway)
		},
	}

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           proxy,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("guardian escuchando en %s -> %s", srv.Addr, upstream)
	log.Fatal(srv.ListenAndServe())
}
