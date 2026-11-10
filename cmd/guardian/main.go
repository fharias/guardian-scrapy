package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/fharias/guardian-scrapy/internal/config"
)

func main() {
	path := flag.String("config", "guardian-config.yml", "ruta del archivo de configuración")
	flag.Parse()

	cfg, err := config.Load(*path)
	if err != nil {
		log.Fatal(err)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(cfg.UpstreamURL)
			if cfg.PreserveHost {
				pr.Out.Host = pr.In.Host
			}
			pr.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("error hacia upstream: %v", err)
			http.Error(w, "upstream no disponible", http.StatusBadGateway)
		},
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           proxy,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
	}

	log.Printf("guardian escuchando en %s -> %s", srv.Addr, cfg.UpstreamURL)
	log.Fatal(srv.ListenAndServe())
}
