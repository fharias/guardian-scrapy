package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fharias/guardian-scrapy/internal/config"
	"github.com/fharias/guardian-scrapy/internal/middleware"
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

	var ready atomic.Bool
	ready.Store(true)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if ready.Load() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if ready.Load() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	handler := middleware.Chain(proxy,
		middleware.Init,
		middleware.Logger(logger),
		middleware.SuspiciousUA(90),
		middleware.Honeypot(50, cfg.HoneypotPaths...),
		middleware.Enforce(85),
	)
	mux.Handle("/", handler)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		log.Printf("guardian escuchando en %s -> %s", srv.Addr, cfg.UpstreamURL)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("error al escuchar: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("señal recibida: dejando de estar listo")
	ready.Store(false)
	time.Sleep(cfg.DrainDelay)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	log.Println("cerrando: esperando requests en curso")
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("apagado forzado: %v", err)
		return
	}
	log.Println("apagado limpio")

}
