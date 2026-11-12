package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/fharias/guardian-scrapy/internal/clientip"
	"github.com/fharias/guardian-scrapy/internal/config"
	"github.com/fharias/guardian-scrapy/internal/goodbot"
	"github.com/fharias/guardian-scrapy/internal/middleware"
	"github.com/fharias/guardian-scrapy/internal/ratelimit"
	"github.com/fharias/guardian-scrapy/internal/rules"
	"github.com/fharias/guardian-scrapy/internal/scoring"
	"github.com/fharias/guardian-scrapy/internal/verdict"
	"github.com/redis/go-redis/v9"
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
			pr.SetXForwarded()
			if v := verdict.From(pr.In.Context()); v != nil && v.ClientIP.IsValid() {
				pr.Out.Header.Set("X-Forwarded-For", v.ClientIP.String())
			}
			if cfg.PreserveHost {
				pr.Out.Host = pr.In.Host
			}
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
	go func() {
		m := http.NewServeMux()
		m.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(":2112", m); err != nil {
			logger.Error("servidor de métricas", "err", err)
		}
	}()
	rdb := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:                 []string{cfg.RedisAddr},
		DialTimeout:           200 * time.Millisecond,
		ReadTimeout:           100 * time.Millisecond,
		WriteTimeout:          100 * time.Millisecond,
		ContextTimeoutEnabled: true,
		MaxRetries:            -1,
	})
	defer rdb.Close()
	redisStore := ratelimit.NewRedisStore(rdb, cfg.App, cfg.Rate, cfg.Burst)
	local := ratelimit.NewMemoryStore(cfg.Rate, cfg.Burst)

	store := ratelimit.NewFailoverStore(redisStore, local, 50*time.Millisecond, 5, 10*time.Second, logger)

	clientipResolver, err := clientip.New(cfg.TrustedProxies, cfg.XForwardedForHeader)
	if err != nil {
		logger.Error("error al crear el resolver de clientip", "err", err)
		os.Exit(1)
	}
	scorer, err := scoring.New(cfg.Scoring)
	if err != nil {
		logger.Error("scoring", "err", err)
		os.Exit(1)
	}

	engine, err := rules.New(cfg.Rules)
	if err != nil {
		logger.Error("rules", "err", err)
		os.Exit(1)
	}
	bots := goodbot.NewVerifier(cfg.GoodBots, net.DefaultResolver, time.Hour)

	handler := middleware.Chain(proxy,
		middleware.Init,
		middleware.ClientIP(clientipResolver),
		middleware.Logger(logger),
		middleware.SuspiciousUA(),
		middleware.Fingerprint(),
		middleware.Rules(engine, bots, 300*time.Millisecond),
		middleware.RateLimit(store, logger),
		middleware.Score(scorer),
		middleware.Enforce(),
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
	local.StartJanitor(ctx, time.Minute, logger)
	defer stop()
	logger.Info("listener", "addr", cfg.Listen, "proxy_protocol", cfg.ProxyProtocol, "trusted", cfg.TrustedProxies)
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		logger.Error("no pude escuchar", "err", err)
		os.Exit(1)
	}
	if cfg.ProxyProtocol {
		policy, err := proxyproto.TrustProxyHeaderFromRanges(cfg.TrustedProxies)
		if err != nil {
			logger.Error("proxy protocol", "err", err)
			os.Exit(1)
		}
		ln = &proxyproto.Listener{
			Listener:          ln,
			ConnPolicy:        policy,
			ReadHeaderTimeout: 2 * time.Second,
		}
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("servidor", "err", err)
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
