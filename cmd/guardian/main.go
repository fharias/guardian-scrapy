package main

import (
	"context"
	"crypto/tls"
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

	"github.com/fharias/guardian-scrapy/internal/challenge"
	"github.com/fharias/guardian-scrapy/internal/clientip"
	"github.com/fharias/guardian-scrapy/internal/config"
	"github.com/fharias/guardian-scrapy/internal/goodbot"
	"github.com/fharias/guardian-scrapy/internal/middleware"
	"github.com/fharias/guardian-scrapy/internal/policy"
	"github.com/fharias/guardian-scrapy/internal/ratelimit"
	"github.com/fharias/guardian-scrapy/internal/rules"
	"github.com/fharias/guardian-scrapy/internal/scoring"
	"github.com/fharias/guardian-scrapy/internal/tlshello"
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

	healthz := func(w http.ResponseWriter, r *http.Request) {
		if ready.Load() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}
	readyz := func(w http.ResponseWriter, r *http.Request) {
		if ready.Load() {
			w.WriteHeader(http.StatusOK)
		}
	}
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
	keys, err := challenge.ParseKeyring(os.Getenv("GUARDIAN_PASS_KEYS"))
	if err != nil {
		logger.Error("pass keys", "err", err)
		os.Exit(1)
	}
	ch := challenge.NewService(keys, cfg.Challenge.Difficulty, cfg.Challenge.TTL, cfg.Challenge.PassTTL)
	modes, err := policy.New(cfg.Modes)
	if err != nil {
		logger.Error("modes", "err", err)
		os.Exit(1)
	}
	protected := middleware.Chain(proxy,
		middleware.Init,
		middleware.ClientIP(clientipResolver),
		middleware.Logger(logger),
		middleware.SuspiciousUA(),
		middleware.Fingerprint(),
		middleware.Rules(engine, bots, 300*time.Millisecond),
		middleware.RateLimit(store, logger),
		middleware.Score(scorer),
		middleware.Enforce(ch, modes, logger),
	)
	verify := middleware.Chain(middleware.VerifyHandler(ch, logger),
		middleware.Init,
		middleware.ClientIP(clientipResolver),
		middleware.Logger(logger),
		middleware.Fingerprint(),
	)
	root := http.NewServeMux()
	root.Handle(middleware.VerifyPath, verify)
	root.HandleFunc("GET /healthz", healthz)
	root.HandleFunc("GET /readyz", readyz)
	root.Handle("/", protected)

	newServer := func(addr string, handler http.Handler) *http.Server {
		return &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			ReadTimeout:       cfg.ReadTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			IdleTimeout:       cfg.IdleTimeout,
		}
	}

	abrirListener := func(addr string) (net.Listener, error) {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		if cfg.ProxyProtocol {
			policy, err := proxyproto.TrustProxyHeaderFromRanges(cfg.TrustedProxies)
			if err != nil {
				ln.Close()
				return nil, err
			}
			ln = &proxyproto.Listener{
				Listener:          ln,
				ConnPolicy:        policy,
				ReadHeaderTimeout: 2 * time.Second,
			}
		}
		return ln, nil
	}

	httpSrv := newServer(cfg.Listen, root)

	var tlsSrv *http.Server
	if cfg.TLS.Enabled() {
		if _, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil {
			logger.Error("tls: no pude cargar el certificado", "err", err)
			os.Exit(1)
		}
		tlsSrv = newServer(cfg.TLS.Listen, tlshello.LogHandler(logger, root))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	local.StartJanitor(ctx, time.Minute, logger)
	defer stop()
	logger.Info("listener", "addr", cfg.Listen, "proxy_protocol", cfg.ProxyProtocol, "trusted", cfg.TrustedProxies)

	ln, err := abrirListener(cfg.Listen)
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
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("servidor", "err", err)
		}
	}()

	if tlsSrv != nil {
		tlsLn, err := abrirListener(cfg.TLS.Listen)
		if err != nil {
			logger.Error("no pude escuchar TLS", "err", err)
			os.Exit(1)
		}
		tlsLn = tlshello.Hook(tlsSrv, tlsLn)
		logger.Info("listener_tls", "addr", cfg.TLS.Listen, "cert", cfg.TLS.CertFile)
		go func() {
			if err := tlsSrv.ServeTLS(tlsLn, cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("servidor tls", "err", err)
			}
		}()
	}

	<-ctx.Done()
	log.Println("señal recibida: dejando de estar listo")
	ready.Store(false)
	time.Sleep(cfg.DrainDelay)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	log.Println("cerrando: esperando requests en curso")
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("apagado forzado: %v", err)
	}
	if tlsSrv != nil {
		if err := tlsSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("apagado forzado: %v", err)
		}
	}
	log.Println("apagado limpio")

}
