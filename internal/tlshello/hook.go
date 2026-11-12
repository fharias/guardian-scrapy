package tlshello

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
)

type ctxKey struct{}

// conn envuelve la conexión aceptada y le cuelga el ClientHello
// cuando llega el handshake.
type conn struct {
	net.Conn
	hello  atomic.Pointer[Hello]
	logged atomic.Bool
}

type listener struct {
	net.Listener
}

// Wrap va ANTES de TLS: TCP -> Proxy Protocol (si aplica) -> Wrap -> TLS.
func Wrap(l net.Listener) net.Listener {
	return &listener{Listener: l}
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &conn{Conn: c}, nil
}

// Instrument clona cfg e instala GetConfigForClient para fotografiar
// el ClientHello. Devolver (nil, nil) = seguir con la misma config.
func Instrument(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		cfg = &tls.Config{}
	} else {
		cfg = cfg.Clone()
	}
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS12
	}
	prev := cfg.GetConfigForClient
	cfg.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		if ac := annotated(info.Conn); ac != nil {
			ac.hello.Store(fromClientHello(info))
		}
		if prev != nil {
			return prev(info)
		}
		return nil, nil
	}
	return cfg
}

// ConnContext corre DESPUÉS de Accept y ANTES del handshake: guardamos
// el *conn (el "cajón"), no el Hello, que todavía no existe.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if ac := annotated(c); ac != nil {
		return context.WithValue(ctx, ctxKey{}, ac)
	}
	return ctx
}

// Hook deja el *http.Server listo para ServeTLS y devuelve el listener
// que le debes pasar a ServeTLS.
func Hook(srv *http.Server, ln net.Listener) net.Listener {
	if srv.TLSConfig == nil {
		srv.TLSConfig = &tls.Config{}
	}
	srv.TLSConfig = Instrument(srv.TLSConfig)
	prev := srv.ConnContext
	srv.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		ctx = ConnContext(ctx, c)
		if prev != nil {
			ctx = prev(ctx, c)
		}
		return ctx
	}
	return Wrap(ln)
}

func From(ctx context.Context) *Hello {
	ac, _ := ctx.Value(ctxKey{}).(*conn)
	if ac == nil {
		return nil
	}
	return ac.hello.Load()
}

// FromRequest devuelve el Hello y le completa versión, cipher y ALPN
// negociados con r.TLS.
func FromRequest(r *http.Request) *Hello {
	if r == nil {
		return nil
	}
	return withState(r.Context(), r.TLS)
}

func withState(ctx context.Context, st *tls.ConnectionState) *Hello {
	ac, _ := ctx.Value(ctxKey{}).(*conn)
	if ac == nil {
		return nil
	}
	h := ac.hello.Load()
	if h == nil {
		return nil
	}
	if st == nil || h.Version != 0 {
		return h
	}
	cp := *h
	cp.applyState(st)
	ac.hello.Store(&cp)
	return &cp
}

// LogOnce escribe UNA línea tls_hello por conexión.
func LogOnce(ctx context.Context, logger *slog.Logger) {
	if logger == nil {
		return
	}
	ac, _ := ctx.Value(ctxKey{}).(*conn)
	if ac == nil {
		return
	}
	h := ac.hello.Load()
	if h == nil {
		return
	}
	if !ac.logged.CompareAndSwap(false, true) {
		return
	}
	logger.Info("tls_hello",
		"sni", h.SNI,
		"tls_version", h.VersionName(),
		"cipher", h.CipherName(),
		"alpn", h.Protocol,
		"offered_versions", h.OfferedVersionNames(),
		"ciphers", h.OfferedCipherNames(),
		"extensions", h.ExtensionNames(),
		"curves", h.CurveNames(),
		"offered_alpn", h.SupportedProtos,
	)
}

// LogHandler envuelve el handler raíz del servidor HTTPS para que también
// /healthz y /readyz dejen el log por conexión.
func LogHandler(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if FromRequest(r) != nil {
			LogOnce(r.Context(), logger)
		}
		next.ServeHTTP(w, r)
	})
}

func annotated(c net.Conn) *conn {
	for c != nil {
		switch t := c.(type) {
		case *conn:
			return t
		case *tls.Conn:
			c = t.NetConn()
		default:
			type netConner interface{ NetConn() net.Conn }
			if u, ok := c.(netConner); ok {
				c = u.NetConn()
				continue
			}
			return nil
		}
	}
	return nil
}
