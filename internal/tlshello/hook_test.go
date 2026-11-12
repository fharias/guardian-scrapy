package tlshello

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCapture(t *testing.T) {
	srv, baseURL, _ := startTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := FromRequest(r)
		if h == nil {
			t.Error("FromRequest devolvió nil en una conexión TLS")
			http.Error(w, "sin hello", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sni":              h.SNI,
			"tls_version":      h.VersionName(),
			"cipher":           h.CipherName(),
			"alpn":             h.Protocol,
			"offered_versions": h.OfferedVersionNames(),
			"ciphers":          h.OfferedCipherNames(),
			"extensions":       h.ExtensionNames(),
			"has_server_name":  h.HasExtension(0x0000),
			"has_alpn":         h.HasExtension(0x0010),
			"has_versions":     h.HasExtension(0x002b),
			"offered_alpn":     h.SupportedProtos,
		})
	}))
	defer srv.Close()

	cases := []struct {
		name       string
		min, max   uint16
		alpn       []string
		wantVer    string
		wantALPN   string
		forceHTTP1 bool
	}{
		{name: "tls13_h2", min: tls.VersionTLS13, max: tls.VersionTLS13,
			alpn: []string{"h2", "http/1.1"}, wantVer: "TLS 1.3", wantALPN: "h2"},
		{name: "tls12_http11", min: tls.VersionTLS12, max: tls.VersionTLS12,
			alpn: []string{"http/1.1"}, wantVer: "TLS 1.2", wantALPN: "http/1.1", forceHTTP1: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := tlsClient(t, srv.certificate, c.min, c.max, c.alpn, c.forceHTTP1)
			resp, err := client.Get(baseURL + "/hello")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status %d: %s", resp.StatusCode, body)
			}
			var got struct {
				SNI             string   `json:"sni"`
				TLSVersion      string   `json:"tls_version"`
				Cipher          string   `json:"cipher"`
				ALPN            string   `json:"alpn"`
				OfferedVersions []string `json:"offered_versions"`
				Ciphers         []string `json:"ciphers"`
				Extensions      []string `json:"extensions"`
				HasServerName   bool     `json:"has_server_name"`
				HasALPN         bool     `json:"has_alpn"`
				HasVersions     bool     `json:"has_versions"`
				OfferedALPN     []string `json:"offered_alpn"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got.SNI != "localhost" {
				t.Errorf("sni = %q, want localhost", got.SNI)
			}
			if got.TLSVersion != c.wantVer {
				t.Errorf("tls_version = %q, want %q", got.TLSVersion, c.wantVer)
			}
			if got.Cipher == "" {
				t.Error("cipher negociado vacío")
			}
			if got.ALPN != c.wantALPN {
				t.Errorf("alpn = %q, want %q", got.ALPN, c.wantALPN)
			}
			if !contains(got.OfferedVersions, c.wantVer) {
				t.Errorf("offered_versions = %v, falta %q", got.OfferedVersions, c.wantVer)
			}
			if len(got.Ciphers) == 0 {
				t.Error("el cliente no ofreció ciphers")
			}
			if !got.HasServerName || !got.HasVersions {
				t.Errorf("extensiones incompletas: %v", got.Extensions)
			}
			if len(c.alpn) > 0 && !got.HasALPN {
				t.Errorf("faltaba extensión ALPN: %v", got.Extensions)
			}
			if !equalStrings(got.OfferedALPN, c.alpn) {
				t.Errorf("offered_alpn = %v, want %v", got.OfferedALPN, c.alpn)
			}
		})
	}
}

func TestLogOncePerConnection(t *testing.T) {
	srv, baseURL, logs := startTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := tlsClient(t, srv.certificate, tls.VersionTLS13, tls.VersionTLS13, []string{"http/1.1"}, true)
	for i := 0; i < 3; i++ {
		resp, err := client.Get(baseURL + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}

	hellos := 0
	dec := json.NewDecoder(bytes.NewReader(logs.Bytes()))
	for {
		var ev map[string]any
		if err := dec.Decode(&ev); err != nil {
			break
		}
		if ev["msg"] == "tls_hello" {
			hellos++
			if ev["tls_version"] != "TLS 1.3" {
				t.Errorf("tls_hello.tls_version = %v", ev["tls_version"])
			}
			ciphers, _ := ev["ciphers"].([]any)
			exts, _ := ev["extensions"].([]any)
			if len(ciphers) == 0 || len(exts) == 0 {
				t.Errorf("tls_hello sin ciphers o extensions: %v", ev)
			}
		}
	}
	if hellos != 1 {
		t.Fatalf("tls_hello se escribió %d veces, want 1 (una por conexión)", hellos)
	}
}

func TestFromNilOnPlainHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var seen *Hello
	srv := &http.Server{
		ConnContext: ConnContext,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = FromRequest(r)
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	resp, err := http.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen != nil {
		t.Fatalf("FromRequest en HTTP plano debía ser nil, got %#v", seen)
	}
}

func TestGetConfigForClientChains(t *testing.T) {
	var called bool
	base := &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			called = true
			return nil, nil
		},
	}
	cfg := Instrument(base)
	info := &tls.ClientHelloInfo{ServerName: "x"}
	if _, err := cfg.GetConfigForClient(info); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("no se encadenó el GetConfigForClient previo")
	}
}

func TestJA4OverRealTLS(t *testing.T) {
	var got []string
	var mu sync.Mutex
	srv, baseURL, logs := startTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := FromRequest(r); h != nil {
			mu.Lock()
			got = append(got, h.JA4)
			mu.Unlock()
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// Dos conexiones distintas (clientes distintos) con la misma configuración.
	for i := 0; i < 2; i++ {
		client := tlsClient(t, srv.certificate, tls.VersionTLS12, tls.VersionTLS13, []string{"h2", "http/1.1"}, false)
		resp, err := client.Get(baseURL + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	// Un cliente solo TLS 1.2 con http/1.1 debe dar otro JA4.
	old := tlsClient(t, srv.certificate, tls.VersionTLS12, tls.VersionTLS12, []string{"http/1.1"}, true)
	resp, err := old.Get(baseURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 3 {
		t.Fatalf("esperaba 3 JA4, got %v", got)
	}
	if got[0] != got[1] {
		t.Errorf("mismo cliente, distinto JA4: %s vs %s", got[0], got[1])
	}
	if got[0] == got[2] {
		t.Errorf("clientes distintos, mismo JA4: %s", got[0])
	}
	if !strings.HasPrefix(got[0], "t13d") || !strings.Contains(got[0], "h2_") {
		t.Errorf("ja4 inesperado para TLS 1.3/h2 con SNI: %s", got[0])
	}
	if !strings.HasPrefix(got[2], "t12d") || !strings.Contains(got[2], "h1_") {
		t.Errorf("ja4 inesperado para TLS 1.2/http1.1 con SNI: %s", got[2])
	}
	if !strings.Contains(string(logs.Bytes()), `"ja4":"`+got[0]+`"`) {
		t.Errorf("el log tls_hello no trae el ja4 %s: %s", got[0], logs.Bytes())
	}
}

// ---- helpers ----

type testServer struct {
	*http.Server
	certificate tls.Certificate
}

func startTLSServer(t *testing.T, h http.Handler) (*testServer, string, *lockedBuffer) {
	t.Helper()
	cert, err := selfSigned()
	if err != nil {
		t.Fatal(err)
	}
	logs := &lockedBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{
		Handler:      LogHandler(logger, h),
		TLSConfig:    &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}},
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	tlsLn := Hook(srv, ln)
	go func() {
		if err := srv.ServeTLS(tlsLn, "", ""); err != nil && err != http.ErrServerClosed {
			t.Log("ServeTLS:", err)
		}
	}()
	t.Cleanup(func() { srv.Close() })
	return &testServer{Server: srv, certificate: cert}, "https://" + ln.Addr().String(), logs
}

func tlsClient(t *testing.T, cert tls.Certificate, min, max uint16, alpn []string, forceHTTP1 bool) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	for _, der := range cert.Certificate {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		pool.AddCert(c)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: pool, ServerName: "localhost",
			MinVersion: min, MaxVersion: max, NextProtos: alpn,
		},
		ForceAttemptHTTP2: !forceHTTP1,
	}
	if forceHTTP1 {
		tr.TLSNextProto = map[string]func(authority string, c *tls.Conn) http.RoundTripper{}
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// lockedBuffer es un io.Writer seguro para slog desde varias goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.b.Bytes()...)
}
