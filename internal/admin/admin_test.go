package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"

	"github.com/fharias/guardian-scrapy/internal/acl"
)

const (
	tokenA  = "token-actual-0123456789abcdef0123456789abcdef"
	tokenB  = "token-anterior-0123456789abcdef0123456789abcd"
	testJA4 = "t13d4907h2_0d8feac7bc37_7395dae3b2f3"
)

// syncBuffer: el handler escribe logs desde la goroutine del test; con -race
// un bytes.Buffer compartido necesita su mutex.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type api struct {
	h    http.Handler
	mr   *miniredis.Miniredis
	reg  *prometheus.Registry
	logs *syncBuffer
}

func newAPI(t *testing.T, mutate func(*Options)) *api {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	tokens, err := ParseTokens(tokenA + "," + tokenB)
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	reg := prometheus.NewRegistry()
	o := Options{
		Store:      acl.New(rdb, "shop", acl.Options{CacheTTL: -1}),
		Tokens:     tokens,
		MaxTTL:     24 * time.Hour,
		Logger:     slog.New(slog.NewJSONHandler(logs, nil)),
		Registerer: reg,
	}
	if mutate != nil {
		mutate(&o)
	}
	h, err := NewHandler(o)
	if err != nil {
		t.Fatal(err)
	}
	return &api{h: h, mr: mr, reg: reg, logs: logs}
}

func (a *api) do(t *testing.T, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("X-Guardian-Actor", "fabio")
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	return rec
}

func TestParseTokens(t *testing.T) {
	if _, err := ParseTokens(""); err == nil || !strings.Contains(err.Error(), TokenEnv) {
		t.Fatalf("vacío debe fallar mencionando %s: %v", TokenEnv, err)
	}
	_, err := ParseTokens("corto-secreto")
	if err == nil || strings.Contains(err.Error(), "corto-secreto") {
		t.Fatalf("un token corto falla y el error NO lo imprime: %v", err)
	}
	if _, err := ParseTokens(tokenA + "," + tokenB + "," + tokenA); err == nil {
		t.Fatal("más de dos tokens debe fallar")
	}
	tk, err := ParseTokens(" " + tokenA + " , " + tokenB)
	if err != nil {
		t.Fatal(err)
	}
	if !tk.Valid(tokenA) || !tk.Valid(tokenB) {
		t.Fatal("los dos tokens (actual y anterior) deben servir durante la rotación")
	}
	if tk.Valid(tokenA+"x") || tk.Valid("") || tk.Valid(tokenA[:10]) {
		t.Fatal("token distinto, vacío o prefijo no pueden pasar")
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "tokens", tk)
	if strings.Contains(buf.String(), "token-") || !strings.Contains(tk.String(), "redactados") {
		t.Fatalf("ni slog ni %%v muestran los tokens: %s / %s", buf.String(), tk)
	}
}

func TestNewHandlerRequiresTokens(t *testing.T) {
	mr := miniredis.RunT(t)
	store := acl.New(redis.NewClient(&redis.Options{Addr: mr.Addr()}), "shop", acl.Options{})
	if _, err := NewHandler(Options{Store: store}); err == nil {
		t.Fatal("sin tokens NewHandler debe fallar: nunca una Admin API abierta")
	}
}

func TestUnauthorized(t *testing.T) {
	a := newAPI(t, nil)
	cases := []struct{ name, method, path, token string }{
		{"sin header", "GET", "/v1/blocks", ""},
		{"token equivocado", "GET", "/v1/blocks", "token-equivocado-0123456789abcdef0123456789"},
		{"PUT sin token", "PUT", "/v1/blocks/ip/203.0.113.10", ""},
		{"ruta que no existe", "GET", "/v1/no-existe", ""}, // 401, no 404: no se enumera la API
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := a.do(t, c.method, c.path, c.token, `{"ttl":"1h","reason":"x"}`)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("code = %d, want 401", rec.Code)
			}
			if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer") {
				t.Fatal("falta WWW-Authenticate: Bearer")
			}
		})
	}
	// Basic auth con el token correcto tampoco: solo Bearer.
	req := httptest.NewRequest("GET", "/v1/blocks", nil)
	req.SetBasicAuth("admin", tokenA)
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("basic auth: code = %d", rec.Code)
	}
	if a.mr.Exists("gd:shop:acl:block:ip:203.0.113.10") {
		t.Fatal("un PUT sin token NO puede escribir")
	}
	if got := metricValue(t, a.reg, "guardian_admin_auth_failures_total"); got != 5 {
		t.Fatalf("auth_failures = %v, want 5", got)
	}
	if strings.Contains(a.logs.String(), "token-equivocado") {
		t.Fatal("el token presentado jamás aparece en el log")
	}
}

func TestBlockLifecycle(t *testing.T) {
	a := newAPI(t, nil)
	path := "/v1/blocks/ja4/" + strings.ToUpper(testJA4) // se normaliza a minúsculas

	rec := a.do(t, "PUT", path, tokenA, `{"ttl":"30m","reason":"scraping de /api/prices"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body)
	}
	var e acl.Entry
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if e.Value != testJA4 || e.Actor != "fabio" || e.ExpiresAt.Sub(e.CreatedAt) != 30*time.Minute {
		t.Fatalf("entry = %+v", e)
	}
	if ttl := a.mr.TTL("gd:shop:acl:block:ja4:" + testJA4); ttl != 30*time.Minute {
		t.Fatalf("TTL en Redis = %s", ttl)
	}

	if rec := a.do(t, "GET", path, tokenB, ""); rec.Code != http.StatusOK { // el token anterior también sirve
		t.Fatalf("GET = %d", rec.Code)
	}
	rec = a.do(t, "GET", "/v1/blocks", tokenA, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"count":1`) {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	if rec := a.do(t, "DELETE", path, tokenA, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d", rec.Code)
	}
	if rec := a.do(t, "DELETE", path, tokenA, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("DELETE repetido = %d, want 404", rec.Code)
	}
	if rec := a.do(t, "GET", path, tokenA, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("GET después de borrar = %d", rec.Code)
	}

	logs := a.logs.String()
	for _, want := range []string{`"msg":"admin_audit"`, `"action":"put"`, `"action":"delete"`, `"actor":"fabio"`, `"reason":"scraping de /api/prices"`} {
		if !strings.Contains(logs, want) {
			t.Fatalf("audit log sin %s:\n%s", want, logs)
		}
	}
	if strings.Contains(logs, tokenA) || strings.Contains(logs, tokenB) {
		t.Fatal("el token apareció en el log")
	}
}

func TestTTLExpiryThroughAPI(t *testing.T) {
	a := newAPI(t, nil)
	if rec := a.do(t, "PUT", "/v1/allowlist/ip/10.1.2.3", tokenA, `{"ttl":"1m","reason":"monitor de un partner"}`); rec.Code != 200 {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body)
	}
	a.mr.FastForward(61 * time.Second)
	if rec := a.do(t, "GET", "/v1/allowlist/ip/10.1.2.3", tokenA, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("pasado el TTL = %d, want 404", rec.Code)
	}
}

func TestPutValidation(t *testing.T) {
	a := newAPI(t, nil)
	cases := []struct{ name, path, body string }{
		{"kind desconocido", "/v1/blocks/fp/abc", `{"ttl":"1h","reason":"x"}`},
		{"ip inválida", "/v1/blocks/ip/999.1.1.1", `{"ttl":"1h","reason":"x"}`},
		{"CIDR no", "/v1/blocks/ip/203.0.113.0%2F24", `{"ttl":"1h","reason":"x"}`},
		{"allowlist por ja4", "/v1/allowlist/ja4/" + testJA4, `{"ttl":"1h","reason":"x"}`},
		{"sin ttl", "/v1/blocks/ip/203.0.113.10", `{"reason":"x"}`},
		{"ttl negativo", "/v1/blocks/ip/203.0.113.10", `{"ttl":"-1h","reason":"x"}`},
		{"ttl mayor que max_ttl", "/v1/blocks/ip/203.0.113.10", `{"ttl":"48h","reason":"x"}`},
		{"sin reason", "/v1/blocks/ip/203.0.113.10", `{"ttl":"1h"}`},
		{"reason gigante", "/v1/blocks/ip/203.0.113.10", `{"ttl":"1h","reason":"` + strings.Repeat("á", acl.MaxReasonLen+1) + `"}`},
		{"campo desconocido", "/v1/blocks/ip/203.0.113.10", `{"ttl":"1h","reason":"x","permanent":true}`},
		{"no es JSON", "/v1/blocks/ip/203.0.113.10", `ttl=1h`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := a.do(t, "PUT", c.path, tokenA, c.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("code = %d %s, want 400", rec.Code, rec.Body)
			}
		})
	}
	if keys := a.mr.Keys(); len(keys) != 0 {
		t.Fatalf("ninguna escritura inválida toca Redis: %v", keys)
	}
}

func TestMethodNotAllowedComesFromServeMux(t *testing.T) {
	a := newAPI(t, nil)
	rec := a.do(t, "POST", "/v1/blocks/ip/203.0.113.10", tokenA, `{}`)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code = %d, want 405", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); !strings.Contains(allow, "PUT") || !strings.Contains(allow, "DELETE") {
		t.Fatalf("Allow = %q", allow)
	}
}

func TestMetricsUsePatternNotURL(t *testing.T) {
	a := newAPI(t, nil)
	for _, ipStr := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		a.do(t, "PUT", "/v1/blocks/ip/"+ipStr, tokenA, `{"ttl":"1h","reason":"x"}`)
	}
	a.do(t, "GET", "/v1/blocks", "", "")
	mfs, err := a.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "guardian_admin_requests_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			got[labels["route"]+" "+labels["code"]] = m.GetCounter().GetValue()
		}
	}
	if got["PUT /v1/blocks/{kind}/{value} 200"] != 3 || got["unauthorized 401"] != 1 || len(got) != 2 {
		t.Fatalf("series = %v; tres IPs distintas deben ser UNA serie", got)
	}
}

func TestWriteFailsClosedWhenRedisIsDown(t *testing.T) {
	a := newAPI(t, nil)
	a.mr.SetError("LOADING simulado")
	rec := a.do(t, "PUT", "/v1/blocks/ip/203.0.113.10", tokenA, `{"ttl":"1h","reason":"x"}`)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "NO se aplicó") {
		t.Fatalf("code = %d %s, want 503", rec.Code, rec.Body)
	}
	if !strings.Contains(a.logs.String(), `"result":"error"`) {
		t.Fatal("el intento fallido también queda en el audit log")
	}
}

func TestReloadEndpoint(t *testing.T) {
	t.Run("aplica", func(t *testing.T) {
		a := newAPI(t, func(o *Options) {
			o.Reload = func(context.Context) (string, string, error) { return "aaa111", "bbb222", nil }
		})
		rec := a.do(t, "POST", "/v1/reload", tokenA, "")
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"changed":true`) || !strings.Contains(rec.Body.String(), "bbb222") {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	t.Run("rechazada", func(t *testing.T) {
		a := newAPI(t, func(o *Options) {
			o.Reload = func(context.Context) (string, string, error) {
				return "aaa111", "aaa111", errors.New("scoring.thresholds: challenge (90) debe ser menor que block (85)")
			}
		})
		rec := a.do(t, "POST", "/v1/reload", tokenA, "")
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "challenge (90)") {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	})
	t.Run("sin reloader", func(t *testing.T) {
		a := newAPI(t, nil)
		if rec := a.do(t, "POST", "/v1/reload", tokenA, ""); rec.Code != http.StatusNotImplemented {
			t.Fatalf("code = %d", rec.Code)
		}
	})
}

func TestConfigInfo(t *testing.T) {
	a := newAPI(t, func(o *Options) {
		o.Info = func() ConfigInfo { return ConfigInfo{Version: "fede100cd5ef", Reloadable: []string{"scoring"}} }
	})
	rec := a.do(t, "GET", "/v1/config", tokenA, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "fede100cd5ef") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestActorIsSanitized(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Guardian-Actor", "fabio\x00\x1b[31m"+strings.Repeat("ñ", 100))
	got := actor(req)
	if strings.ContainsAny(got, "\x00\x1b") || len([]rune(got)) != acl.MaxActorLen {
		t.Fatalf("actor = %q", got)
	}
	if actor(httptest.NewRequest("GET", "/", nil)) != "desconocido" {
		t.Fatal("sin header el actor es 'desconocido'")
	}
}

// metricValue suma todas las series de una métrica del registry del test.
func metricValue(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var total float64
	for _, mf := range mfs {
		if mf.GetName() == name {
			for _, m := range mf.GetMetric() {
				total += m.GetCounter().GetValue()
			}
		}
	}
	return total
}
