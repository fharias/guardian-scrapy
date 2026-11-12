package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/fharias/guardian-scrapy/internal/challenge"
	"github.com/fharias/guardian-scrapy/internal/verdict"
)

func newService(t *testing.T) *challenge.Service {
	t.Helper()
	b := make([]byte, 32)
	rand.Read(b)
	kr, err := challenge.ParseKeyring("k1:" + base64.StdEncoding.EncodeToString(b))
	if err != nil {
		t.Fatal(err)
	}
	return challenge.NewService(kr, 8, time.Minute, time.Hour)
}

// withVerdict simula lo que hacen Init + ClientIP + Score en la cadena real.
func withVerdict(d verdict.Decision, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := &verdict.Verdict{ClientIP: netip.MustParseAddr("203.0.113.7"), Fingerprint: "fpA", Decision: d}
		h.ServeHTTP(w, r.WithContext(verdict.WithVerdict(r.Context(), v)))
	})
}

func TestChallengeRoundTrip(t *testing.T) {
	ch := newService(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })

	app := withVerdict(verdict.Challenge, Enforce(ch, logger)(upstream))
	verify := withVerdict(verdict.Challenge, VerifyHandler(ch, logger))

	// 1. Sin pase: página de desafío.
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest("GET", "/precios?x=1", nil))
	body := rec.Body.String()
	if rec.Code != http.StatusForbidden || !strings.Contains(body, "crypto.subtle") {
		t.Fatalf("esperaba página de desafío, code=%d", rec.Code)
	}

	// 2. "Navegador": extrae token y semilla, resuelve la PoW
	token := regexp.MustCompile(`name="token" value="([^"]+)"`).FindStringSubmatch(body)[1]
	seed := regexp.MustCompile(`const seed = "([0-9a-f]+)"`).FindStringSubmatch(body)[1]
	form := url.Values{"token": {token}, "nonce": {challenge.Solve(seed, 8)}, "next": {"/precios?x=1"}}
	req := httptest.NewRequest("POST", VerifyPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	verify.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/precios?x=1" {
		t.Fatalf("verify: code=%d location=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	cookie := rec.Result().Cookies()[0]

	// 3. Con el pase: llega al upstream.
	req = httptest.NewRequest("GET", "/precios?x=1", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("con pase: code=%d", rec.Code)
	}
}

func TestBlockIgnoresPass(t *testing.T) {
	ch := newService(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app := withVerdict(verdict.Block, Enforce(ch, logger)(http.NotFoundHandler()))
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"/precios?x=1":      "/precios?x=1",
		"https://evil.com/": "/",
		"//evil.com":        "/",
		"precios":           "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}
