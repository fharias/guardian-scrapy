package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnforceBlocksCurl(t *testing.T) {
	called := false
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	h := Chain(final,
		Init,
		SuspiciousUA(90),
		Honeypot(50, "/admin-oculto", "/robots.txt", "/favicon.ico"),
		Enforce(85),
	)
	req := httptest.NewRequest(http.MethodGet, "/admin-oculto", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("código = %d, quiero %d", rec.Code, http.StatusForbidden)
	}
	if called {
		t.Error("el handler final se ejecutó, y Enforce debió cortar la cadena")
	}
}
