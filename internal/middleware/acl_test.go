package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestACLNilStoreIsPassthrough(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := ACL(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))(next)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("con admin apagado ACL no debe hacer nada; code=%d", rec.Code)
	}
}
