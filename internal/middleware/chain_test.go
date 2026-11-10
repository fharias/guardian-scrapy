package middleware

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestChainOrder(t *testing.T) {
	var got []string

	mark := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = append(got, name)
				next.ServeHTTP(w, r)
			})
		}
	}

	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, "final")
	})

	h := Chain(final, mark("A"), mark("B"), mark("C"))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	want := []string{"A", "B", "C", "final"}
	if !slices.Equal(got, want) {
		t.Fatalf("orden = %v, quiero %v", got, want)
	}
}
