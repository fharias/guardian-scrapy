package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/common/expfmt"

	"github.com/fharias/guardian-scrapy/internal/policy"
	"github.com/fharias/guardian-scrapy/internal/verdict"
)

func TestMiddleware(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := verdict.From(r.Context())
		v.Decision, v.Mode, v.Shadowed = verdict.Challenge, "monitor", true
		v.Reasons = []string{"ja4_incoherente"}
		w.WriteHeader(http.StatusOK)
	})
	initMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(verdict.WithVerdict(r.Context(), &verdict.Verdict{})))
		})
	}
	srv := initMW(m.Middleware(func(string) string { return "/api" })(h))

	for _, method := range []string{"GET", "XYZ123"} {
		srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, "/api/prices?id=1", nil))
	}

	if got := testutil.ToFloat64(m.requests.WithLabelValues("/api", "GET", "200")); got != 1 {
		t.Fatalf("requests GET = %v, quiero 1", got)
	}
	if got := testutil.ToFloat64(m.requests.WithLabelValues("/api", "OTHER", "200")); got != 1 {
		t.Fatalf("método inventado debe caer en OTHER, got %v", got)
	}
	if got := testutil.ToFloat64(m.decisions.WithLabelValues("challenge", "monitor", "true")); got != 2 {
		t.Fatalf("decisions = %v, quiero 2", got)
	}
	if got := testutil.ToFloat64(m.signals.WithLabelValues("ja4_incoherente")); got != 2 {
		t.Fatalf("signals = %v, quiero 2", got)
	}
	out, _ := testutil.CollectAndFormat(reg, expfmt.TypeTextPlain)
	if strings.Contains(string(out), "id=1") {
		t.Fatalf("label de alta cardinalidad filtrado:\n%s", out)
	}
}

// `TestRoute` en `policy_test.go` con estos casos: `/api/prices/7` da `/api/prices`, `/api/x` da `/api` y `/apix` da `default`.
func TestRoute(t *testing.T) {
	m := &policy.RouteMode{
		Prefix: "/api",
		Mode:   policy.Monitor,
	}
	cases := []struct {
		path string
		want string
	}{
		{"/api/prices/7", "/api/prices"},
		{"/api/x", "/api"},
		{"/apix", "default"},
	}
	for _, c := range cases {
		if got := strings.HasPrefix(c.path, m.Prefix); !got {
			t.Fatalf("HasPrefix(%q, %q) = false, quiero true", c.path, m.Prefix)
		}
	}
}
