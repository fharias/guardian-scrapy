package middleware

import (
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/fharias/guardian-scrapy/internal/challenge"
	"github.com/fharias/guardian-scrapy/internal/policy"
	"github.com/fharias/guardian-scrapy/internal/verdict"
)

const (
	PassCookie = "guardian_pass"
	VerifyPath = "/__guardian/verify"
)

func Enforce(ch *challenge.Service, modes *policy.Modes, logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v := verdict.From(r.Context())
			if v == nil {
				next.ServeHTTP(w, r)
				return
			}
			mode := modes.For(r.URL.Path)
			v.Mode = string(mode)
			if mode == policy.Monitor && v.Decision != verdict.Allow && v.Signals.DenyReason == "" {
				v.Shadowed = true
				next.ServeHTTP(w, r) // registra, pero NO bloquea ni desafía
				return
			}
			switch v.Decision {
			case verdict.Block:
				http.Error(w, "acceso denegado", http.StatusForbidden)
			case verdict.Challenge:
				if c, err := r.Cookie(PassCookie); err == nil {
					err := ch.ValidPass(c.Value, v.ClientIP.String(), v.Fingerprint)
					if err == nil {
						v.Reasons = append(v.Reasons, "pase_valido")
						next.ServeHTTP(w, r)
						return
					}
					logger.Info("pase rechazado", "client_ip", v.ClientIP, "err", err)
				}
				serveChallenge(w, r, ch, v)
			default:
				next.ServeHTTP(w, r)
			}
		})
	}
}

var page = template.Must(template.New("c").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Verificando…</title></head>
<body>
<p>Verificando tu navegador…</p>
<form id="f" method="POST" action="{{.Action}}">
  <input type="hidden" name="token" value="{{.Token}}">
  <input type="hidden" name="nonce" id="nonce">
  <input type="hidden" name="next" value="{{.Next}}">
</form>
<script>
(async () => {
  const seed = {{.Seed}}, difficulty = {{.Difficulty}};
  const enc = new TextEncoder();
  for (let n = 0; ; n++) {
    const h = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(seed + n)));
    let zeros = 0;
    for (const b of h) {
      if (b === 0) { zeros += 8; continue; }
      zeros += Math.clz32(b) - 24;
      break;
    }
    if (zeros >= difficulty) {
      document.getElementById("nonce").value = String(n);
      document.getElementById("f").submit();
      return;
    }
  }
})();
</script>
</body></html>`))

func serveChallenge(w http.ResponseWriter, r *http.Request, ch *challenge.Service, v *verdict.Verdict) {
	seed, token, err := ch.NewChallenge(v.ClientIP.String(), v.Fingerprint)
	if err != nil {
		http.Error(w, "error interno", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	page.Execute(w, map[string]any{
		"Action":     VerifyPath,
		"Token":      token,
		"Seed":       seed,
		"Difficulty": ch.Difficulty(),
		"Next":       r.URL.RequestURI(),
	})
}

// VerifyHandler recibe el formulario del desafío y entrega el pase.
func VerifyHandler(ch *challenge.Service, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := verdict.From(r.Context())
		if r.Method != http.MethodPost || v == nil {
			http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
			return
		}
		pass, err := ch.Redeem(r.FormValue("token"), r.FormValue("nonce"), v.ClientIP.String(), v.Fingerprint)
		if err != nil {
			logger.Info("desafio fallido", "client_ip", v.ClientIP, "err", err)
			http.Error(w, "desafío inválido", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     PassCookie,
			Value:    pass,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(ch.PassTTL().Seconds()),
		})
		http.Redirect(w, r, safeNext(r.FormValue("next")), http.StatusSeeOther)
	})
}

func safeNext(next string) string {
	u, err := url.Parse(next)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}
