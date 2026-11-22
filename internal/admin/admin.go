package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/fharias/guardian-scrapy/internal/acl"
	"github.com/fharias/guardian-scrapy/internal/apps"
)

// ReloadFunc pide una recarga de la config y devuelve la versión antes y
// después. main la arma sobre configsource.Reloader: este paquete no conoce
// el tipo genérico del Reloader ni importa config.
type ReloadFunc func(ctx context.Context) (before, after string, err error)

// ConfigInfo es lo que GET /v1/config muestra de la config activa. Nada de
// valores: solo versión, qué se puede recargar y qué apps hay. Los valores
// pueden incluir rutas internas o CIDRs que no hace falta exponer ni en una
// API interna.
type ConfigInfo struct {
	Version    string    `json:"version"`
	LoadedAt   time.Time `json:"loaded_at"`
	Reloadable []string  `json:"reloadable"`
	Apps       []string  `json:"apps"`
	DefaultApp string    `json:"default_app"`
}

// AppsFunc devuelve las apps de la config VIGENTE y la default ("" = no hay).
// main la arma sobre el snapshot del Reloader: si una recarga agrega una app,
// la Admin API la conoce en el siguiente request, sin reiniciar nada.
type AppsFunc func() (names []string, def string)

// Options arma el handler. Store y Tokens son obligatorios.
type Options struct {
	Store      *acl.Store
	Apps       AppsFunc
	Tokens     Tokens
	MaxTTL     time.Duration
	Reload     ReloadFunc        // nil = POST /v1/reload responde 501
	Info       func() ConfigInfo // nil = GET /v1/config responde 501
	Logger     *slog.Logger
	Registerer prometheus.Registerer
}

type server struct {
	store  *acl.Store
	apps   AppsFunc
	tokens Tokens
	maxTTL time.Duration
	reload ReloadFunc
	info   func() ConfigInfo
	log    *slog.Logger

	requests    *prometheus.CounterVec
	authFailed  prometheus.Counter
	changes     *prometheus.CounterVec
	reqDuration *prometheus.HistogramVec
}

// paths de la API -> lista de la ACL. El nombre en la URL es para humanos;
// el valor interno es el que va en la llave de Redis.
var lists = map[string]acl.List{"blocks": acl.Block, "allowlist": acl.Allow}

// NewHandler devuelve el http.Handler completo de la Admin API:
//
//	métricas -> autenticación -> ServeMux
//
// La autenticación envuelve AL MUX: un request sin token recibe 401 antes de
// saber si la ruta existe (no se puede enumerar la API sin token).
func NewHandler(o Options) (http.Handler, error) {
	if o.Store == nil {
		return nil, errors.New("admin: Store es obligatorio")
	}
	if o.Apps == nil {
		return nil, errors.New("admin: Apps es obligatorio")
	}
	if len(o.Tokens.sums) == 0 {
		return nil, fmt.Errorf("admin: sin tokens; define %s", TokenEnv)
	}
	if o.MaxTTL <= 0 {
		o.MaxTTL = DefaultMaxTTL
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Registerer == nil {
		o.Registerer = prometheus.NewRegistry()
	}
	f := promauto.With(o.Registerer)
	s := &server{
		store: o.Store, apps: o.Apps, tokens: o.Tokens, maxTTL: o.MaxTTL,
		reload: o.Reload, info: o.Info, log: o.Logger,
		requests: f.NewCounterVec(prometheus.CounterOpts{
			Name: "guardian_admin_requests_total",
			Help: "Requests a la Admin API por patrón de ruta (no la URL cruda) y status code.",
		}, []string{"route", "code"}),
		authFailed: f.NewCounter(prometheus.CounterOpts{
			Name: "guardian_admin_auth_failures_total",
			Help: "Requests a la Admin API rechazados con 401.",
		}),
		changes: f.NewCounterVec(prometheus.CounterOpts{
			Name: "guardian_admin_changes_total",
			Help: "Cambios hechos por la Admin API, por acción, app, lista, tipo y resultado.",
		}, []string{"action", "app", "list", "kind", "result"}),
		reqDuration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "guardian_admin_request_duration_seconds",
			Help:    "Latencia de la Admin API por patrón de ruta.",
			Buckets: []float64{.001, .005, .01, .05, .1, .5, 1, 5},
		}, []string{"route"}),
	}

	mux := http.NewServeMux()
	// Patrones de Go 1.22: método + path + comodines {app}, {kind} y {value}.
	// El mux responde 405 (con header Allow) si el path existe con otro
	// método, y 404 si no existe. Sin routers externos.
	//
	// Cada ruta existe dos veces:
	//   /v1/apps/{app}/blocks/...  la forma explícita, por app
	//   /v1/blocks/...             la de siempre: va a la app por defecto
	// Con una config sin apps la app por defecto es la única, así que los
	// scripts y runbooks que ya usan /v1/blocks siguen funcionando igual.
	for name, list := range lists {
		for _, prefix := range []string{"/v1/apps/{app}/", "/v1/"} {
			mux.HandleFunc("GET "+prefix+name, s.handleList(list))
			mux.HandleFunc("GET "+prefix+name+"/{kind}/{value}", s.handleGet(list))
			mux.HandleFunc("PUT "+prefix+name+"/{kind}/{value}", s.handlePut(list))
			mux.HandleFunc("DELETE "+prefix+name+"/{kind}/{value}", s.handleDelete(list))
		}
	}
	mux.HandleFunc("GET /v1/apps", s.handleApps)
	mux.HandleFunc("POST /v1/reload", s.handleReload)
	mux.HandleFunc("GET /v1/config", s.handleConfig)

	return s.instrument(s.authenticate(mux)), nil
}

// ---------------------------------------------------------------- middlewares

func (s *server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || !s.tokens.Valid(token) {
			s.authFailed.Inc()
			motivo := "sin_bearer"
			if ok {
				motivo = "token_invalido"
			}
			// Nunca el header Authorization en el log: ni completo, ni recortado.
			s.log.Warn("admin_auth_fallida", "remote", r.RemoteAddr, "method", r.Method,
				"path", r.URL.Path, "motivo", motivo)
			w.Header().Set("WWW-Authenticate", `Bearer realm="guardian-admin"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no autorizado"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// instrument mide cada request con el PATRÓN que matcheó (r.Pattern, Go 1.23+),
// no con la URL: "PUT /v1/apps/{app}/blocks/{kind}/{value}" es una serie;
// cada IP bloqueada (o cada app inventada) sería una serie nueva y Prometheus
// explota.
func (s *server) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		route := r.Pattern // lo escribe el ServeMux en ESTE mismo *Request
		switch {
		case sw.status == http.StatusUnauthorized && route == "":
			route = "unauthorized"
		case route == "":
			route = "unmatched"
		}
		s.requests.WithLabelValues(route, strconv.Itoa(sw.status)).Inc()
		s.reqDuration.WithLabelValues(route).Observe(time.Since(start).Seconds())
	})
}

// ---------------------------------------------------------------- handlers

type putBody struct {
	TTL    string `json:"ttl"`    // duración de Go: "15m", "2h", "168h"
	Reason string `json:"reason"` // texto libre para el humano que lea el audit log
}

func (s *server) handlePut(list acl.List) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app, ok := s.app(w, r)
		if !ok {
			return
		}
		kind, value, ok := s.target(w, r, app, list, "put")
		if !ok {
			return
		}
		var body putBody
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			s.badRequest(w, r, "put", app, list, kind, value, fmt.Errorf("body JSON inválido: %w", err))
			return
		}
		ttl, err := time.ParseDuration(body.TTL)
		switch {
		case err != nil || ttl <= 0:
			s.badRequest(w, r, "put", app, list, kind, value, fmt.Errorf("ttl %q: usa una duración > 0, ej. \"30m\" o \"24h\"", body.TTL))
			return
		case ttl > s.maxTTL:
			s.badRequest(w, r, "put", app, list, kind, value, fmt.Errorf("ttl %s supera admin.max_ttl (%s): lo permanente va en rules.deny_cidrs del YAML", ttl, s.maxTTL))
			return
		}
		reason := strings.TrimSpace(body.Reason)
		if reason == "" || utf8.RuneCountInString(reason) > acl.MaxReasonLen {
			s.badRequest(w, r, "put", app, list, kind, value, fmt.Errorf("reason es obligatorio y de máximo %d caracteres", acl.MaxReasonLen))
			return
		}
		e, err := s.store.Put(r.Context(), app, acl.Entry{
			List: list, Kind: kind, Value: value, Reason: reason, Actor: actor(r),
		}, ttl)
		if err != nil {
			s.unavailable(w, r, "put", app, list, kind, value, err)
			return
		}
		s.audit(r, "put", app, list, kind, value, "ok", "ttl", ttl.String(), "reason", reason, "expires_at", e.ExpiresAt)
		writeJSON(w, http.StatusOK, e)
	}
}

func (s *server) handleGet(list acl.List) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app, ok := s.app(w, r)
		if !ok {
			return
		}
		kind, value, ok := s.target(w, r, app, list, "get")
		if !ok {
			return
		}
		e, err := s.store.Get(r.Context(), app, list, kind, value)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		if e == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no existe o ya expiró"})
			return
		}
		writeJSON(w, http.StatusOK, e)
	}
}

func (s *server) handleDelete(list acl.List) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app, ok := s.app(w, r)
		if !ok {
			return
		}
		kind, value, ok := s.target(w, r, app, list, "delete")
		if !ok {
			return
		}
		existed, err := s.store.Delete(r.Context(), app, list, kind, value)
		if err != nil {
			s.unavailable(w, r, "delete", app, list, kind, value, err)
			return
		}
		if !existed {
			s.audit(r, "delete", app, list, kind, value, "not_found")
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no existe o ya expiró"})
			return
		}
		s.audit(r, "delete", app, list, kind, value, "ok")
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *server) handleList(list acl.List) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app, ok := s.app(w, r)
		if !ok {
			return
		}
		entries, err := s.store.List(r.Context(), app, list)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"app": app, "list": list, "count": len(entries), "entries": entries})
	}
}

func (s *server) handleApps(w http.ResponseWriter, r *http.Request) {
	names, def := s.apps()
	writeJSON(w, http.StatusOK, map[string]any{"apps": names, "default_app": def})
}

func (s *server) handleReload(w http.ResponseWriter, r *http.Request) {
	if s.reload == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "recarga no disponible"})
		return
	}
	before, after, err := s.reload(r.Context())
	if err != nil {
		s.changes.WithLabelValues("reload", "", "", "", "rejected").Inc()
		s.log.Warn("admin_audit", "action", "reload", "result", "rejected", "actor", actor(r),
			"remote", r.RemoteAddr, "version_activa", after, "err", err)
		// 422: el request está bien formado, pero la config del archivo no se puede aplicar.
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"changed": false, "version": after, "error": err.Error(),
		})
		return
	}
	s.changes.WithLabelValues("reload", "", "", "", "ok").Inc()
	s.log.Info("admin_audit", "action", "reload", "result", "ok", "actor", actor(r),
		"remote", r.RemoteAddr, "version_anterior", before, "version", after)
	writeJSON(w, http.StatusOK, map[string]any{
		"changed": before != after, "version_anterior": before, "version": after,
	})
}

func (s *server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if s.info == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "info no disponible"})
		return
	}
	writeJSON(w, http.StatusOK, s.info())
}

// ---------------------------------------------------------------- helpers

// app resuelve la app del request contra la config VIGENTE. Con {app} en el
// path, tiene que existir; sin {app} (las rutas de siempre) es la default.
// Una app que no está en la config es 404 aunque el nombre sea válido: así
// nadie escribe llaves gd:<app>: que ningún proxy va a leer nunca.
func (s *server) app(w http.ResponseWriter, r *http.Request) (string, bool) {
	names, def := s.apps()
	name := r.PathValue("app")
	if name == "" {
		if def == "" {
			writeJSON(w, http.StatusNotFound, map[string]any{
				"error": "no hay default_app: usa /v1/apps/{app}/...", "apps": names,
			})
			return "", false
		}
		return def, true
	}
	if !apps.ValidName(name) || !slices.Contains(names, name) {
		// El nombre no se devuelve: viene del cliente y no es de ninguna app.
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "la app no existe", "apps": names})
		return "", false
	}
	return name, true
}

// target saca {kind} y {value} del path (r.PathValue, Go 1.22) y los normaliza.
func (s *server) target(w http.ResponseWriter, r *http.Request, app string, list acl.List, action string) (acl.Kind, string, bool) {
	kind := acl.Kind(r.PathValue("kind"))
	value, err := acl.Normalize(list, kind, r.PathValue("value"))
	if err != nil {
		s.badRequest(w, r, action, app, list, kind, "", err)
		return "", "", false
	}
	return kind, value, true
}

func (s *server) badRequest(w http.ResponseWriter, r *http.Request, action, app string, list acl.List, kind acl.Kind, value string, err error) {
	if action != "get" {
		s.audit(r, action, app, list, kind, value, "invalid", "err", err.Error())
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}

// unavailable: si Redis no está, la escritura FALLA y se dice. Para escribir
// somos fail-closed: nunca respondemos "bloqueado" si el bloqueo no quedó.
func (s *server) unavailable(w http.ResponseWriter, r *http.Request, action, app string, list acl.List, kind acl.Kind, value string, err error) {
	s.audit(r, action, app, list, kind, value, "error", "err", err.Error())
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "redis no disponible: el cambio NO se aplicó"})
}

// audit deja UNA línea por cambio con quién, qué, desde dónde y el resultado.
// Es el log que te piden en un incidente: "¿quién bloqueó a este cliente?".
func (s *server) audit(r *http.Request, action, app string, list acl.List, kind acl.Kind, value, result string, extra ...any) {
	s.changes.WithLabelValues(action, app, string(list), string(kind), result).Inc()
	attrs := append([]any{
		"action", action, "app", app, "list", list, "kind", kind, "value", value, "result", result,
		"actor", actor(r), "remote", r.RemoteAddr,
	}, extra...)
	s.log.Info("admin_audit", attrs...)
}

// actor es quién dice ser el operador (header X-Guardian-Actor). Con un token
// compartido NO está autenticado: es una etiqueta para el audit log, no una
// identidad. Se limpia para que nadie inyecte saltos de línea en el log.
func actor(r *http.Request) string {
	a := strings.TrimSpace(r.Header.Get("X-Guardian-Actor"))
	a = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, a)
	if a == "" {
		return "desconocido"
	}
	if rs := []rune(a); len(rs) > acl.MaxActorLen {
		a = string(rs[:acl.MaxActorLen]) // por runas: no partir una tilde a la mitad
	}
	return a
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status, s.wroteHeader = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}
