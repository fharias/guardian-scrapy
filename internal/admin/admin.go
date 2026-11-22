package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/fharias/guardian-scrapy/internal/acl"
)

// ReloadFunc pide una recarga de la config y devuelve la versión antes y
// después. main la arma sobre configsource.Reloader: este paquete no conoce
// el tipo genérico del Reloader ni importa config.
type ReloadFunc func(ctx context.Context) (before, after string, err error)

// ConfigInfo es lo que GET /v1/config muestra de la config activa. Nada de
// valores: solo versión y qué se puede recargar. Los valores pueden incluir
// rutas internas o CIDRs que no hace falta exponer ni en una API interna.
type ConfigInfo struct {
	Version    string    `json:"version"`
	LoadedAt   time.Time `json:"loaded_at"`
	Reloadable []string  `json:"reloadable"`
}

// Options arma el handler. Store y Tokens son obligatorios.
type Options struct {
	Store      *acl.Store
	Tokens     Tokens
	MaxTTL     time.Duration
	Reload     ReloadFunc        // nil = POST /v1/reload responde 501
	Info       func() ConfigInfo // nil = GET /v1/config responde 501
	Logger     *slog.Logger
	Registerer prometheus.Registerer
}

type server struct {
	store  *acl.Store
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
		store: o.Store, tokens: o.Tokens, maxTTL: o.MaxTTL,
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
			Help: "Cambios hechos por la Admin API, por acción, lista, tipo y resultado.",
		}, []string{"action", "list", "kind", "result"}),
		reqDuration: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "guardian_admin_request_duration_seconds",
			Help:    "Latencia de la Admin API por patrón de ruta.",
			Buckets: []float64{.001, .005, .01, .05, .1, .5, 1, 5},
		}, []string{"route"}),
	}

	mux := http.NewServeMux()
	// Patrones de Go 1.22: método + path + comodines {kind} y {value}. El mux
	// responde 405 (con header Allow) si el path existe con otro método, y 404
	// si no existe. Sin routers externos.
	for name, list := range lists {
		mux.HandleFunc("GET /v1/"+name, s.handleList(list))
		mux.HandleFunc("GET /v1/"+name+"/{kind}/{value}", s.handleGet(list))
		mux.HandleFunc("PUT /v1/"+name+"/{kind}/{value}", s.handlePut(list))
		mux.HandleFunc("DELETE /v1/"+name+"/{kind}/{value}", s.handleDelete(list))
	}
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
// no con la URL: "PUT /v1/blocks/{kind}/{value}" es una serie; cada IP
// bloqueada sería una serie nueva y Prometheus explota.
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
		kind, value, ok := s.target(w, r, list, "put")
		if !ok {
			return
		}
		var body putBody
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			s.badRequest(w, r, "put", list, kind, value, fmt.Errorf("body JSON inválido: %w", err))
			return
		}
		ttl, err := time.ParseDuration(body.TTL)
		switch {
		case err != nil || ttl <= 0:
			s.badRequest(w, r, "put", list, kind, value, fmt.Errorf("ttl %q: usa una duración > 0, ej. \"30m\" o \"24h\"", body.TTL))
			return
		case ttl > s.maxTTL:
			s.badRequest(w, r, "put", list, kind, value, fmt.Errorf("ttl %s supera admin.max_ttl (%s): lo permanente va en rules.deny_cidrs del YAML", ttl, s.maxTTL))
			return
		}
		reason := strings.TrimSpace(body.Reason)
		if reason == "" || utf8.RuneCountInString(reason) > acl.MaxReasonLen {
			s.badRequest(w, r, "put", list, kind, value, fmt.Errorf("reason es obligatorio y de máximo %d caracteres", acl.MaxReasonLen))
			return
		}
		e, err := s.store.Put(r.Context(), acl.Entry{
			List: list, Kind: kind, Value: value, Reason: reason, Actor: actor(r),
		}, ttl)
		if err != nil {
			s.unavailable(w, r, "put", list, kind, value, err)
			return
		}
		s.audit(r, "put", list, kind, value, "ok", "ttl", ttl.String(), "reason", reason, "expires_at", e.ExpiresAt)
		writeJSON(w, http.StatusOK, e)
	}
}

func (s *server) handleGet(list acl.List) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kind, value, ok := s.target(w, r, list, "get")
		if !ok {
			return
		}
		e, err := s.store.Get(r.Context(), list, kind, value)
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
		kind, value, ok := s.target(w, r, list, "delete")
		if !ok {
			return
		}
		existed, err := s.store.Delete(r.Context(), list, kind, value)
		if err != nil {
			s.unavailable(w, r, "delete", list, kind, value, err)
			return
		}
		if !existed {
			s.audit(r, "delete", list, kind, value, "not_found")
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no existe o ya expiró"})
			return
		}
		s.audit(r, "delete", list, kind, value, "ok")
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *server) handleList(list acl.List) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := s.store.List(r.Context(), list)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"list": list, "count": len(entries), "entries": entries})
	}
}

func (s *server) handleReload(w http.ResponseWriter, r *http.Request) {
	if s.reload == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "recarga no disponible"})
		return
	}
	before, after, err := s.reload(r.Context())
	if err != nil {
		s.changes.WithLabelValues("reload", "", "", "rejected").Inc()
		s.log.Warn("admin_audit", "action", "reload", "result", "rejected", "actor", actor(r),
			"remote", r.RemoteAddr, "version_activa", after, "err", err)
		// 422: el request está bien formado, pero la config del archivo no se puede aplicar.
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"changed": false, "version": after, "error": err.Error(),
		})
		return
	}
	s.changes.WithLabelValues("reload", "", "", "ok").Inc()
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

// target saca {kind} y {value} del path (r.PathValue, Go 1.22) y los normaliza.
func (s *server) target(w http.ResponseWriter, r *http.Request, list acl.List, action string) (acl.Kind, string, bool) {
	kind := acl.Kind(r.PathValue("kind"))
	value, err := acl.Normalize(list, kind, r.PathValue("value"))
	if err != nil {
		s.badRequest(w, r, action, list, kind, "", err)
		return "", "", false
	}
	return kind, value, true
}

func (s *server) badRequest(w http.ResponseWriter, r *http.Request, action string, list acl.List, kind acl.Kind, value string, err error) {
	if action != "get" {
		s.audit(r, action, list, kind, value, "invalid", "err", err.Error())
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}

// unavailable: si Redis no está, la escritura FALLA y se dice. Para escribir
// somos fail-closed: nunca respondemos "bloqueado" si el bloqueo no quedó.
func (s *server) unavailable(w http.ResponseWriter, r *http.Request, action string, list acl.List, kind acl.Kind, value string, err error) {
	s.audit(r, action, list, kind, value, "error", "err", err.Error())
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "redis no disponible: el cambio NO se aplicó"})
}

// audit deja UNA línea por cambio con quién, qué, desde dónde y el resultado.
// Es el log que te piden en un incidente: "¿quién bloqueó a este cliente?".
func (s *server) audit(r *http.Request, action string, list acl.List, kind acl.Kind, value, result string, extra ...any) {
	s.changes.WithLabelValues(action, string(list), string(kind), result).Inc()
	attrs := append([]any{
		"action", action, "list", list, "kind", kind, "value", value, "result", result,
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
