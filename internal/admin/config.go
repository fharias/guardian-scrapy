// Package admin es la Admin API de guardian: un http.Server aparte, en un
// puerto interno, con token, para crear bloqueos y allowlist (que se propagan
// a todas las réplicas vía Redis) y para pedir una recarga de la config.
package admin

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/fharias/guardian-scrapy/internal/acl"
)

const (
	DefaultListen = "127.0.0.1:9091"
	DefaultMaxTTL = 7 * 24 * time.Hour
	// TokenEnv es la ÚNICA forma de pasar el token. No existe en el YAML:
	// el YAML vive en git y un secreto en git es un secreto filtrado.
	TokenEnv      = "GUARDIAN_ADMIN_TOKEN"
	minTokenBytes = 32
	maxTokens     = 2
)

// Config vive en el YAML bajo la clave `admin`. Todo requiere reinicio: el
// listener y el Store se crean una vez al arrancar.
type Config struct {
	Enabled       bool          `yaml:"enabled"`
	Listen        string        `yaml:"listen"`         // default 127.0.0.1:9091
	MaxTTL        time.Duration `yaml:"max_ttl"`        // TTL máximo de un bloqueo; default 168h
	CacheTTL      time.Duration `yaml:"cache_ttl"`      // caché local de la ACL en cada réplica; default 2s
	StaleTTL      time.Duration `yaml:"stale_ttl"`      // si Redis falla, cuánto sirve lo viejo; default 1m
	LookupTimeout time.Duration `yaml:"lookup_timeout"` // presupuesto del GET por request; default 20ms
}

func (c Config) WithDefaults() Config {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.MaxTTL == 0 {
		c.MaxTTL = DefaultMaxTTL
	}
	if c.CacheTTL == 0 {
		c.CacheTTL = acl.DefaultCacheTTL
	}
	if c.StaleTTL == 0 {
		c.StaleTTL = acl.DefaultStaleTTL
	}
	if c.LookupTimeout == 0 {
		c.LookupTimeout = acl.DefaultLookupTimeout
	}
	return c
}

// Validate espera la config YA con defaults (config.Parse llama WithDefaults antes).
func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	var errs []error
	if c.MaxTTL <= 0 {
		errs = append(errs, errors.New("admin.max_ttl debe ser > 0"))
	}
	if c.CacheTTL < 0 || c.LookupTimeout <= 0 {
		errs = append(errs, errors.New("admin.cache_ttl no puede ser negativo y admin.lookup_timeout debe ser > 0"))
	}
	if c.StaleTTL < c.CacheTTL {
		errs = append(errs, fmt.Errorf("admin.stale_ttl (%s) no puede ser menor que admin.cache_ttl (%s)", c.StaleTTL, c.CacheTTL))
	}
	return errors.Join(errs...)
}

// ACLOptions traduce la config al Store de la ACL.
func (c Config) ACLOptions() acl.Options {
	return acl.Options{CacheTTL: c.CacheTTL, StaleTTL: c.StaleTTL, LookupTimeout: c.LookupTimeout}
}

// Tokens guarda SOLO el SHA-256 de cada token válido. Así, aunque alguien
// vuelque la memoria del struct en un log, no ve el token.
type Tokens struct {
	sums [][sha256.Size]byte
}

// ParseTokens lee GUARDIAN_ADMIN_TOKEN: uno o dos tokens separados por coma.
// Dos sirven para rotar sin cortar: despliegas "nuevo,viejo", cambias los
// clientes al nuevo y luego despliegas solo "nuevo".
func ParseTokens(raw string) (Tokens, error) {
	var t Tokens
	if strings.TrimSpace(raw) == "" {
		return t, fmt.Errorf("admin.enabled es true pero %s está vacío: no arranco una Admin API sin autenticación", TokenEnv)
	}
	parts := strings.Split(raw, ",")
	if len(parts) > maxTokens {
		return t, fmt.Errorf("%s: máximo %d tokens (actual y anterior), recibí %d", TokenEnv, maxTokens, len(parts))
	}
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if len(p) < minTokenBytes {
			// No imprimimos el token, ni siquiera el corto: solo su posición y largo.
			return Tokens{}, fmt.Errorf("%s: el token %d tiene %d caracteres; mínimo %d (genera uno con: openssl rand -hex 32)",
				TokenEnv, i+1, len(p), minTokenBytes)
		}
		t.sums = append(t.sums, sha256.Sum256([]byte(p)))
	}
	return t, nil
}

// Valid compara en tiempo constante. Hashear primero iguala los largos
// (ConstantTimeCompare sale rápido si difieren, y eso filtra el largo del
// token) y recorremos TODOS los tokens sin salir antes: el tiempo de respuesta
// no dice si acertaste el primero o el segundo.
func (t Tokens) Valid(presented string) bool {
	if len(t.sums) == 0 || presented == "" {
		return false
	}
	got := sha256.Sum256([]byte(presented))
	ok := 0
	for _, s := range t.sums {
		ok |= subtle.ConstantTimeCompare(got[:], s[:])
	}
	return ok == 1
}

// String nunca muestra los tokens: si alguien loguea el struct con %v, sale esto.
func (t Tokens) String() string { return fmt.Sprintf("Tokens(%d, redactados)", len(t.sums)) }

// LogValue hace lo mismo para slog: logger.Info("x", "tokens", t) no filtra nada.
func (t Tokens) LogValue() slog.Value { return slog.StringValue(t.String()) }
