package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/fharias/guardian-scrapy/internal/admin"
	"github.com/fharias/guardian-scrapy/internal/clientip"
	"github.com/fharias/guardian-scrapy/internal/events"
	"github.com/fharias/guardian-scrapy/internal/fingerprint"
	"github.com/fharias/guardian-scrapy/internal/goodbot"
	"github.com/fharias/guardian-scrapy/internal/policy"
	"github.com/fharias/guardian-scrapy/internal/reputation"
	"github.com/fharias/guardian-scrapy/internal/rules"
	"github.com/fharias/guardian-scrapy/internal/scoring"
	"github.com/fharias/guardian-scrapy/internal/tracing"
	"gopkg.in/yaml.v3"
)

type ChallengeConfig struct {
	Difficulty int           `yaml:"difficulty"`
	TTL        time.Duration `yaml:"ttl"`
	PassTTL    time.Duration `yaml:"pass_ttl"`
}

type Config struct {
	Listen            string        `yaml:"listen"`
	Upstream          string        `yaml:"upstream"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	ShutdownTimeout   time.Duration `yaml:"shutdown_timeout"`
	DrainDelay        time.Duration `yaml:"drain_delay"`
	PreserveHost      bool          `yaml:"preserve_host"`
	HoneypotPaths     []string      `yaml:"honeypot_paths"`

	App                 string                `yaml:"app"`
	RedisAddr           string                `yaml:"redis_addr"`
	Rate                float64               `yaml:"rate"`
	Burst               int                   `yaml:"burst"`
	TrustedProxies      []string              `yaml:"trusted_proxies"`
	XForwardedForHeader string                `yaml:"x_forwarded_for_header"`
	ProxyProtocol       bool                  `yaml:"proxy_protocol"`
	Scoring             scoring.Config        `yaml:"scoring"`
	Rules               rules.Config          `yaml:"rules"`
	GoodBots            []goodbot.Bot         `yaml:"good_bots"`
	Challenge           ChallengeConfig       `yaml:"challenge"`
	Modes               policy.Config         `yaml:"modes"`
	TLS                 TLSConfig             `yaml:"tls"`
	JA4                 fingerprint.JA4Config `yaml:"ja4"`
	Tracing             tracing.Config        `yaml:"tracing"`
	Events              events.Config         `yaml:"events"`
	Reputation          reputation.Config     `yaml:"reputation"`
	Admin               admin.Config          `yaml:"admin"`
	UpstreamURL         *url.URL              `yaml:"-"`
}

type TLSConfig struct {
	Listen   string `yaml:"listen"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

func (t TLSConfig) Enabled() bool {
	return t.Listen != "" || t.CertFile != "" || t.KeyFile != ""
}
func (t TLSConfig) validate() error {
	if !t.Enabled() {
		return nil
	}
	var errs []error
	if t.Listen == "" {
		errs = append(errs, errors.New("tls.listen es obligatorio si habilitas TLS"))
	}
	if t.CertFile == "" {
		errs = append(errs, errors.New("tls.cert_file es obligatorio si habilitas TLS"))
	}
	if t.KeyFile == "" {
		errs = append(errs, errors.New("tls.key_file es obligatorio si habilitas TLS"))
	}
	return errors.Join(errs...)
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error al leer el archivo de configuración: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse convierte bytes YAML en una Config con defaults aplicados y validada.
// No sabe de dónde salieron los bytes (archivo, S3, SSM, Redis): eso es
// problema de la fuente. Así la misma validación protege el arranque y cada
// recarga en caliente.
func Parse(data []byte) (*Config, error) {
	cfg := &Config{
		Listen:            ":8080",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       10 * time.Second,
		ShutdownTimeout:   10 * time.Second,
		DrainDelay:        10 * time.Second,
		RedisAddr:         "localhost:6379",
		App:               "shop",
		Rate:              1,
		Burst:             10,
		JA4:               fingerprint.JA4Config{Source: fingerprint.SourceTLS},
		Events:            events.Config{Sink: events.SinkLog, Buffer: events.DefaultBuffer},
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parseando YAML: %w", err)
	}
	if v := os.Getenv("GUARDIAN_UPSTREAM"); v != "" {
		cfg.Upstream = v // la variable de entorno gana sobre el YAML
	}
	cfg.Events = cfg.Events.WithDefaults()
	cfg.Reputation = cfg.Reputation.WithDefaults()
	cfg.Admin = cfg.Admin.WithDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config inválida: %w", err)
	}

	return cfg, nil
}

// Validate expone la validación completa. La usa la recarga en caliente para
// revisar la config YA mezclada (lo recargable del archivo nuevo + lo que
// requiere reinicio de la config activa) antes de aplicarla.
func (c *Config) Validate() error { return c.validate() }

func (c *Config) validate() error {
	var errs []error
	if c.Upstream == "" {
		errs = append(errs, errors.New("upstream es obligatorio"))
	} else {
		u, err := url.Parse(c.Upstream)
		if err != nil || u.Scheme == "" || u.Host == "" {
			errs = append(errs, fmt.Errorf("upstream %q debe ser una URL completa, ej. http://host:puerto", c.Upstream))
		} else {
			c.UpstreamURL = u
		}
	}
	if c.ReadHeaderTimeout <= 0 {
		errs = append(errs, errors.New("read_header_timeout debe ser mayor que 0"))
	}

	if c.ShutdownTimeout+c.DrainDelay >= 30*time.Second {
		errs = append(errs, fmt.Errorf("shutdown_timeout + drain_delay (%s) debe ser menor que 30s, el límite de ECS", c.ShutdownTimeout+c.DrainDelay))
	}

	if c.WriteTimeout > c.ShutdownTimeout {
		errs = append(errs, fmt.Errorf("write_timeout (%s) no puede ser mayor que shutdown_timeout (%s)", c.WriteTimeout, c.ShutdownTimeout))
	}

	if c.Rate <= 0 {
		errs = append(errs, errors.New("rate debe ser mayor que 0"))
	}
	if c.Burst <= 0 {
		errs = append(errs, errors.New("burst debe ser mayor que 1"))
	}

	if len(c.TrustedProxies) > 0 {
		_, err := clientip.New(c.TrustedProxies, c.XForwardedForHeader)
		if err != nil {
			errs = append(errs, fmt.Errorf("error al crear el resolver de clientip: %w", err))
		}
	}

	// valida en `validate` que `difficulty` esté entre 8 y 24.
	if c.Challenge.Difficulty < 8 || c.Challenge.Difficulty > 24 {
		errs = append(errs, errors.New("difficulty debe estar entre 8 y 24"))
	}

	if _, err := policy.New(c.Modes); err != nil {
		errs = append(errs, err)
	}

	if c.JA4.Source == fingerprint.SourceCloudFront && len(c.TrustedProxies) == 0 {
		errs = append(errs, errors.New("ja4.source: cloudfront requiere trusted_proxies: sin proxies confiables nunca se creería el header"))
	}

	if err := c.TLS.validate(); err != nil {
		errs = append(errs, err)
	}
	if _, err := fingerprint.NewJA4Policy(c.JA4); err != nil {
		errs = append(errs, err)
	}
	if err := c.Tracing.Validate(); err != nil {
		errs = append(errs, err)
	}
	if err := c.Events.Validate(); err != nil {
		errs = append(errs, err)
	}
	if err := c.Reputation.Validate(); err != nil {
		errs = append(errs, err)
	}
	if c.Reputation.Enabled && c.Scoring.Weights.JA4Reputation <= 0 {
		errs = append(errs, errors.New("reputation.enabled es true pero scoring.weights.ja4_reputation es 0: la señal se calcularía y nunca sumaría"))
	}
	if err := c.Admin.Validate(); err != nil {
		errs = append(errs, err)
	}
	if c.Admin.Enabled {
		for _, other := range []string{c.Listen, c.TLS.Listen, ":2112"} {
			if other != "" && samePort(c.Admin.Listen, other) {
				errs = append(errs, fmt.Errorf("admin.listen (%s) choca con %s: la Admin API va en su propio puerto", c.Admin.Listen, other))
			}
		}
	}
	return errors.Join(errs...)
}

// samePort compara solo el puerto: "127.0.0.1:8080" y ":8080" chocan, porque
// ":8080" escucha en todas las interfaces, incluida 127.0.0.1.
func samePort(a, b string) bool {
	_, pa, errA := net.SplitHostPort(a)
	_, pb, errB := net.SplitHostPort(b)
	return errA == nil && errB == nil && pa == pb
}
