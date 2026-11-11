package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

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

	App         string   `yaml:"app"`
	RedisAddr   string   `yaml:"redis_addr"`
	Rate        float64  `yaml:"rate"`
	Burst       int      `yaml:"burst"`
	UpstreamURL *url.URL `yaml:"-"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error al leer el archivo de configuración: %w", err)
	}

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
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parseando %s: %w", path, err)
	}
	if v := os.Getenv("GUARDIAN_UPSTREAM"); v != "" {
		cfg.Upstream = v // la variable de entorno gana sobre el YAML
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config inválida: %w", err)
	}

	return cfg, nil

}

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

	return errors.Join(errs...)
}
