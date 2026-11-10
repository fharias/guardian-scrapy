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
	PreserveHost      bool          `yaml:"preserve_host"`

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
		PreserveHost:      true,
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
	return errors.Join(errs...)
}
