package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type Mode string

const (
	Monitor Mode = "monitor"
	Enforce Mode = "enforce"
)

func (m Mode) valid() bool { return m == Monitor || m == Enforce }

type RouteMode struct {
	Prefix string `yaml:"prefix"`
	Mode   Mode   `yaml:"mode"`
}

type Config struct {
	Default Mode        `yaml:"default"`
	Routes  []RouteMode `yaml:"routes"`
}

type Modes struct {
	def    Mode
	routes []RouteMode
}

func New(cfg Config) (*Modes, error) {
	var errs []error
	if !cfg.Default.valid() {
		errs = append(errs, fmt.Errorf("modes.default es obligatorio y debe ser monitor o enforce (tiene %q)", cfg.Default))
	}
	seen := make(map[string]bool)
	routes := make([]RouteMode, 0, len(cfg.Routes))
	for i, r := range cfg.Routes {
		if !strings.HasPrefix(r.Prefix, "/") {
			errs = append(errs, fmt.Errorf("modes.routes[%d].prefix debe empezar con /", i))
		}
		if !r.Mode.valid() {
			errs = append(errs, fmt.Errorf("modes.routes[%d].mode debe ser monitor o enforce (tiene %q)", i, r.Mode))
		}
		p := strings.TrimSuffix(r.Prefix, "/")
		if p == "" {
			p = "/"
		}
		if seen[p] {
			errs = append(errs, fmt.Errorf("modes.routes[%d]: prefix %q repetido", i, r.Prefix))
		}
		seen[p] = true
		routes = append(routes, RouteMode{Prefix: p, Mode: r.Mode})
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	sort.Slice(routes, func(i, j int) bool { return len(routes[i].Prefix) > len(routes[j].Prefix) })
	return &Modes{def: cfg.Default, routes: routes}, nil
}

func (m *Modes) For(path string) Mode {
	for _, r := range m.routes {
		if matches(r.Prefix, path) {
			return r.Mode
		}
	}
	return m.def
}

func matches(prefix, path string) bool {
	if prefix == "/" {
		return true
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

// Route devuelve el prefix configurado que gana para este path
// (el mismo que usa For) o "default" si ninguno aplica.
// Sirve como label de métricas: su cardinalidad está acotada por el YAML.
func (m *Modes) Route(path string) string {
	for _, r := range m.routes {
		if matches(r.Prefix, path) {
			return r.Prefix
		}
	}
	return "default"
}
