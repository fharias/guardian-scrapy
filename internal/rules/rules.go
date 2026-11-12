package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

type Route struct {
	Prefix     string   `yaml:"prefix"`
	AllowCIDRs []string `yaml:"allow_cidrs"`
}

type Config struct {
	Honeypots []string `yaml:"honeypots"`
	DenyCIDRs []string `yaml:"deny_cidrs"`
	Routes    []Route  `yaml:"routes"`
}

type route struct {
	prefix string
	allow  []netip.Prefix
}
type Engine struct {
	honeypots map[string]struct{}
	deny      []netip.Prefix
	routes    []route
}

func New(cfg Config) (*Engine, error) {
	var errs []error
	e := &Engine{honeypots: make(map[string]struct{}, len(cfg.Honeypots))}
	for _, p := range cfg.Honeypots {
		e.honeypots[p] = struct{}{}
	}
	deny, err := parsePrefixes(cfg.DenyCIDRs)
	if err != nil {
		errs = append(errs, fmt.Errorf("rules.deny_cidrs: %w", err))
	}
	e.deny = deny
	for i, r := range cfg.Routes {
		if !strings.HasPrefix(r.Prefix, "/") {
			errs = append(errs, fmt.Errorf("rules.routes[%d].prefix debe empezar con /", i))
		}
		allow, err := parsePrefixes(r.AllowCIDRs)
		if err != nil {
			errs = append(errs, fmt.Errorf("rules.routes[%d]: %w", i, err))
		}
		e.routes = append(e.routes, route{prefix: r.Prefix, allow: allow})
	}
	return e, errors.Join(errs...)
}

func parsePrefixes(cidrs []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	var errs []error
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, p.Masked())
	}
	return out, errors.Join(errs...)
}
func (e *Engine) IsHoneypot(path string) bool {
	_, ok := e.honeypots[path]
	return ok
}
func (e *Engine) DenyReason(ip netip.Addr, path string) string {
	ip = ip.Unmap()
	if containsIP(e.deny, ip) {
		return "ip_denegada"
	}
	for _, r := range e.routes {
		if strings.HasPrefix(path, r.prefix) && !containsIP(r.allow, ip) {
			return "ruta_privada"
		}
	}
	return ""
}
func containsIP(list []netip.Prefix, ip netip.Addr) bool {
	for _, p := range list {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
