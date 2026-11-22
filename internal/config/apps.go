package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/fharias/guardian-scrapy/internal/apps"
	"github.com/fharias/guardian-scrapy/internal/policy"
	"github.com/fharias/guardian-scrapy/internal/rules"
	"github.com/fharias/guardian-scrapy/internal/scoring"
)

// AppConfig es una entrada de la sección `apps`: un grupo de hosts con su
// propio upstream y su propia política. Toda sección que no pongas (nil o 0)
// se HEREDA completa del nivel superior del YAML.
//
// La herencia es por sección, no campo por campo: si pones `scoring` en una
// app, esa app usa SOLO ese scoring (pesos y umbrales) y no mezcla nada del
// global. Así el bloque de la app se lee solo y no hay que adivinar qué valor
// salió de dónde.
type AppConfig struct {
	Name     string          `yaml:"name"`
	Hosts    []string        `yaml:"hosts"`    // exactos o *.dominio; sin puerto
	Upstream string          `yaml:"upstream"` // "" = el upstream global
	Rate     float64         `yaml:"rate"`     // 0 = el rate global
	Burst    int             `yaml:"burst"`    // 0 = el burst global
	Scoring  *scoring.Config `yaml:"scoring"`
	Rules    *rules.Config   `yaml:"rules"`
	Modes    *policy.Config  `yaml:"modes"`
}

// App es una app ya resuelta: con la herencia aplicada y el upstream
// parseado. Es lo que usa main para armar la cadena de cada app.
type App struct {
	Name        string
	Hosts       []string // como vienen en el YAML; apps.NewRouter los normaliza
	Upstream    string
	UpstreamURL *url.URL
	Rate        float64
	Burst       int
	Scoring     scoring.Config
	Rules       rules.Config
	Modes       policy.Config
}

// MultiApp dice si la config usa la sección apps. Sin apps, guardian se porta
// como antes: una sola app (el campo `app`) que atiende cualquier Host.
func (c *Config) MultiApp() bool { return len(c.Apps) > 0 }

// EffectiveDefaultApp es la app que atiende un Host desconocido. En modo
// legacy es la única app; en multi-app es default_app, que puede ser "" (y
// entonces un Host desconocido recibe 421).
func (c *Config) EffectiveDefaultApp() string {
	if !c.MultiApp() {
		return c.App
	}
	return c.DefaultApp
}

// ResolveApps devuelve las apps efectivas, con la herencia aplicada. Asume
// una config ya validada (validate llama a validateApps).
func (c *Config) ResolveApps() []App {
	if !c.MultiApp() {
		return []App{{
			Name:        c.App,
			Hosts:       nil, // sin hosts: la atiende todo por ser el default
			Upstream:    c.Upstream,
			UpstreamURL: c.UpstreamURL,
			Rate:        c.Rate,
			Burst:       c.Burst,
			Scoring:     c.Scoring,
			Rules:       c.Rules,
			Modes:       c.Modes,
		}}
	}
	out := make([]App, 0, len(c.Apps))
	for _, a := range c.Apps {
		r := App{
			Name: a.Name, Hosts: a.Hosts,
			Upstream: c.Upstream, UpstreamURL: c.UpstreamURL,
			Rate: c.Rate, Burst: c.Burst,
			Scoring: c.Scoring, Rules: c.Rules, Modes: c.Modes,
		}
		if a.Upstream != "" {
			r.Upstream = a.Upstream
			r.UpstreamURL, _ = parseUpstream(a.Upstream) // ya validado
		}
		if a.Rate > 0 {
			r.Rate = a.Rate
		}
		if a.Burst > 0 {
			r.Burst = a.Burst
		}
		if a.Scoring != nil {
			r.Scoring = *a.Scoring
		}
		if a.Rules != nil {
			r.Rules = *a.Rules
		}
		if a.Modes != nil {
			r.Modes = *a.Modes
		}
		out = append(out, r)
	}
	return out
}

// AppNames devuelve los nombres de las apps efectivas, en el orden del YAML.
func (c *Config) AppNames() []string {
	if !c.MultiApp() {
		return []string{c.App}
	}
	names := make([]string, len(c.Apps))
	for i, a := range c.Apps {
		names[i] = a.Name
	}
	return names
}

func parseUpstream(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("%q debe ser una URL completa, ej. http://host:puerto", raw)
	}
	return u, nil
}

// validateApps revisa todo lo que puede romper el ruteo por Host ANTES de
// publicar la config: nombres que no sirven como prefijo de Redis o label de
// Prometheus, el mismo host en dos apps, comodines mal escritos, un
// default_app que no existe... Corre al arrancar y en cada recarga.
func (c *Config) validateApps() []error {
	var errs []error
	if !apps.ValidName(c.App) {
		errs = append(errs, fmt.Errorf("app %q: usa [a-z0-9-], máximo %d, sin ':' ni llaves (va en las llaves de Redis y en los labels)", c.App, apps.MaxNameLen))
	}
	if !c.MultiApp() {
		if c.DefaultApp != "" {
			errs = append(errs, errors.New("default_app sin apps: en modo de una sola app usa el campo app"))
		}
		return errs
	}

	names := make(map[string]bool, len(c.Apps))
	hostOwner := make(map[string]string) // host normalizado ("*" delante si es comodín) -> app
	for i, a := range c.Apps {
		where := fmt.Sprintf("apps[%d]", i)
		if a.Name != "" {
			where = fmt.Sprintf("apps[%s]", a.Name)
		}
		switch {
		case !apps.ValidName(a.Name):
			errs = append(errs, fmt.Errorf("%s: name %q inválido: usa [a-z0-9-], máximo %d", where, a.Name, apps.MaxNameLen))
		case names[a.Name]:
			errs = append(errs, fmt.Errorf("%s: name repetido", where))
		}
		names[a.Name] = true

		if len(a.Hosts) == 0 && a.Name != c.DefaultApp {
			errs = append(errs, fmt.Errorf("%s: sin hosts nunca recibiría tráfico (solo default_app puede ir sin hosts)", where))
		}
		for _, h := range a.Hosts {
			host, wild, err := apps.NormalizePattern(h)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s.hosts: %w", where, err))
				continue
			}
			k := host
			if wild {
				k = "*" + host
			}
			if owner, dup := hostOwner[k]; dup {
				errs = append(errs, fmt.Errorf("%s.hosts: %q ya es de apps[%s]: un host solo puede ser de una app", where, h, owner))
				continue
			}
			hostOwner[k] = a.Name
		}

		switch {
		case a.Upstream != "":
			if _, err := parseUpstream(a.Upstream); err != nil {
				errs = append(errs, fmt.Errorf("%s.upstream: %w", where, err))
			}
		case c.Upstream == "":
			errs = append(errs, fmt.Errorf("%s: sin upstream propio y sin upstream global", where))
		}
		if a.Rate < 0 || a.Burst < 0 {
			errs = append(errs, fmt.Errorf("%s: rate y burst deben ser > 0 (o 0 para heredar)", where))
		}
		// Solo se validan las secciones PROPIAS de la app. Las heredadas se
		// validan donde siempre: si el global está mal, falla igual que antes.
		if a.Scoring != nil {
			if err := a.Scoring.Validate(); err != nil {
				errs = append(errs, fmt.Errorf("%s.%w", where, err))
			}
		}
		if a.Rules != nil {
			if _, err := rules.New(*a.Rules); err != nil {
				errs = append(errs, fmt.Errorf("%s.%w", where, err))
			}
		}
		if a.Modes != nil {
			if _, err := policy.New(*a.Modes); err != nil {
				errs = append(errs, fmt.Errorf("%s.modes: %w", where, err))
			}
		}
	}
	if c.DefaultApp != "" && !names[c.DefaultApp] {
		errs = append(errs, fmt.Errorf("default_app %q no está en apps (tienes: %s)", c.DefaultApp, strings.Join(c.AppNames(), ", ")))
	}
	return errs
}
