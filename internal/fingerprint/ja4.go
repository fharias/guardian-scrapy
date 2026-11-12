package fingerprint

import (
	"errors"
	"fmt"
	"strings"
)

// KnownJA4 es un JA4 que TÚ mediste y sabes a qué herramienta pertenece
// (por ejemplo, el de tu curl). El JA4 de curl cambia con la versión y con la
// librería TLS con la que se compiló, por eso NO lo traemos quemado en el código.
type KnownJA4 struct {
	Name string `yaml:"name"`
	JA4  string `yaml:"ja4"`
}

type JA4Config struct {
	Tools []KnownJA4 `yaml:"tools"`
}

// JA4Policy decide si el JA4 contradice al User-Agent.
type JA4Policy struct {
	tools map[string]string // JA4 -> nombre de la herramienta
}

func NewJA4Policy(cfg JA4Config) (*JA4Policy, error) {
	p := &JA4Policy{tools: make(map[string]string, len(cfg.Tools))}
	var errs []error
	for i, t := range cfg.Tools {
		if t.Name == "" {
			errs = append(errs, fmt.Errorf("ja4.tools[%d].name es obligatorio", i))
		}
		if !validJA4(t.JA4) {
			errs = append(errs, fmt.Errorf("ja4.tools[%d].ja4 %q no tiene el formato 10_12_12", i, t.JA4))
			continue
		}
		if _, dup := p.tools[t.JA4]; dup {
			errs = append(errs, fmt.Errorf("ja4.tools[%d]: JA4 repetido %q", i, t.JA4))
			continue
		}
		p.tools[t.JA4] = t.Name
	}
	return p, errors.Join(errs...)
}

// validJA4 revisa la forma A_B_C con largos 10, 12 y 12.
func validJA4(s string) bool {
	parts := strings.Split(s, "_")
	return len(parts) == 3 && len(parts[0]) == 10 && len(parts[1]) == 12 && len(parts[2]) == 12
}

// Mismatch devuelve (nombre, true) si el UA dice ser un navegador pero el
// JA4 es de una herramienta conocida. Si no hay JA4 (HTTP plano) o no hay
// política, no opina: callar es mejor que acusar sin evidencia.
func (p *JA4Policy) Mismatch(userAgent, ja4 string) (string, bool) {
	if p == nil || ja4 == "" || !claimsBrowser(userAgent) {
		return "", false
	}
	name, ok := p.tools[ja4]
	return name, ok
}

// claimsBrowser: todos los navegadores modernos empiezan con "Mozilla/".
func claimsBrowser(ua string) bool {
	return strings.HasPrefix(ua, "Mozilla/")
}
