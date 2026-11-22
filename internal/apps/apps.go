// Package apps resuelve a qué aplicación pertenece un request según su header
// Host. Una "app" es un conjunto de hosts que comparten upstream y política
// (modo, scoring, rate limit, rules) y un prefijo propio en Redis: gd:<app>:.
//
// La resolución corre en CADA request, así que está pensada para costar un
// map lookup y cero allocations en el caso normal (host en minúsculas, con o
// sin puerto). Todo lo caro (IDNA, validación, armar los maps) pasa al cargar
// la config, una vez por recarga.
package apps

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// MaxNameLen es el largo máximo de un nombre de app. El nombre termina en
// llaves de Redis, en el label app de Prometheus y en una URL de la Admin API:
// corto y predecible en los tres lados.
const MaxNameLen = 32

// maxHostLen es el largo máximo de un nombre DNS (RFC 1035). Un Host más largo
// no puede ser de ninguna app: se trata como desconocido sin buscarlo.
const maxHostLen = 253

// ValidName dice si name sirve como nombre de app: [a-z0-9-], empieza con
// letra o dígito, máximo MaxNameLen. Sin ':' (rompería el formato gd:<app>:),
// sin '{' ni '}' (cambiarían el hash tag de Redis Cluster), sin '/' (rompería
// /v1/apps/{app}/...), sin mayúsculas (dos series de Prometheus para lo mismo).
func ValidName(name string) bool {
	if name == "" || len(name) > MaxNameLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && i > 0:
		default:
			return false
		}
	}
	return true
}

// NormalizeHost deja el header Host de un request en la forma con la que se
// arman los maps: sin puerto, sin punto final y en minúsculas. No valida: un
// Host basura simplemente no matchea nada.
//
//	"Shop.Example:8080" -> "shop.example"
//	"shop.example."     -> "shop.example"
//	"[2001:db8::1]:443" -> "2001:db8::1"
//
// Cero allocations si el Host ya viene en minúsculas, que es lo normal:
// los navegadores y los SDK lo mandan así. Con mayúsculas, una allocation.
func NormalizeHost(host string) string {
	if strings.HasPrefix(host, "[") {
		// IPv6 literal: "[::1]" o "[::1]:8080".
		end := strings.IndexByte(host, ']')
		if end < 0 {
			return ""
		}
		host = host[1:end]
	} else if i := strings.LastIndexByte(host, ':'); i >= 0 && strings.IndexByte(host, ':') == i {
		// Un solo ':' es host:puerto. Varios ':' sin corchetes sería un IPv6
		// mal formado: se deja tal cual y no va a matchear.
		host = host[:i]
	}
	host = strings.TrimSuffix(host, ".")
	return lower(host)
}

// lower es strings.ToLower con un camino rápido explícito: si no hay ninguna
// mayúscula ASCII devuelve el mismo string sin copiarlo.
func lower(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || c >= 0x80 {
			return strings.ToLower(s)
		}
	}
	return s
}

// NormalizePattern valida y deja en forma canónica un host de la config.
// Acepta un host exacto ("shop.example", "127.0.0.1", "::1") o un comodín
// "*.shop.example". Devuelve el host canónico y si es comodín; para un
// comodín, el valor devuelto es el sufijo CON el punto: ".shop.example".
//
// Los nombres internacionales se convierten a punycode con IDNA (UTS #46):
// "tienda-café.example" -> "xn--tienda-caf-k7a.example". El navegador manda
// el Host ya en punycode, así que el map tiene que guardarlo igual. Esto pasa
// solo al cargar la config: el camino del request nunca llama a IDNA.
func NormalizePattern(p string) (host string, wildcard bool, err error) {
	orig := p
	p = strings.TrimSpace(p)
	if p == "" {
		return "", false, errors.New("host vacío")
	}
	if strings.ContainsAny(p, "/ ?#@") {
		return "", false, fmt.Errorf("host %q: solo el nombre, sin esquema, path ni credenciales", orig)
	}
	if rest, ok := strings.CutPrefix(p, "*."); ok {
		wildcard = true
		p = rest
	}
	if strings.Contains(p, "*") {
		return "", false, fmt.Errorf("host %q: el comodín solo va al principio, como *.shop.example", orig)
	}
	// Una IP literal (con o sin corchetes) va tal cual; no tiene sentido un
	// comodín sobre una IP.
	if a, perr := netip.ParseAddr(strings.Trim(p, "[]")); perr == nil {
		if wildcard {
			return "", false, fmt.Errorf("host %q: un comodín no aplica a una IP", orig)
		}
		if a.Zone() != "" {
			return "", false, fmt.Errorf("host %q: una IP con zona no puede venir en un Host", orig)
		}
		return a.String(), false, nil
	}
	if strings.Contains(p, ":") {
		return "", false, fmt.Errorf("host %q: sin puerto; el puerto se ignora al resolver", orig)
	}
	p = strings.TrimSuffix(p, ".")
	ascii, err := hostProfile.ToASCII(p)
	if err != nil {
		return "", false, fmt.Errorf("host %q: no es un nombre DNS válido: %v", orig, err)
	}
	if ascii == "" || len(ascii) > maxHostLen {
		return "", false, fmt.Errorf("host %q: largo inválido", orig)
	}
	if wildcard {
		if !strings.Contains(ascii, ".") {
			// *.com o *.local: atraparía un TLD entero. Casi siempre es un error.
			return "", false, fmt.Errorf("host %q: el comodín necesita al menos dos etiquetas, como *.shop.example", orig)
		}
		return "." + ascii, true, nil
	}
	return ascii, false, nil
}

// hostProfile es idna.Lookup (mapeo UTS #46 + reglas STD3: solo letras,
// dígitos y guiones) más VerifyDNSLength, que rechaza etiquetas vacías como
// "a..b" y etiquetas de más de 63 bytes.
var hostProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.Transitional(false),
	idna.VerifyDNSLength(true),
)

// Table resuelve un host normalizado a un valor de tipo T. Es inmutable: se
// arma completa con NewTable y nunca se modifica, así que se puede leer desde
// todos los goroutines sin locks (vive dentro del Snapshot de la config).
//
// Precedencia: host exacto > comodín más específico (el sufijo más largo) >
// default. Un comodín "*.shop.example" cubre a.shop.example y a.b.shop.example,
// pero NO a shop.example: si quieres el apex, lístalo aparte.
type Table[T any] struct {
	exact  map[string]T
	suffix map[string]T // llave ".shop.example"
	def    T
	hasDef bool
}

// Entry es un host ya normalizado (de NormalizePattern) y su valor.
type Entry[T any] struct {
	Host     string // "shop.example" o, si Wildcard, ".shop.example"
	Wildcard bool
	Value    T
}

// NewTable arma la tabla. Un host repetido es un error: la validación de la
// config ya lo atrapa con un mensaje mejor, esto es la red de seguridad.
func NewTable[T any](entries []Entry[T]) (*Table[T], error) {
	t := &Table[T]{exact: make(map[string]T), suffix: make(map[string]T)}
	for _, e := range entries {
		m := t.exact
		if e.Wildcard {
			m = t.suffix
		}
		if _, dup := m[e.Host]; dup {
			return nil, fmt.Errorf("host %q repetido", e.Host)
		}
		m[e.Host] = e.Value
	}
	return t, nil
}

// WithDefault devuelve una copia de la tabla que, cuando nada matchea,
// responde def en vez de "no encontrado".
func (t *Table[T]) WithDefault(def T) *Table[T] {
	c := *t
	c.def, c.hasDef = def, true
	return &c
}

// Lookup busca un host YA normalizado (NormalizeHost). Un lookup en exact y,
// si falla, uno por cada punto del host recorriendo de izquierda a derecha:
// el primer sufijo que aparece es el más largo, o sea, el comodín más
// específico. Substrings de host: cero allocations.
func (t *Table[T]) Lookup(host string) (T, bool) {
	if len(host) <= maxHostLen {
		if v, ok := t.exact[host]; ok {
			return v, true
		}
		if len(t.suffix) > 0 {
			for i := 0; i < len(host); i++ {
				if host[i] == '.' {
					if v, ok := t.suffix[host[i:]]; ok {
						return v, true
					}
				}
			}
		}
	}
	return t.def, t.hasDef
}
