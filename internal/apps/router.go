package apps

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
)

// Route es una app ya armada: su nombre, sus hosts (como vienen en la config)
// y la cadena de middlewares que la atiende.
type Route struct {
	Name    string
	Hosts   []string
	Handler http.Handler
}

// Router es el http.Handler de la cadena protegida: resuelve la app por el
// Host y le pasa el request a la cadena de esa app. Es inmutable; en cada
// recarga se arma uno nuevo y se publica entero en el Snapshot, así que un
// request ve la tabla vieja completa o la nueva completa, nunca una mezcla.
type Router struct {
	table   *Table[*Route]
	names   []string
	def     string
	unknown http.Handler
}

// NewRouter arma la tabla de hosts. def es el nombre de la app que atiende un
// Host que no matchea nada ("" = ninguna). Sin default, ese request va a
// unknown (que debería responder 421).
func NewRouter(routes []Route, def string, unknown http.Handler) (*Router, error) {
	if unknown == nil {
		unknown = http.HandlerFunc(Misdirected)
	}
	var entries []Entry[*Route]
	byName := make(map[string]*Route, len(routes))
	names := make([]string, 0, len(routes))
	for i := range routes {
		r := &routes[i]
		if !ValidName(r.Name) {
			return nil, fmt.Errorf("apps: nombre de app %q inválido", r.Name)
		}
		if r.Handler == nil {
			return nil, fmt.Errorf("apps: la app %q no tiene handler", r.Name)
		}
		if _, dup := byName[r.Name]; dup {
			return nil, fmt.Errorf("apps: app %q repetida", r.Name)
		}
		byName[r.Name] = r
		names = append(names, r.Name)
		for _, h := range r.Hosts {
			host, wild, err := NormalizePattern(h)
			if err != nil {
				return nil, fmt.Errorf("apps: app %q: %w", r.Name, err)
			}
			entries = append(entries, Entry[*Route]{Host: host, Wildcard: wild, Value: r})
		}
	}
	t, err := NewTable(entries)
	if err != nil {
		return nil, fmt.Errorf("apps: %w", err)
	}
	if def != "" {
		r, ok := byName[def]
		if !ok {
			return nil, fmt.Errorf("apps: default %q no es una app", def)
		}
		t = t.WithDefault(r)
	}
	if len(names) == 0 {
		return nil, errors.New("apps: se necesita al menos una app")
	}
	slices.Sort(names)
	return &Router{table: t, names: names, def: def, unknown: unknown}, nil
}

// ServeHTTP: un lookup y a la cadena de la app. Nada más.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, ok := rt.table.Lookup(NormalizeHost(r.Host))
	if !ok {
		rt.unknown.ServeHTTP(w, r)
		return
	}
	route.Handler.ServeHTTP(w, r)
}

// Resolve dice qué app atiende un Host crudo (con puerto, mayúsculas...).
func (rt *Router) Resolve(host string) (string, bool) {
	route, ok := rt.table.Lookup(NormalizeHost(host))
	if !ok {
		return "", false
	}
	return route.Name, true
}

// Names devuelve los nombres de las apps, ordenados. No modifiques el slice.
func (rt *Router) Names() []string { return rt.names }

// Default es la app que atiende hosts desconocidos ("" = ninguna: 421).
func (rt *Router) Default() string { return rt.def }

// Has dice si name es una app de esta tabla.
func (rt *Router) Has(name string) bool {
	_, ok := slices.BinarySearch(rt.names, name)
	return ok
}

// Misdirected responde 421 Misdirected Request (RFC 9110 §15.5.20): "este
// servidor no puede dar una respuesta autoritativa para este host". Es el
// código correcto para un Host que no es nuestro, y con HTTP/2 el navegador
// sabe qué hacer con él: reintenta por una conexión nueva en vez de reusar
// una que coalesció hacia el servidor equivocado.
func Misdirected(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusMisdirectedRequest)
	_, _ = w.Write([]byte("host desconocido\n"))
}
