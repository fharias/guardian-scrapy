package config

import (
	"fmt"
	"reflect"
	"strings"
	"time"
)

// Reloadable son las rutas YAML que se pueden cambiar en caliente. Todo lo que
// no esté aquí (listen, tls, upstream, timeouts, redis_addr, rate/burst,
// trusted_proxies, events, tracing, reputation, challenge, good_bots,
// ja4.source...) requiere reiniciar el proceso: si cambia, se loguea un warning
// y se ignora.
//
// Regla para agregar algo a esta lista: el valor solo se lee en el camino del
// request a través de un objeto que se reconstruye por completo en cada
// recarga, y no carga estado (conexiones, cachés, listeners) que se perdería.
// Si agregas una ruta aquí, agrégala también en MergeReloadable; el test
// TestMergeReloadableCubreLaLista falla si se te olvida.
var Reloadable = []string{
	"scoring",   // pesos, umbrales y browser_ratio_min
	"rules",     // honeypots, deny_cidrs y allowlists por ruta
	"modes",     // monitor/enforce por ruta
	"ja4.tools", // JA4 conocidos de herramientas
}

// IsReloadable dice si la ruta YAML (ej. "scoring.weights.ua_tool") está
// cubierta por alguna entrada de Reloadable.
func IsReloadable(path string) bool {
	for _, p := range Reloadable {
		if path == p || strings.HasPrefix(path, p+".") {
			return true
		}
	}
	return false
}

// MergeReloadable devuelve una copia de running con SOLO las partes recargables
// tomadas de incoming. Lo que requiere reinicio se queda como está corriendo.
// running nunca se modifica: la copia comparte slices con él, pero nadie
// escribe sobre una Config publicada.
func MergeReloadable(running, incoming *Config) *Config {
	merged := *running
	merged.Scoring = incoming.Scoring
	merged.Rules = incoming.Rules
	merged.Modes = incoming.Modes
	merged.JA4.Tools = incoming.JA4.Tools
	return &merged
}

// Change es un campo que cambió entre dos configs, con su ruta YAML.
type Change struct {
	Path string
	Old  string
	New  string
}

func (c Change) String() string { return fmt.Sprintf("%s: %s -> %s", c.Path, c.Old, c.New) }

// Diff compara dos configs campo por campo usando los tags yaml, así la ruta
// que aparece en el log es la misma que escribes en el archivo.
func Diff(a, b *Config) []Change {
	var out []Change
	diffValue("", reflect.ValueOf(*a), reflect.ValueOf(*b), &out)
	return out
}

// SplitChanges separa los cambios en los que se aplican en caliente y los que
// requieren reinicio.
func SplitChanges(changes []Change) (apply, restart []Change) {
	for _, c := range changes {
		if IsReloadable(c.Path) {
			apply = append(apply, c)
		} else {
			restart = append(restart, c)
		}
	}
	return apply, restart
}

// Paths devuelve solo las rutas, útil para logs compactos.
func Paths(changes []Change) []string {
	out := make([]string, len(changes))
	for i, c := range changes {
		out[i] = c.Path
	}
	return out
}

var durationType = reflect.TypeOf(time.Duration(0))

func diffValue(path string, a, b reflect.Value, out *[]Change) {
	if a.Kind() == reflect.Pointer {
		if a.IsNil() || b.IsNil() {
			if a.IsNil() != b.IsNil() {
				*out = append(*out, change(path, a, b))
			}
			return
		}
		diffValue(path, a.Elem(), b.Elem(), out)
		return
	}
	if a.Kind() != reflect.Struct {
		if !reflect.DeepEqual(a.Interface(), b.Interface()) {
			*out = append(*out, change(path, a, b))
		}
		return
	}
	t := a.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "-" {
			continue // campos derivados, como UpstreamURL
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		child := name
		if path != "" {
			child = path + "." + name
		}
		diffValue(child, a.Field(i), b.Field(i), out)
	}
}

func change(path string, a, b reflect.Value) Change {
	return Change{Path: path, Old: format(path, a), New: format(path, b)}
}

func format(path string, v reflect.Value) string {
	last := path[strings.LastIndex(path, ".")+1:]
	for _, s := range []string{"password", "secret", "token", "key_file"} {
		if strings.Contains(last, s) {
			return "***" // nunca un secreto en el log, ni siquiera en un diff
		}
	}
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return "nil"
	}
	if v.Type() == durationType {
		return time.Duration(v.Int()).String()
	}
	if v.Kind() == reflect.String {
		return fmt.Sprintf("%q", v.String())
	}
	return fmt.Sprintf("%v", v.Interface())
}
