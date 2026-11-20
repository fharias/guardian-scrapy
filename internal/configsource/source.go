// Package configsource carga la configuración de guardian desde una fuente
// (hoy un archivo; mañana Redis, la Admin API, S3, SSM o AppConfig), la vigila
// y la recarga en caliente sin reiniciar ni cortar requests.
//
// La idea central: cada recarga construye un Snapshot NUEVO e inmutable y lo
// publica con un atomic.Pointer. Un request lee el puntero UNA vez al empezar y
// usa ese snapshot hasta terminar, aunque en la mitad se publique otro.
package configsource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/fharias/guardian-scrapy/internal/config"
)

// Source es de dónde salen los bytes de la configuración.
//
// Separa "traer los bytes" (Fetch) de "avisar que puede haber cambiado"
// (Watch). El Reloader no sabe si detrás hay un archivo, un GET a S3 o un
// SUBSCRIBE de Redis: solo pide bytes y escucha avisos.
type Source interface {
	// Name identifica la fuente en logs, ej. "file:/etc/guardian/guardian.yml".
	Name() string
	// Fetch devuelve el contenido completo y actual de la configuración.
	Fetch(ctx context.Context) ([]byte, error)
	// Watch bloquea hasta que ctx termine y llama notify cada vez que la
	// fuente CREE que algo cambió. Puede avisar de más (eventos repetidos, poll):
	// el Reloader compara el hash del contenido y descarta lo que no cambió.
	Watch(ctx context.Context, notify func(reason string)) error
}

// Version es el hash del contenido: los primeros 12 hex de su SHA-256.
// Dos archivos con los mismos bytes tienen la misma versión, en cualquier
// réplica, sin coordinarse. Es lo que se ve en el log y en guardian_config_info.
func Version(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:12]
}

// LoadInitial trae y valida la config con la que arranca el proceso. Si falla,
// el proceso NO debe arrancar: a diferencia de una recarga, aquí no hay una
// config anterior a la cual volver.
func LoadInitial(ctx context.Context, src Source) (*config.Config, string, error) {
	data, err := src.Fetch(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", src.Name(), err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", src.Name(), err)
	}
	return cfg, Version(data), nil
}
