package configsource

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// k8sDataLink es el symlink que Kubernetes cambia de forma atómica cuando
// actualiza un ConfigMap montado como volumen. El archivo que lees
// (guardian.yml) es otro symlink que apunta a ..data/guardian.yml y NUNCA
// recibe eventos propios.
const k8sDataLink = "..data"

// FileSource lee la config de un archivo y avisa cuando cambia.
type FileSource struct {
	path string
	poll time.Duration
	log  *slog.Logger
}

// NewFileSource crea la fuente. poll > 0 agrega un chequeo periódico como red
// de seguridad para cuando fsnotify no ve los cambios (algunos bind mounts de
// Docker Desktop, NFS, EFS). poll = 0 lo desactiva.
func NewFileSource(path string, poll time.Duration, log *slog.Logger) *FileSource {
	if log == nil {
		log = slog.Default()
	}
	return &FileSource{path: path, poll: poll, log: log}
}

func (f *FileSource) Name() string { return "file:" + f.path }

func (f *FileSource) Fetch(context.Context) ([]byte, error) { return os.ReadFile(f.path) }

// Watch vigila el DIRECTORIO, no el archivo. Vigilar el archivo directo falla
// en los dos casos más comunes:
//
//   - Editores y herramientas con "atomic save" (vim, VS Code, sed -i, kubectl
//     cp): escriben un temporal y lo renombran encima. El inode viejo, que es
//     el que inotify estaba mirando, desaparece; el nuevo nadie lo vigila.
//   - ConfigMaps de Kubernetes: el archivo es un symlink a ..data/, y lo que
//     cambia es el symlink ..data. El archivo "no se toca".
//
// En el directorio, en cambio, todo eso se ve como CREATE/RENAME/WRITE de un
// nombre. Filtramos por nombre para no recargar cuando cambia un vecino.
func (f *FileSource) Watch(ctx context.Context, notify func(reason string)) error {
	dir, base := filepath.Dir(f.path), filepath.Base(f.path)

	var evs <-chan fsnotify.Event
	var errs <-chan error
	w, err := fsnotify.NewWatcher()
	if err == nil {
		if err = w.Add(dir); err != nil {
			w.Close()
		}
	}
	if err != nil {
		if f.poll <= 0 {
			return errors.Join(errors.New("fsnotify no disponible y poll desactivado: solo recarga con SIGHUP"), err)
		}
		f.log.Warn("config_watch_sin_fsnotify", "dir", dir, "err", err, "poll", f.poll.String())
	} else {
		defer w.Close()
		evs, errs = w.Events, w.Errors
	}

	var tick <-chan time.Time
	if f.poll > 0 {
		t := time.NewTicker(f.poll)
		defer t.Stop()
		tick = t.C
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-evs:
			if !ok {
				evs = nil
				continue
			}
			if relevant(ev, base) {
				notify("fsnotify " + ev.Op.String())
			}
		case err, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			f.log.Warn("config_watch_error", "err", err)
		case <-tick:
			notify("poll")
		}
	}
}

// relevant decide si un evento del directorio nos importa.
func relevant(ev fsnotify.Event, base string) bool {
	if ev.Op == fsnotify.Chmod {
		return false // cambiar permisos o el atime no cambia el contenido
	}
	name := filepath.Base(ev.Name)
	return name == base || name == k8sDataLink
}
