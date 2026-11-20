package configsource

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeAtomic hace lo que vim, VS Code o sed -i: escribe un temporal y lo
// renombra encima. El archivo final es un inode NUEVO.
func writeAtomic(t *testing.T, path, content string) {
	t.Helper()
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	write(t, tmp, content)
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// k8sLayout arma lo que hace el kubelet con un ConfigMap montado:
// guardian.yml -> ..data/guardian.yml, ..data -> ..<timestamp>/
func k8sLayout(t *testing.T, dir, stamp, content string) {
	t.Helper()
	real := filepath.Join(dir, stamp)
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(real, "guardian.yml"), content)
	tmpLink := filepath.Join(dir, "..data_tmp")
	if err := os.Symlink(stamp, tmpLink); err != nil {
		t.Fatal(err)
	}
	// El cambio atómico: rename del symlink temporal encima de ..data.
	if err := os.Rename(tmpLink, filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
}

func TestFileSourceDetectaFormasDeGuardar(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(t *testing.T, dir string)
		act        func(t *testing.T, dir string)
		wantNotify bool
	}{
		{
			name:       "escritura en el sitio",
			setup:      func(t *testing.T, dir string) { write(t, filepath.Join(dir, "guardian.yml"), "a") },
			act:        func(t *testing.T, dir string) { write(t, filepath.Join(dir, "guardian.yml"), "b") },
			wantNotify: true,
		},
		{
			name:       "atomic save: temporal + rename",
			setup:      func(t *testing.T, dir string) { write(t, filepath.Join(dir, "guardian.yml"), "a") },
			act:        func(t *testing.T, dir string) { writeAtomic(t, filepath.Join(dir, "guardian.yml"), "b") },
			wantNotify: true,
		},
		{
			name: "ConfigMap de Kubernetes: cambia el symlink ..data",
			setup: func(t *testing.T, dir string) {
				if runtime.GOOS != "linux" {
					t.Skip("kqueue en macOS/BSD no emite eventos al reemplazar un symlink a directorio; Kubernetes corre sobre inotify en Linux")
				}
				k8sLayout(t, dir, "..2026_11_19_08_00_00.1", "a")
				if err := os.Symlink("..data/guardian.yml", filepath.Join(dir, "guardian.yml")); err != nil {
					t.Fatal(err)
				}
			},
			act:        func(t *testing.T, dir string) { k8sLayout(t, dir, "..2026_11_19_08_05_00.2", "b") },
			wantNotify: true,
		},
		{
			name:       "otro archivo del directorio no dispara",
			setup:      func(t *testing.T, dir string) { write(t, filepath.Join(dir, "guardian.yml"), "a") },
			act:        func(t *testing.T, dir string) { write(t, filepath.Join(dir, "guardian.sqs.yml"), "x") },
			wantNotify: false,
		},
		{
			name:  "chmod no dispara",
			setup: func(t *testing.T, dir string) { write(t, filepath.Join(dir, "guardian.yml"), "a") },
			act: func(t *testing.T, dir string) {
				if err := os.Chmod(filepath.Join(dir, "guardian.yml"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantNotify: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			c.setup(t, dir)
			path := filepath.Join(dir, "guardian.yml")
			src := NewFileSource(path, 0, quietLogger())

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			got := make(chan string, 16)
			go src.Watch(ctx, func(reason string) { got <- reason })
			time.Sleep(150 * time.Millisecond) // que el watcher quede registrado

			c.act(t, dir)

			select {
			case reason := <-got:
				if !c.wantNotify {
					t.Fatalf("avisó (%s) y no debía", reason)
				}
				data, err := src.Fetch(ctx)
				if err != nil || string(data) != "b" {
					t.Fatalf("Fetch = %q, %v; want \"b\"", data, err)
				}
			case <-time.After(400 * time.Millisecond):
				if c.wantNotify {
					t.Fatal("no avisó")
				}
			}
		})
	}
}

func TestFileSourcePollComoRedDeSeguridad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardian.yml")
	write(t, path, "a")
	src := NewFileSource(path, 20*time.Millisecond, quietLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 16)
	go src.Watch(ctx, func(reason string) { got <- reason })
	deadline := time.After(time.Second)
	for {
		select {
		case reason := <-got:
			if reason == "poll" {
				return
			}
		case <-deadline:
			t.Fatal("el poll nunca avisó")
		}
	}
}
