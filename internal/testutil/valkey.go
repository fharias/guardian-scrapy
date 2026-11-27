//go:build integration

// Package testutil tiene helpers para tests de integración. Lleva el build
// tag integration para que testcontainers (y su árbol de dependencias de
// Docker) nunca entre en un build ni en un go test normal.
package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// ValkeyImage es la misma versión mayor que corre en ElastiCache.
const ValkeyImage = "valkey/valkey:8"

// Valkey levanta un contenedor de Valkey para este test y devuelve su
// host:port. El contenedor se destruye solo al terminar el test (t.Cleanup).
func Valkey(t testing.TB) (addr string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        ValkeyImage,
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections"),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("no pude levantar valkey (¿Docker está encendido?): %v", err)
	}
	t.Cleanup(func() {
		if err := c.Terminate(context.Background()); err != nil {
			t.Logf("terminate valkey: %v", err)
		}
	})

	addr, err = c.Endpoint(ctx, "")
	if err != nil {
		t.Fatalf("endpoint de valkey: %v", err)
	}
	return addr
}
