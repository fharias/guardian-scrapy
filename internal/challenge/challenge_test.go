package challenge

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func newKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestFlujoCompleto(t *testing.T) {
	kr, err := ParseKeyring("k1:" + newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	s := NewService(kr, 12, time.Minute, time.Hour)

	seed, tok, err := s.NewChallenge("203.0.113.7", "fpA")
	if err != nil {
		t.Fatal(err)
	}
	nonce := Solve(seed, s.Difficulty())

	if _, err := s.Redeem(tok, "nonce-malo", "203.0.113.7", "fpA"); !errors.Is(err, ErrBadPoW) {
		t.Fatalf("nonce malo: err = %v", err)
	}
	if _, err := s.Redeem(tok, nonce, "198.51.100.1", "fpA"); !errors.Is(err, ErrBadBinding) {
		t.Fatalf("otra IP: err = %v", err)
	}
	pass, err := s.Redeem(tok, nonce, "203.0.113.7", "fpA")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ValidPass(pass, "203.0.113.7", "fpA"); err != nil {
		t.Fatalf("pase válido rechazado: %v", err)
	}
	if err := s.ValidPass(pass, "203.0.113.7", "fpB"); !errors.Is(err, ErrBadBinding) {
		t.Fatalf("pase robado a otro fingerprint: err = %v", err)
	}
	if err := s.ValidPass(tok, "203.0.113.7", "fpA"); err == nil {
		t.Fatal("un token de desafío no debe servir como pase")
	}
}

func TestRotacionDeLlaves(t *testing.T) {
	viejaB64, nuevaB64 := newKey(t), newKey(t)

	antes, _ := ParseKeyring("k1:" + viejaB64)
	sAntes := NewService(antes, 8, time.Minute, time.Hour)
	seed, tok, _ := sAntes.NewChallenge("ip", "fp")
	pase, err := sAntes.Redeem(tok, Solve(seed, 8), "ip", "fp")
	if err != nil {
		t.Fatal(err)
	}

	durante, _ := ParseKeyring("k2:" + nuevaB64 + ",k1:" + viejaB64)
	sDurante := NewService(durante, 8, time.Minute, time.Hour)
	if err := sDurante.ValidPass(pase, "ip", "fp"); err != nil {
		t.Fatalf("pase con llave anterior debería seguir válido: %v", err)
	}

	despues, _ := ParseKeyring("k2:" + nuevaB64)
	sDespues := NewService(despues, 8, time.Minute, time.Hour)
	if err := sDespues.ValidPass(pase, "ip", "fp"); !errors.Is(err, ErrUnknownKid) {
		t.Fatalf("tras retirar k1: err = %v, want ErrUnknownKid", err)
	}
}

func TestExpiracionYManipulacion(t *testing.T) {
	kr, _ := ParseKeyring("k1:" + newKey(t))
	s := NewService(kr, 8, time.Minute, time.Hour)
	seed, tok, _ := s.NewChallenge("ip", "fp")
	pase, _ := s.Redeem(tok, Solve(seed, 8), "ip", "fp")

	falso := pase[:len(pase)-2] + "AA"
	if err := s.ValidPass(falso, "ip", "fp"); !errors.Is(err, ErrBadSig) {
		t.Fatalf("firma alterada: err = %v", err)
	}

	ahora := time.Now()
	s.now = func() time.Time { return ahora.Add(2 * time.Hour) }
	if err := s.ValidPass(pase, "ip", "fp"); !errors.Is(err, ErrExpired) {
		t.Fatalf("expirado: err = %v", err)
	}
}

func TestParseKeyringErrores(t *testing.T) {
	for _, spec := range []string{"", "sinbase64", "k1:" + base64.StdEncoding.EncodeToString([]byte("corta"))} {
		if _, err := ParseKeyring(spec); err == nil {
			t.Fatalf("esperaba error con %q", spec)
		}
	}
}
