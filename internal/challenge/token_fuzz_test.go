package challenge

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// fuzzKeyring arma un Keyring con llaves fijas: el fuzzer debe ser
// determinista, así que nada de crypto/rand aquí.
func fuzzKeyring(t testing.TB) *Keyring {
	t.Helper()
	k1 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32))
	k2 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x02}, 32))
	kr, err := ParseKeyring("k1:" + k1 + ",k2:" + k2)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func FuzzVerify(f *testing.F) {
	kr := fuzzKeyring(f)
	now := time.Unix(1_800_000_000, 0)

	f.Add(issue(kr, "1.2.3.4|t13d", now.Add(time.Minute)), "1.2.3.4|t13d")
	f.Add("", "")
	f.Add("a.b.c.d", "a.b")
	f.Add("k1.9999999999.AA.", "\xff\xfe")

	f.Fuzz(func(t *testing.T, token, data string) {
		// 1) Input del atacante: nunca panic. Si dice que es válido, el
		//    token tiene que tener la forma kid.exp.datos.firma.
		if _, err := verify(kr, token, now); err == nil && strings.Count(token, ".") != 3 {
			t.Fatalf("verify aceptó un token sin 4 partes: %q", token)
		}

		// 2) Roundtrip: lo que firmamos se recupera idéntico, byte a byte.
		tok := issue(kr, data, now.Add(time.Minute))
		got, err := verify(kr, tok, now)
		if err != nil {
			t.Fatalf("roundtrip falló con data=%q: %v", data, err)
		}
		if got != data {
			t.Fatalf("roundtrip: got %q, want %q", got, data)
		}

		// 3) Expira: el mismo token un instante después de exp se rechaza.
		if _, err := verify(kr, tok, now.Add(2*time.Minute)); !errors.Is(err, ErrExpired) {
			t.Fatalf("token vencido: err = %v, want ErrExpired", err)
		}

		// 4) Integridad: alterar cualquier byte de la firma invalida el token.
		i := strings.LastIndexByte(tok, '.') + 1
		mut := []byte(tok)
		if mut[i] == 'A' {
			mut[i] = 'B'
		} else {
			mut[i] = 'A'
		}
		if _, err := verify(kr, string(mut), now); !errors.Is(err, ErrBadSig) {
			t.Fatalf("firma alterada: err = %v, want ErrBadSig", err)
		}
	})
}
