package challenge

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

type Keyring struct {
	active string
	keys   map[string][]byte
}

// ParseKeyring lee "kid1:base64,kid2:base64". La primera es la activa (firma);
// las demás solo verifican.
func ParseKeyring(spec string) (*Keyring, error) {
	kr := &Keyring{keys: make(map[string][]byte)}
	for i, part := range strings.Split(spec, ",") {
		kid, b64, ok := strings.Cut(strings.TrimSpace(part), ":")
		if !ok || kid == "" {
			return nil, fmt.Errorf("llave %d: formato esperado kid:base64", i)
		}
		if strings.ContainsAny(kid, ".") {
			return nil, fmt.Errorf("llave %d: el kid no puede tener puntos", i)
		}
		key, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("llave %q: %w", kid, err)
		}
		if len(key) < 32 {
			return nil, fmt.Errorf("llave %q: mínimo 32 bytes, tiene %d", kid, len(key))
		}
		if _, dup := kr.keys[kid]; dup {
			return nil, fmt.Errorf("llave %q repetida", kid)
		}
		kr.keys[kid] = key
		if i == 0 {
			kr.active = kid
		}
	}
	if kr.active == "" {
		return nil, errors.New("keyring vacío")
	}
	return kr, nil
}

func (k *Keyring) Active() (string, []byte) { return k.active, k.keys[k.active] }

func (k *Keyring) Get(kid string) ([]byte, bool) {
	key, ok := k.keys[kid]
	return key, ok
}
