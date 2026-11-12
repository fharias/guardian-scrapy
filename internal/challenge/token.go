package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
)

var (
	ErrMalformed  = errors.New("token mal formado")
	ErrUnknownKid = errors.New("kid desconocido")
	ErrBadSig     = errors.New("firma inválida")
	ErrExpired    = errors.New("token expirado")
)

var b64 = base64.RawURLEncoding

func sign(key []byte, msg string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return b64.EncodeToString(m.Sum(nil))
}

// Formato: kid.exp.datos.firma   (datos en base64url para que no tenga puntos)
func issue(kr *Keyring, data string, exp time.Time) string {
	kid, key := kr.Active()
	body := kid + "." + strconv.FormatInt(exp.Unix(), 10) + "." + b64.EncodeToString([]byte(data))
	return body + "." + sign(key, body)
}

func verify(kr *Keyring, token string, now time.Time) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return "", ErrMalformed
	}
	kid, expStr, dataB64, sig := parts[0], parts[1], parts[2], parts[3]
	key, ok := kr.Get(kid)
	if !ok {
		return "", ErrUnknownKid
	}
	body := kid + "." + expStr + "." + dataB64
	if !hmac.Equal([]byte(sig), []byte(sign(key, body))) {
		return "", ErrBadSig
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return "", ErrMalformed
	}
	if now.Unix() > exp {
		return "", ErrExpired
	}
	data, err := b64.DecodeString(dataB64)
	if err != nil {
		return "", ErrMalformed
	}
	return string(data), nil
}
