package challenge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/bits"
	"strconv"
	"strings"
	"time"
)

var ErrBadBinding = errors.New("el token no corresponde a este cliente")
var ErrBadPoW = errors.New("prueba de trabajo inválida")

type Service struct {
	keys       *Keyring
	difficulty int
	chalTTL    time.Duration
	passTTL    time.Duration
	now        func() time.Time
}

func NewService(keys *Keyring, difficulty int, chalTTL, passTTL time.Duration) *Service {
	return &Service{keys: keys, difficulty: difficulty, chalTTL: chalTTL, passTTL: passTTL, now: time.Now}
}

func (s *Service) Difficulty() int { return s.difficulty }

func (s *Service) PassTTL() time.Duration { return s.passTTL }

func binding(ip, fp string) string { return ip + "|" + fp }

// NewChallenge devuelve la semilla (lo que el navegador hashea) y el token
// firmado que la acompaña, atado a la IP y al fingerprint.
func (s *Service) NewChallenge(ip, fp string) (seed, token string, err error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	seed = hex.EncodeToString(buf)
	token = issue(s.keys, seed+"|"+binding(ip, fp), s.now().Add(s.chalTTL))
	return seed, token, nil
}

// Solve es lo que hace el JavaScript del navegador; aquí sirve para tests.
func Solve(seed string, difficulty int) string {
	for n := 0; ; n++ {
		nonce := strconv.Itoa(n)
		if leadingZeroBits(seed+nonce) >= difficulty {
			return nonce
		}
	}
}

func leadingZeroBits(s string) int {
	sum := sha256.Sum256([]byte(s))
	zeros := 0
	for _, b := range sum {
		if b == 0 {
			zeros += 8
			continue
		}
		zeros += bits.LeadingZeros8(b)
		break
	}
	return zeros
}

// Redeem verifica el token del desafío y la PoW; si todo cuadra emite el pase.
func (s *Service) Redeem(token, nonce, ip, fp string) (string, error) {
	data, err := verify(s.keys, token, s.now())
	if err != nil {
		return "", err
	}
	seed, bound, ok := strings.Cut(data, "|")
	if !ok {
		return "", ErrMalformed
	}
	if bound != binding(ip, fp) {
		return "", ErrBadBinding
	}
	if len(nonce) > 20 || leadingZeroBits(seed+nonce) < s.difficulty {
		return "", ErrBadPoW
	}
	return issue(s.keys, "pass|"+binding(ip, fp), s.now().Add(s.passTTL)), nil
}

func (s *Service) ValidPass(pass, ip, fp string) error {
	data, err := verify(s.keys, pass, s.now())
	if err != nil {
		return err
	}
	if data != "pass|"+binding(ip, fp) {
		return ErrBadBinding
	}
	return nil
}
