package tlshello

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// JA4Result guarda las tres partes del fingerprint JA4 (FoxIO) y sus
// variantes "raw", que sirven para reproducirlo offline.
//
//	JA4 = A _ B _ C
//	A: t13d1517h2   protocolo, versión, SNI, #ciphers, #extensiones, ALPN
//	B: 12 hex       sha256 de los ciphers ordenados
//	C: 12 hex       sha256 de las extensiones ordenadas (sin SNI ni ALPN)
//	                + "_" + signature algorithms en su orden original
type JA4Result struct {
	A string
	B string
	C string

	// Raw (ja4_r) es lo mismo pero con las listas en claro, ordenadas.
	Raw string
	// Original (ja4_o) hashea las listas en el orden en que llegaron
	// (incluye SNI y ALPN en las extensiones). Cambia con cada shuffle.
	Original string
	// RawOriginal (ja4_ro) son las listas en claro, en el orden original.
	RawOriginal string
}

// String devuelve el JA4 "normal": A_B_C.
func (r JA4Result) String() string {
	return r.A + "_" + r.B + "_" + r.C
}

const (
	extSNI  uint16 = 0x0000
	extALPN uint16 = 0x0010

	emptyHash = "000000000000"
)

// ComputeJA4 calcula el JA4 de un ClientHello capturado. Solo mira lo que el
// cliente OFRECIÓ (no lo negociado), y solo cubre TLS sobre TCP ('t').
func ComputeJA4(h *Hello) JA4Result {
	if h == nil {
		return JA4Result{}
	}

	ciphers := dropGREASE(h.CipherSuites)
	exts := dropGREASE(h.Extensions)
	sigs := dropGREASE(schemesToUint16(h.SignatureSchemes))

	a := ja4A(h, len(ciphers), len(exts))

	// ja4_b: ciphers ordenados.
	sortedCiphers := slices.Clone(ciphers)
	slices.Sort(sortedCiphers)

	// ja4_c: extensiones sin SNI ni ALPN, ordenadas, y luego los sigalgs
	// tal cual llegaron.
	withoutSNIALPN := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if e != extSNI && e != extALPN {
			withoutSNIALPN = append(withoutSNIALPN, e)
		}
	}
	sortedExts := slices.Clone(withoutSNIALPN)
	slices.Sort(sortedExts)

	sigPart := hexList(sigs)
	return JA4Result{
		A:           a,
		B:           hashOrEmpty(hexList(sortedCiphers)),
		C:           hashOrEmpty(joinExtsAndSigs(hexList(sortedExts), sigPart)),
		Raw:         a + "_" + hexList(sortedCiphers) + "_" + joinExtsAndSigs(hexList(sortedExts), sigPart),
		Original:    a + "_" + hashOrEmpty(hexList(ciphers)) + "_" + hashOrEmpty(joinExtsAndSigs(hexList(exts), sigPart)),
		RawOriginal: a + "_" + hexList(ciphers) + "_" + joinExtsAndSigs(hexList(exts), sigPart),
	}
}

// ja4A arma la primera parte: t + versión + d/i + #ciphers + #ext + ALPN.
func ja4A(h *Hello, nCiphers, nExts int) string {
	sni := "i"
	if h.HasExtension(extSNI) {
		sni = "d"
	}
	return fmt.Sprintf("t%s%s%02d%02d%s",
		ja4Version(h.SupportedVersions), sni, min(nCiphers, 99), min(nExts, 99), ja4ALPN(h.SupportedProtos))
}

// ja4Version toma la versión MÁS ALTA que ofrece el cliente, ignorando GREASE.
// Go ya nos entrega SupportedVersions: si el cliente mandó la extensión
// supported_versions usa esa lista; si no, la extrapola desde la versión
// del ClientHello. Es justo lo que pide la especificación.
func ja4Version(vs []uint16) string {
	var best uint16
	for _, v := range vs {
		if !isGREASE(v) && v > best {
			best = v
		}
	}
	switch best {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	}
	return "00"
}

// ja4ALPN devuelve primer y último carácter del PRIMER valor de ALPN.
// Sin ALPN: "00". Si alguno de los dos bytes no es alfanumérico ASCII, se
// usan el primer y último carácter de la representación hexadecimal.
func ja4ALPN(protos []string) string {
	if len(protos) == 0 || protos[0] == "" {
		return "00"
	}
	p := protos[0]
	first, last := p[0], p[len(p)-1]
	if isAlnum(first) && isAlnum(last) {
		return string([]byte{first, last})
	}
	hx := hex.EncodeToString([]byte(p))
	return string([]byte{hx[0], hx[len(hx)-1]})
}

func isAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

func dropGREASE(ids []uint16) []uint16 {
	out := make([]uint16, 0, len(ids))
	for _, id := range ids {
		if !isGREASE(id) {
			out = append(out, id)
		}
	}
	return out
}

func schemesToUint16(in []tls.SignatureScheme) []uint16 {
	out := make([]uint16, len(in))
	for i, v := range in {
		out[i] = uint16(v)
	}
	return out
}

// hexList formatea IDs como "002f,0035": 4 dígitos hex en minúscula.
func hexList(ids []uint16) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("%04x", id)
	}
	return strings.Join(parts, ",")
}

// joinExtsAndSigs une extensiones y sigalgs con "_", pero si no hay sigalgs
// NO deja el guion bajo (así lo pide la especificación).
func joinExtsAndSigs(exts, sigs string) string {
	if sigs == "" {
		return exts
	}
	return exts + "_" + sigs
}

// hashOrEmpty devuelve los primeros 12 hex de sha256(s). Si la lista está
// vacía devuelve 12 ceros para que se note que no había datos.
func hashOrEmpty(s string) string {
	if s == "" {
		return emptyHash
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
