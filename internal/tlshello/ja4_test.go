package tlshello

import (
	"crypto/tls"
	"slices"
	"strings"
	"testing"
)

// specHello reproduce, campo por campo, el ejemplo de la especificación JA4
// de FoxIO (technical_details/JA4.md). OJO: sale del texto de la especificación,
// no de un pcap; los valores esperados también son los que publica ese texto.
func specHello() *Hello {
	return &Hello{
		SNI:               "example.com",
		CipherSuites:      []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
		Extensions:        []uint16{0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015},
		SupportedVersions: []uint16{0x0304, 0x0303},
		SupportedProtos:   []string{"h2", "http/1.1"},
		SignatureSchemes:  []tls.SignatureScheme{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601},
	}
}

func TestJA4SpecVector(t *testing.T) {
	r := ComputeJA4(specHello())
	checks := []struct{ name, got, want string }{
		{"ja4", r.String(), "t13d1516h2_8daaf6152771_e5627efa2ab1"},
		{"ja4_r", r.Raw, "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"},
		{"ja4_o", r.Original, "t13d1516h2_acb858a92679_18f69afefd3d"},
		{"ja4_ro", r.RawOriginal, "t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015_0403,0804,0401,0503,0805,0501,0806,0601"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s:\n got  %s\n want %s", c.name, c.got, c.want)
		}
	}
}

// Sin signature algorithms, la especificación da 6d807ffa2a79 para ja4_c.
func TestJA4WithoutSignatureAlgorithms(t *testing.T) {
	h := specHello()
	h.SignatureSchemes = nil
	r := ComputeJA4(h)
	if r.C != "6d807ffa2a79" {
		t.Fatalf("ja4_c = %s, want 6d807ffa2a79", r.C)
	}
	if strings.HasSuffix(r.Raw, "_") || strings.Count(r.Raw, "_") != 2 {
		t.Fatalf("sin sigalgs no debe quedar un '_' de más: %s", r.Raw)
	}
}

// GREASE en cualquier lista no debe cambiar nada (ni los conteos ni los hashes).
func TestJA4IgnoresGREASE(t *testing.T) {
	clean := ComputeJA4(specHello())

	h := specHello()
	h.CipherSuites = append([]uint16{0x7a7a}, h.CipherSuites...)
	h.Extensions = append(append([]uint16{0x1a1a}, h.Extensions...), 0x3a3a)
	h.SupportedVersions = []uint16{0x1a1a, 0x0304, 0x0303}
	h.SignatureSchemes = append([]tls.SignatureScheme{0x2a2a}, h.SignatureSchemes...)

	got := ComputeJA4(h)
	if got != clean {
		t.Fatalf("GREASE cambió el resultado:\n got  %+v\n want %+v", got, clean)
	}
}

// La demo clave: Chrome mezcla el orden de sus extensiones en cada conexión.
// ja4 / ja4_r NO deben cambiar; ja4_o sí (por eso JA3 se rompió).
func TestJA4StableUnderShuffle(t *testing.T) {
	base := ComputeJA4(specHello())

	h := specHello()
	slices.Reverse(h.Extensions)
	h.CipherSuites = append(h.CipherSuites[7:], h.CipherSuites[:7]...)
	shuffled := ComputeJA4(h)

	if shuffled.String() != base.String() {
		t.Errorf("ja4 cambió con el orden: %s vs %s", shuffled.String(), base.String())
	}
	if shuffled.Raw != base.Raw {
		t.Errorf("ja4_r cambió con el orden")
	}
	if shuffled.Original == base.Original {
		t.Errorf("ja4_o debía cambiar con el orden y no cambió")
	}

	// Pero el orden de los signature algorithms SÍ importa.
	h2 := specHello()
	slices.Reverse(h2.SignatureSchemes)
	if ComputeJA4(h2).C == base.C {
		t.Errorf("ja4_c debía cambiar al cambiar el orden de los sigalgs")
	}
}

func TestJA4Version(t *testing.T) {
	cases := []struct {
		name string
		in   []uint16
		want string
	}{
		{"1.3 y 1.2", []uint16{0x0304, 0x0303}, "13"},
		{"grease no cuenta", []uint16{0xfafa, 0x0303}, "12"},
		{"solo 1.2", []uint16{0x0303, 0x0302, 0x0301}, "12"},
		{"ssl 3.0", []uint16{0x0300}, "s3"},
		{"vacío", nil, "00"},
		{"solo grease", []uint16{0x0a0a}, "00"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ja4Version(c.in); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestJA4ALPN(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"h2", []string{"h2", "http/1.1"}, "h2"},
		{"http/1.1 primero", []string{"http/1.1", "h2"}, "h1"},
		{"sin ALPN", nil, "00"},
		{"primer valor vacío", []string{""}, "00"},
		// Ejemplos de la especificación (bytes no alfanuméricos → hex).
		{"0xAB", []string{"\xab"}, "ab"},
		{"0xAB 0xCD", []string{"\xab\xcd"}, "ad"},
		{"0x30 0xAB 0xCD 0x31", []string{"\x30\xab\xcd\x31"}, "01"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ja4ALPN(c.in); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestJA4PartA(t *testing.T) {
	t.Run("sin SNI es i", func(t *testing.T) {
		h := specHello()
		h.Extensions = slices.DeleteFunc(h.Extensions, func(e uint16) bool { return e == 0x0000 })
		if got := ComputeJA4(h).A; got != "t13i1515h2" {
			t.Fatalf("A = %s, want t13i1515h2", got)
		}
	})
	t.Run("sin ALPN", func(t *testing.T) {
		h := specHello()
		h.SupportedProtos = nil
		if got := ComputeJA4(h).A; got != "t13d151600" {
			t.Fatalf("A = %s, want t13d151600", got)
		}
	})
	t.Run("conteos topan en 99", func(t *testing.T) {
		h := specHello()
		h.CipherSuites = make([]uint16, 120)
		for i := range h.CipherSuites {
			h.CipherSuites[i] = uint16(0x1000 + i)
		}
		if got := ComputeJA4(h).A; !strings.HasPrefix(got, "t13d99") {
			t.Fatalf("A = %s, want prefijo t13d99", got)
		}
	})
	t.Run("sin ciphers ni extensiones: 12 ceros", func(t *testing.T) {
		r := ComputeJA4(&Hello{SupportedVersions: []uint16{0x0303}})
		if r.B != "000000000000" || r.C != "000000000000" {
			t.Fatalf("B=%s C=%s, want doce ceros", r.B, r.C)
		}
		if r.A != "t12i000000" {
			t.Fatalf("A = %s, want t12i000000", r.A)
		}
	})
	t.Run("hello nil", func(t *testing.T) {
		if got := ComputeJA4(nil).String(); got != "__" {
			t.Fatalf("got %q", got)
		}
	})
}

// El Chrome real de Fabio (línea tls_hello del paso 13). El log tiene nombres,
// no hex: aquí los traducimos a mano. NO conocemos sus signature algorithms
// (el log no los traía), así que solo verificamos ja4_a y ja4_b.
// ja4_b coincide con el de la especificación porque los 15 ciphers son los
// mismos (Chrome cambia el orden solo con las extensiones, no con los ciphers).
func TestJA4FabioChrome(t *testing.T) {
	h := &Hello{
		SNI: "localhost",
		CipherSuites: []uint16{
			0x7a7a, // GREASE
			tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		// grease, ech, alps, groups, sigalgs, reneg, ems, compress_cert, sni,
		// ec_point_formats, status_request, session_ticket, psk_modes, sct,
		// key_share, alpn, 0xca34, supported_versions, grease
		Extensions: []uint16{
			0x1a1a, 0xfe0d, 0x44cd, 0x000a, 0x000d, 0xff01, 0x0017, 0x001b, 0x0000,
			0x000b, 0x0005, 0x0023, 0x002d, 0x0012, 0x0033, 0x0010, 0xca34, 0x002b, 0x3a3a,
		},
		SupportedVersions: []uint16{0x1a1a, 0x0304, 0x0303},
		SupportedProtos:   []string{"h2", "http/1.1"},
	}
	r := ComputeJA4(h)
	if r.A != "t13d1517h2" {
		t.Errorf("ja4_a = %s, want t13d1517h2", r.A)
	}
	if r.B != "8daaf6152771" {
		t.Errorf("ja4_b = %s, want 8daaf6152771", r.B)
	}
}
