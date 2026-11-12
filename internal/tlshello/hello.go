package tlshello

import (
	"crypto/tls"
	"fmt"
)

// Hello es una foto del ClientHello (lo que ofrece el cliente) más lo que
// quedó negociado después del handshake.
type Hello struct {
	SNI               string
	CipherSuites      []uint16
	Extensions        []uint16
	SupportedVersions []uint16
	SupportedCurves   []tls.CurveID
	SupportedProtos   []string
	SignatureSchemes  []tls.SignatureScheme

	// Se llenan después del handshake, con tls.ConnectionState.
	Version     uint16
	CipherSuite uint16
	Protocol    string
}

func fromClientHello(info *tls.ClientHelloInfo) *Hello {
	if info == nil {
		return nil
	}
	return &Hello{
		SNI:               info.ServerName,
		CipherSuites:      append([]uint16(nil), info.CipherSuites...),
		Extensions:        append([]uint16(nil), info.Extensions...),
		SupportedVersions: append([]uint16(nil), info.SupportedVersions...),
		SupportedCurves:   append([]tls.CurveID(nil), info.SupportedCurves...),
		SupportedProtos:   append([]string(nil), info.SupportedProtos...),
		SignatureSchemes:  append([]tls.SignatureScheme(nil), info.SignatureSchemes...),
	}
}

func (h *Hello) applyState(st *tls.ConnectionState) {
	if h == nil || st == nil || h.Version != 0 {
		return
	}
	h.Version = st.Version
	h.CipherSuite = st.CipherSuite
	h.Protocol = st.NegotiatedProtocol
}

func (h *Hello) VersionName() string {
	if h == nil || h.Version == 0 {
		return ""
	}
	return tls.VersionName(h.Version)
}

func (h *Hello) CipherName() string {
	if h == nil || h.CipherSuite == 0 {
		return ""
	}
	return tls.CipherSuiteName(h.CipherSuite)
}

func (h *Hello) OfferedVersionNames() []string {
	if h == nil {
		return nil
	}
	return formatVersions(h.SupportedVersions)
}

func (h *Hello) OfferedCipherNames() []string {
	if h == nil {
		return nil
	}
	return formatCiphers(h.CipherSuites)
}

func (h *Hello) ExtensionNames() []string {
	if h == nil {
		return nil
	}
	return formatExtensions(h.Extensions)
}

func (h *Hello) CurveNames() []string {
	if h == nil {
		return nil
	}
	out := make([]string, len(h.SupportedCurves))
	for i, c := range h.SupportedCurves {
		if isGREASE(uint16(c)) {
			out[i] = formatGREASE(uint16(c))
			continue
		}
		out[i] = c.String()
	}
	return out
}

func (h *Hello) HasExtension(id uint16) bool {
	if h == nil {
		return false
	}
	for _, e := range h.Extensions {
		if e == id {
			return true
		}
	}
	return false
}

func formatVersions(vs []uint16) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		if isGREASE(v) {
			out[i] = formatGREASE(v)
			continue
		}
		out[i] = tls.VersionName(v)
	}
	return out
}

func formatCiphers(cs []uint16) []string {
	out := make([]string, len(cs))
	for i, id := range cs {
		if isGREASE(id) {
			out[i] = formatGREASE(id)
			continue
		}
		out[i] = tls.CipherSuiteName(id)
	}
	return out
}

func formatExtensions(ids []uint16) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = extensionName(id)
	}
	return out
}

// isGREASE sigue el RFC 8701: los valores reservados tienen la forma 0x?a?a.
func isGREASE(id uint16) bool {
	return id&0x0f0f == 0x0a0a
}

func formatGREASE(id uint16) string {
	return fmt.Sprintf("grease:0x%04x", id)
}

func extensionName(id uint16) string {
	if isGREASE(id) {
		return formatGREASE(id)
	}
	if name, ok := extensionNames[id]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", id)
}

// Nombres IANA de las extensiones TLS más comunes. Un ID desconocido
// queda en hexadecimal.
var extensionNames = map[uint16]string{
	0x0000: "server_name",
	0x0001: "max_fragment_length",
	0x0005: "status_request",
	0x000a: "supported_groups",
	0x000b: "ec_point_formats",
	0x000d: "signature_algorithms",
	0x0010: "application_layer_protocol_negotiation",
	0x0012: "signed_certificate_timestamp",
	0x0015: "padding",
	0x0017: "extended_master_secret",
	0x001b: "compress_certificate",
	0x001c: "record_size_limit",
	0x0022: "delegated_credentials",
	0x0023: "session_ticket",
	0x0029: "pre_shared_key",
	0x002b: "supported_versions",
	0x002d: "psk_key_exchange_modes",
	0x0031: "post_handshake_auth",
	0x0032: "signature_algorithms_cert",
	0x0033: "key_share",
	0x44cd: "application_settings", // ALPS, lo envía Chrome
	0xfe0d: "encrypted_client_hello",
	0xff01: "renegotiation_info",
}
