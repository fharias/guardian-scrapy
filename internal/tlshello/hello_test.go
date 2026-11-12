package tlshello

import (
	"fmt"
	"testing"
)

func TestIsGREASE(t *testing.T) {
	cases := []struct {
		id   uint16
		want bool
	}{
		{0x0a0a, true},
		{0x1a1a, true},
		{0xfafa, true},
		{0x0000, false},
		{0x002b, false},
		{0x1301, false}, // TLS_AES_128_GCM_SHA256
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("0x%04x", c.id), func(t *testing.T) {
			if got := isGREASE(c.id); got != c.want {
				t.Errorf("isGREASE(0x%04x) = %v, want %v", c.id, got, c.want)
			}
		})
	}
}

func TestExtensionName(t *testing.T) {
	cases := []struct {
		id   uint16
		want string
	}{
		{0x0000, "server_name"},
		{0x0010, "application_layer_protocol_negotiation"},
		{0x002b, "supported_versions"},
		{0x0033, "key_share"},
		{0x0a0a, "grease:0x0a0a"},
		{0x1234, "0x1234"},
		{0xfe0d, "encrypted_client_hello"},
	}
	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			if got := extensionName(c.id); got != c.want {
				t.Errorf("extensionName(0x%04x) = %q, want %q", c.id, got, c.want)
			}
		})
	}
}

func TestFormatCiphersMarksGREASE(t *testing.T) {
	got := formatCiphers([]uint16{0x0a0a, 0x1301})
	if len(got) != 2 || got[0] != "grease:0x0a0a" || got[1] == "" {
		t.Fatalf("formatCiphers = %#v", got)
	}
	if got[1] != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("cipher name = %q", got[1])
	}
}
