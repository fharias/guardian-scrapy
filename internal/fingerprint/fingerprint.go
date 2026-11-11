package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
)

var valueHeaders = []string{
	"User-Agent",
	"Accept",
	"Accept-Language",
	"Accept-Encoding",
	"Sec-Ch-Ua",
	"Sec-Ch-Ua-Platform",
}

var volatile = map[string]bool{
	"cookie": true, "content-length": true, "content-type": true,
	"referer": true, "authorization": true, "cache-control": true,
	"pragma": true, "if-none-match": true, "if-modified-since": true,
	"x-forwarded-for": true, "x-forwarded-proto": true, "x-forwarded-host": true,
	"forwarded": true, "x-amzn-trace-id": true,
}

type Result struct {
	Hash    string
	Missing []string
}

func Compute(h http.Header) Result {
	var b strings.Builder
	for _, name := range valueHeaders {
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(normalize(h.Get(name)))
		b.WriteByte('\n')
	}
	names := make([]string, 0, len(h))
	for name := range h {
		lower := strings.ToLower(name)
		if volatile[lower] {
			continue
		}
		names = append(names, lower)
	}
	sort.Strings(names)
	b.WriteString("names=")
	b.WriteString(strings.Join(names, ","))
	sum := sha256.Sum256([]byte(b.String()))
	return Result{
		Hash:    hex.EncodeToString(sum[:])[:16],
		Missing: missingBrowserHeaders(h),
	}
}

func normalize(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

func missingBrowserHeaders(h http.Header) []string {
	if !strings.Contains(h.Get("User-Agent"), "Mozilla/") {
		return nil
	}
	var missing []string
	for _, name := range []string{"Accept", "Accept-Language", "Accept-Encoding"} {
		if h.Get(name) == "" {
			missing = append(missing, name)
		}
	}
	return missing
}
