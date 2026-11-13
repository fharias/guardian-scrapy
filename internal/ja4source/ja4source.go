// Package ja4source decide de dónde sale el JA4 de cada petición:
// del ClientHello que guardian ve (tls), del header que agrega CloudFront
// (cloudfront) o de ninguna parte (none). El resto de guardian solo llama a
// Source.JA4 y no sabe cuál de los tres está detrás.
package ja4source

import (
	"fmt"
	"net/http"

	"github.com/fharias/guardian-scrapy/internal/fingerprint"
	"github.com/fharias/guardian-scrapy/internal/tlshello"
)

// CloudFrontHeader es el header donde CloudFront deja el JA4 del visitante.
// Solo llega si lo incluyes en una origin request policy.
const CloudFrontHeader = "CloudFront-Viewer-JA4-Fingerprint"

// Por qué rechazamos un header (Result.Rejected).
const (
	RejectedUntrusted = "peer_no_confiable" // el header llegó, pero de alguien que no es CloudFront
	RejectedBadFormat = "formato_invalido"  // el header llegó de un peer confiable, pero no es un JA4
	RejectedMultiple  = "header_repetido"   // llegó más de una vez: ambiguo
)

// Result es la respuesta de una Source.
type Result struct {
	JA4      string // vacío si no hay JA4
	Source   string // de dónde salió: "tls", "cloudfront" o "none"; vacío si no hubo JA4
	Rejected string // vacío, o por qué se descartó el header de CloudFront
	Header   string // el valor descartado (recortado), para investigar
}

// Source entrega el JA4 de una petición.
type Source interface {
	JA4(r *http.Request) Result
}

// New arma la Source según ja4.source. trusted dice si el vecino inmediato de
// la conexión es un proxy confiable; solo la usa "cloudfront".
func New(source string, trusted func(*http.Request) bool) (Source, error) {
	switch source {
	case "", fingerprint.SourceTLS:
		return TLS{}, nil
	case fingerprint.SourceNone:
		return None{}, nil
	case fingerprint.SourceCloudFront:
		if trusted == nil {
			return nil, fmt.Errorf("ja4.source %q necesita saber qué vecinos son confiables", source)
		}
		return CloudFront{Trusted: trusted, Fallback: TLS{}}, nil
	}
	return nil, fmt.Errorf("ja4.source %q no es válido", source)
}

// TLS usa el JA4 que guardian calculó del ClientHello (paso 14).
type TLS struct{}

func (TLS) JA4(r *http.Request) Result {
	if h := tlshello.FromRequest(r); h != nil && h.JA4 != "" {
		return Result{JA4: h.JA4, Source: fingerprint.SourceTLS}
	}
	return Result{}
}

// None apaga la señal: nunca hay JA4.
type None struct{}

func (None) JA4(*http.Request) Result {
	return Result{Source: fingerprint.SourceNone}
}

// CloudFront lee el header de CloudFront, pero solo si el vecino inmediato es
// confiable. Si el header no está o no sirve, pregunta a Fallback.
type CloudFront struct {
	Trusted  func(*http.Request) bool
	Fallback Source
}

func (c CloudFront) JA4(r *http.Request) Result {
	values := r.Header.Values(CloudFrontHeader)
	if len(values) == 0 {
		return c.fallback(r, Result{})
	}
	if !c.Trusted(r) {
		return c.fallback(r, Result{Rejected: RejectedUntrusted, Header: clip(values[0])})
	}
	if len(values) != 1 {
		return c.fallback(r, Result{Rejected: RejectedMultiple, Header: clip(values[0])})
	}
	if !fingerprint.ValidJA4(values[0]) {
		return c.fallback(r, Result{Rejected: RejectedBadFormat, Header: clip(values[0])})
	}
	return Result{JA4: values[0], Source: fingerprint.SourceCloudFront}
}

// fallback pregunta a la Source de respaldo y conserva el motivo del rechazo.
func (c CloudFront) fallback(r *http.Request, rejected Result) Result {
	var res Result
	if c.Fallback != nil {
		res = c.Fallback.JA4(r)
	}
	res.Rejected, res.Header = rejected.Rejected, rejected.Header
	return res
}

// clip recorta un valor controlado por el atacante antes de loguearlo.
func clip(s string) string {
	const limite = 64
	if len(s) > limite {
		return s[:limite] + "…"
	}
	return s
}
