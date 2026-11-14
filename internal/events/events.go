// Package events define la interfaz EventSink y el adaptador asíncrono
// que aísla la latencia del proxy del destino de los eventos.
// Los adaptadores de SQS, Kinesis y Kafka llegan en los pasos 20 y 22;
// hoy solo hay un sink de log y el wrapper con buffer.
package events

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"
)

const (
	SinkLog  = "log"
	SinkNone = "none"

	// DefaultBuffer cabe ~1 s de holgura a 1.000 req/s. Si el sink
	// va más lento que el ingreso durante más que eso, empezamos a descartar.
	DefaultBuffer = 1024
)

// Event es lo que sale del plano de datos hacia el pipeline de señales.
// No lleva la IP en claro: la IP es dato personal (Ley 1581 de 2012).
type Event struct {
	Time        time.Time `json:"ts"`
	IPHash      string    `json:"ip_hash"`
	JA4         string    `json:"ja4,omitempty"`
	JA4Source   string    `json:"ja4_source,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Route       string    `json:"route"`
	Method      string    `json:"method"`
	Score       int       `json:"score"`
	Decision    string    `json:"decision"`
	Reasons     []string  `json:"reasons,omitempty"`
	Mode        string    `json:"mode"`
	Shadow      bool      `json:"shadow"`
	TraceID     string    `json:"trace_id,omitempty"`
}

// Config vive en el YAML, bajo la clave `events`.
type Config struct {
	Enabled bool   `yaml:"enabled"`
	Sink    string `yaml:"sink"`   // log | none (sqs, kinesis, kafka: pasos 20 y 22)
	Buffer  int    `yaml:"buffer"` // tamaño del canal; default 1024
}

func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	var errs []error
	sink := strings.ToLower(strings.TrimSpace(c.Sink))
	if sink == "" {
		sink = SinkLog
	}
	switch sink {
	case SinkLog, SinkNone:
	default:
		errs = append(errs, fmt.Errorf("events.sink %q no es válido en el paso 19: usa log o none (sqs, kinesis y kafka llegan en los pasos 20 y 22)", c.Sink))
	}
	if c.Buffer < 0 {
		errs = append(errs, errors.New("events.buffer no puede ser negativo"))
	}
	return errors.Join(errs...)
}

// WithDefaults rellena sink y buffer si el YAML no los trae.
func (c Config) WithDefaults() Config {
	if strings.TrimSpace(c.Sink) == "" {
		c.Sink = SinkLog
	}
	c.Sink = strings.ToLower(strings.TrimSpace(c.Sink))
	if c.Buffer == 0 {
		c.Buffer = DefaultBuffer
	}
	return c
}

// Sink es el destino. Puede ser lento: el Async lo aísla del request.
// En el paso 20 SQS y Kinesis implementan esta misma interfaz.
type Sink interface {
	Emit(ctx context.Context, ev Event) error
	Close(ctx context.Context) error
}

// EventSink es lo que ve el plano de datos. Emit NUNCA bloquea:
// si el buffer está lleno, descarta y suma la métrica.
type EventSink interface {
	Emit(ev Event)
	Close(ctx context.Context) error
}

// Hasher convierte la IP en un hmac-sha256 truncado, con una sal
// que vive en GUARDIAN_EVENT_SALT. Sin la sal, el hash no se puede
// revertir; rotarla invalida los hashes viejos (como el anillo HMAC).
type Hasher struct {
	key []byte
}

func NewHasher(salt string) (*Hasher, error) {
	if len(salt) < 16 {
		return nil, errors.New("GUARDIAN_EVENT_SALT es obligatorio si events.enabled es true y debe tener al menos 16 caracteres (openssl rand -hex 32)")
	}
	return &Hasher{key: []byte(salt)}, nil
}

func (h *Hasher) Hash(ip netip.Addr) string {
	if h == nil || !ip.IsValid() {
		return ""
	}
	mac := hmac.New(sha256.New, h.key)
	mac.Write(ip.AsSlice())
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

type noopSink struct{}

func Noop() EventSink                        { return noopSink{} }
func (noopSink) Emit(Event)                  {}
func (noopSink) Close(context.Context) error { return nil }

type noopDest struct{}

func (noopDest) Emit(context.Context, Event) error { return nil }
func (noopDest) Close(context.Context) error       { return nil }

// LogSink escribe cada evento como una línea slog JSON con msg "event".
type LogSink struct {
	log *slog.Logger
}

func NewLogSink(log *slog.Logger) *LogSink {
	if log == nil {
		log = slog.Default()
	}
	return &LogSink{log: log}
}

func (s *LogSink) Emit(_ context.Context, ev Event) error {
	s.log.Info("event",
		"ts", ev.Time,
		"ip_hash", ev.IPHash,
		"ja4", ev.JA4,
		"ja4_source", ev.JA4Source,
		"fingerprint", ev.Fingerprint,
		"route", ev.Route,
		"method", ev.Method,
		"score", ev.Score,
		"decision", ev.Decision,
		"reasons", ev.Reasons,
		"mode", ev.Mode,
		"shadow", ev.Shadow,
		"trace_id", ev.TraceID,
	)
	return nil
}

func (s *LogSink) Close(context.Context) error { return nil }

// NewSink arma el destino según events.sink. El Async lo envuelve después.
func NewSink(cfg Config, log *slog.Logger) (Sink, error) {
	cfg = cfg.WithDefaults()
	switch cfg.Sink {
	case SinkLog:
		return NewLogSink(log), nil
	case SinkNone:
		return noopDest{}, nil
	default:
		return nil, fmt.Errorf("events.sink %q no es válido en el paso 19: usa log o none", cfg.Sink)
	}
}
