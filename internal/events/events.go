// Package events define la interfaz EventSink y el adaptador asíncrono
// que aísla la latencia del proxy del destino de los eventos.
// Destinos: log y none (paso 19), SQS y Kinesis con envío por batches (paso 20)
// y Kafka/MSK (paso 22), los tres detrás del mismo Batcher.
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
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	SinkLog     = "log"
	SinkNone    = "none"
	SinkSQS     = "sqs"
	SinkKinesis = "kinesis"
	SinkKafka   = "kafka" // paso 22: Kafka local o Amazon MSK (kafka.go)

	// DefaultBuffer cabe ~1 s de holgura a 1.000 req/s. Si el sink
	// va más lento que el ingreso durante más que eso, empezamos a descartar.
	DefaultBuffer = 1024

	// Envío por batches (paso 20).
	DefaultBatchSize     = 100
	MaxBatchSize         = 500 // tope de PutRecords; SQS lo parte en llamadas de 10
	DefaultFlushInterval = time.Second
	DefaultMaxRetries    = 3
	DefaultRetryBackoff  = 100 * time.Millisecond
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

// SQSConfig vive bajo events.sqs. El endpoint NO va aquí: sale de la
// variable estándar AWS_ENDPOINT_URL (Floci en local, vacío en AWS real).
type SQSConfig struct {
	QueueURL string `yaml:"queue_url"`
}

// KinesisConfig vive bajo events.kinesis.
type KinesisConfig struct {
	StreamName string `yaml:"stream_name"`
}

// Config vive en el YAML, bajo la clave `events`.
type Config struct {
	Enabled bool   `yaml:"enabled"`
	Sink    string `yaml:"sink"`   // log | none | sqs | kinesis | kafka
	Buffer  int    `yaml:"buffer"` // tamaño del canal; default 1024

	// Solo para sqs, kinesis y kafka. 0 significa "usa el default".
	// En kafka, max_retries no aplica: franz-go reintenta hasta kafka.delivery_timeout.
	BatchSize     int           `yaml:"batch_size"`     // eventos por batch; default 100, máximo 500
	FlushInterval time.Duration `yaml:"flush_interval"` // vacía un batch incompleto; default 1s
	MaxRetries    int           `yaml:"max_retries"`    // retries de lo que falló; default 3
	RetryBackoff  time.Duration `yaml:"retry_backoff"`  // espera base; se duplica; default 100ms

	SQS     SQSConfig     `yaml:"sqs"`
	Kinesis KinesisConfig `yaml:"kinesis"`
	Kafka   KafkaConfig   `yaml:"kafka"` // paso 22
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
	case SinkSQS:
		u, err := url.Parse(strings.TrimSpace(c.SQS.QueueURL))
		if c.SQS.QueueURL == "" || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, fmt.Errorf("events.sqs.queue_url es obligatorio con sink sqs y debe ser una URL completa, ej. https://sqs.us-east-1.amazonaws.com/123456789012/guardian-events (recibido %q)", c.SQS.QueueURL))
		}
	case SinkKinesis:
		if strings.TrimSpace(c.Kinesis.StreamName) == "" {
			errs = append(errs, errors.New("events.kinesis.stream_name es obligatorio con sink kinesis"))
		}
	case SinkKafka:
		if err := c.Kafka.Validate(); err != nil {
			errs = append(errs, err)
		}
	default:
		errs = append(errs, fmt.Errorf("events.sink %q no es válido: usa log, none, sqs, kinesis o kafka", c.Sink))
	}
	if c.Buffer < 0 {
		errs = append(errs, errors.New("events.buffer no puede ser negativo"))
	}
	if c.BatchSize < 0 || c.BatchSize > MaxBatchSize {
		errs = append(errs, fmt.Errorf("events.batch_size debe estar entre 1 y %d (0 usa el default %d)", MaxBatchSize, DefaultBatchSize))
	}
	if c.FlushInterval < 0 {
		errs = append(errs, errors.New("events.flush_interval no puede ser negativo"))
	}
	if c.MaxRetries < 0 {
		errs = append(errs, errors.New("events.max_retries no puede ser negativo"))
	}
	if c.RetryBackoff < 0 {
		errs = append(errs, errors.New("events.retry_backoff no puede ser negativo"))
	}
	return errors.Join(errs...)
}

// WithDefaults rellena lo que el YAML no trae.
func (c Config) WithDefaults() Config {
	if strings.TrimSpace(c.Sink) == "" {
		c.Sink = SinkLog
	}
	c.Sink = strings.ToLower(strings.TrimSpace(c.Sink))
	if c.Buffer == 0 {
		c.Buffer = DefaultBuffer
	}
	if c.BatchSize == 0 {
		c.BatchSize = DefaultBatchSize
	}
	if c.FlushInterval == 0 {
		c.FlushInterval = DefaultFlushInterval
	}
	if c.MaxRetries == 0 {
		c.MaxRetries = DefaultMaxRetries
	}
	if c.RetryBackoff == 0 {
		c.RetryBackoff = DefaultRetryBackoff
	}
	c.Kafka = c.Kafka.WithDefaults()
	return c
}

// Sink es el destino. Puede ser lento: el Async lo aísla del request.
// SQS y Kinesis (paso 20) implementan BatchSender y el Batcher las
// convierte en un Sink: el Async no sabe que hay batches.
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
// reg recibe las métricas del Batcher (sqs, kinesis y kafka las usan).
func NewSink(cfg Config, log *slog.Logger, reg prometheus.Registerer) (Sink, error) {
	cfg = cfg.WithDefaults()
	switch cfg.Sink {
	case SinkLog:
		return NewLogSink(log), nil
	case SinkNone:
		return noopDest{}, nil
	case SinkSQS:
		client, err := newSQSClient(context.Background())
		if err != nil {
			return nil, err
		}
		return NewBatcher(NewSQSSender(client, cfg.SQS.QueueURL, cfg.retryPolicy()), cfg, log, reg), nil
	case SinkKinesis:
		client, err := newKinesisClient(context.Background())
		if err != nil {
			return nil, err
		}
		return NewBatcher(NewKinesisSender(client, cfg.Kinesis.StreamName, cfg.retryPolicy()), cfg, log, reg), nil
	case SinkKafka:
		sender, err := NewKafkaSender(context.Background(), cfg.Kafka, cfg.retryPolicy())
		if err != nil {
			return nil, err
		}
		if log == nil {
			log = slog.Default()
		}
		// Avisa si Kafka no responde, pero NO impide arrancar: perder eventos un
		// rato es mejor que tumbar el proxy. franz-go reconecta solo.
		pctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := sender.Ping(pctx); err != nil {
			log.Warn("events: kafka no responde al arrancar; franz-go seguirá intentando",
				"brokers", cfg.Kafka.Brokers, "err", err)
		}
		cancel()
		return NewBatcher(sender, cfg, log, reg), nil
	default:
		return nil, fmt.Errorf("events.sink %q no es válido: usa log, none, sqs, kinesis o kafka", cfg.Sink)
	}
}
