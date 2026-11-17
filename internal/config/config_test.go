package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// base es la configuración mínima válida; cada caso le agrega un bloque ja4.
const base = `
upstream: "http://localhost:9000"
trusted_proxies: ["10.0.0.0/8"]
challenge:
  difficulty: 16
modes:
  default: enforce
`

func TestLoadJA4Source(t *testing.T) {
	cases := []struct {
		name       string
		extra      string
		noTrusted  bool
		wantSource string
		wantErr    string
	}{
		{"sin bloque ja4: default tls", "", false, "tls", ""},
		{"bloque ja4 sin source: default tls", "ja4:\n  tools: []\n", false, "tls", ""},
		{"cloudfront", "ja4:\n  source: cloudfront\n", false, "cloudfront", ""},
		{"none", "ja4:\n  source: none\n", false, "none", ""},
		{"valor inválido", "ja4:\n  source: akamai\n", false, "", "ja4.source"},
		{"cloudfront sin trusted_proxies", "ja4:\n  source: cloudfront\n", true, "", "trusted_proxies"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			yml := base + c.extra
			if c.noTrusted {
				yml = strings.Replace(yml, `trusted_proxies: ["10.0.0.0/8"]`, "", 1)
			}
			path := filepath.Join(t.TempDir(), "guardian.yml")
			if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want que contenga %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.JA4.Source != c.wantSource {
				t.Fatalf("source = %q, want %q", cfg.JA4.Source, c.wantSource)
			}
		})
	}
}

func TestLoadEvents(t *testing.T) {
	cases := []struct {
		name        string
		extra       string
		wantEnabled bool
		wantSink    string
		wantBuffer  int
		wantErr     string
	}{
		{"sin bloque events: desactivado con defaults", "", false, "log", 1024, ""},
		{"parcial: enabled sin buffer usa 1024", "events:\n  enabled: true\n  sink: log\n", true, "log", 1024, ""},
		{"none", "events:\n  enabled: true\n  sink: none\n  buffer: 8\n", true, "none", 8, ""},
		{"sqs sin queue_url se rechaza", "events:\n  enabled: true\n  sink: sqs\n", false, "", 0, "events.sqs.queue_url"},
		{"sqs completo", "events:\n  enabled: true\n  sink: sqs\n  sqs:\n    queue_url: \"http://localhost:4566/000000000000/guardian-events\"\n", true, "sqs", 1024, ""},
		{"kinesis sin stream_name se rechaza", "events:\n  enabled: true\n  sink: kinesis\n", false, "", 0, "events.kinesis.stream_name"},
		{"kinesis completo", "events:\n  enabled: true\n  sink: kinesis\n  kinesis:\n    stream_name: guardian-events\n", true, "kinesis", 1024, ""},
		{"kafka sin brokers se rechaza", "events:\n  enabled: true\n  sink: kafka\n  kafka:\n    topic: guardian-events\n", false, "", 0, "events.kafka.brokers"},
		{"kafka completo", "events:\n  enabled: true\n  sink: kafka\n  kafka:\n    brokers: [\"kafka:9092\"]\n    topic: guardian-events\n", true, "kafka", 1024, ""},
		{"batch_size fuera de rango", "events:\n  enabled: true\n  sink: log\n  batch_size: 900\n", false, "", 0, "events.batch_size"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "guardian.yml")
			if err := os.WriteFile(path, []byte(base+c.extra), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want que contenga %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Events.Enabled != c.wantEnabled || cfg.Events.Sink != c.wantSink || cfg.Events.Buffer != c.wantBuffer {
				t.Fatalf("events = %+v", cfg.Events)
			}
		})
	}
}

func TestLoadEventsBatchSettings(t *testing.T) {
	yml := base + "events:\n  enabled: true\n  sink: kinesis\n  batch_size: 25\n  flush_interval: 250ms\n  max_retries: 5\n  retry_backoff: 50ms\n  kinesis:\n    stream_name: guardian-events\n"
	path := filepath.Join(t.TempDir(), "guardian.yml")
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	e := cfg.Events
	if e.BatchSize != 25 || e.FlushInterval != 250*time.Millisecond || e.MaxRetries != 5 ||
		e.RetryBackoff != 50*time.Millisecond || e.Kinesis.StreamName != "guardian-events" {
		t.Fatalf("events = %+v", e)
	}

	// Sin esas claves salen los defaults del paso 20.
	path2 := filepath.Join(t.TempDir(), "guardian.yml")
	if err := os.WriteFile(path2, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path2)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Events.BatchSize != 100 || cfg.Events.FlushInterval != time.Second || cfg.Events.MaxRetries != 3 {
		t.Fatalf("defaults = %+v", cfg.Events)
	}
}

func TestLoadEventsKafka(t *testing.T) {
	yml := base + `events:
  enabled: true
  sink: kafka
  batch_size: 200
  kafka:
    brokers: ["b-1.guardian.abc123.c2.kafka.us-east-1.amazonaws.com:9098", "b-2.guardian.abc123.c2.kafka.us-east-1.amazonaws.com:9098"]
    topic: guardian-events
    client_id: guardian-prod
    key: ja4
    compression: lz4
    linger: 20ms
    delivery_timeout: 3s
    consumer_group: aggregator-prod
    tls:
      enabled: true
    sasl:
      mechanism: aws_msk_iam
`
	path := filepath.Join(t.TempDir(), "guardian.yml")
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	k := cfg.Events.Kafka
	if len(k.Brokers) != 2 || k.Topic != "guardian-events" || k.ClientID != "guardian-prod" || k.Key != "ja4" ||
		k.Compression != "lz4" || k.Linger != 20*time.Millisecond || k.DeliveryTimeout != 3*time.Second ||
		k.ConsumerGroup != "aggregator-prod" || !k.TLS.Enabled || k.SASL.Mechanism != "aws_msk_iam" || cfg.Events.BatchSize != 200 {
		t.Fatalf("kafka = %+v", k)
	}

	// Una clave mal escrita (KnownFields) se rechaza en vez de ignorarse.
	bad := filepath.Join(t.TempDir(), "guardian.yml")
	if err := os.WriteFile(bad, []byte(base+"events:\n  enabled: true\n  sink: kafka\n  kafka:\n    broker: [\"kafka:9092\"]\n    topic: t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil || !strings.Contains(err.Error(), "broker") {
		t.Fatalf("err = %v, quiero que mencione la clave desconocida broker", err)
	}
}
