package events

import (
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// isolateAWSEnv evita que la máquina del desarrollador (~/.aws, perfiles,
// metadata de EC2) influya en estos tests.
func isolateAWSEnv(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_ENDPOINT_URL", "")
}

func TestNewSinkBuildsSQSAndKinesisFromEnv(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_ENDPOINT_URL", "http://localhost:4566")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, cfg := range []Config{
		{Enabled: true, Sink: "sqs", SQS: SQSConfig{QueueURL: "http://localhost:4566/000000000000/guardian-events"}},
		{Enabled: true, Sink: "kinesis", Kinesis: KinesisConfig{StreamName: "guardian-events"}},
	} {
		sink, err := NewSink(cfg, log, prometheus.NewRegistry())
		if err != nil {
			t.Fatalf("%s: %v", cfg.Sink, err)
		}
		if _, ok := sink.(*Batcher); !ok {
			t.Fatalf("%s: quiero un *Batcher, got %T", cfg.Sink, sink)
		}
		_ = sink.Close(t.Context())
	}
}

func TestNewSinkFailsFastWithoutRegionOrCredentials(t *testing.T) {
	isolateAWSEnv(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{Enabled: true, Sink: "sqs", SQS: SQSConfig{QueueURL: "http://localhost:4566/000000000000/q"}}

	if _, err := NewSink(cfg, log, prometheus.NewRegistry()); err == nil || !strings.Contains(err.Error(), "AWS_REGION") {
		t.Fatalf("sin región: err = %v, quiero que mencione AWS_REGION", err)
	}
	t.Setenv("AWS_REGION", "us-east-1")
	if _, err := NewSink(cfg, log, prometheus.NewRegistry()); err == nil || !strings.Contains(err.Error(), "credenciales") {
		t.Fatalf("sin credenciales: err = %v, quiero que mencione credenciales", err)
	}
}

func TestNewSinkRejectsKafkaUntilStep22(t *testing.T) {
	_, err := NewSink(Config{Sink: "kafka"}, nil, prometheus.NewRegistry())
	if err == nil || !strings.Contains(err.Error(), "events.sink kafka Not Implemented Yet") {
		t.Fatalf("err = %v", err)
	}
}
