package events

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/twmb/franz-go/pkg/kfake"
	"github.com/twmb/franz-go/pkg/kgo"
)

const testTopic = "guardian-events"

// newKafkaCluster levanta un cluster de Kafka EN MEMORIA (kfake): habla el
// protocolo real por TCP local, sin Docker. El topic nace con 6 partitions.
func newKafkaCluster(t *testing.T) []string {
	t.Helper()
	c, err := kfake.NewCluster(kfake.NumBrokers(1), kfake.SeedTopics(6, testTopic))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c.ListenAddrs()
}

func testKafkaSender(t *testing.T, addrs []string, mutate func(*KafkaConfig)) *KafkaSender {
	t.Helper()
	k := KafkaConfig{Brokers: addrs, Topic: testTopic}
	if mutate != nil {
		mutate(&k)
	}
	s, err := NewKafkaSender(t.Context(), k, Config{}.retryPolicy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(context.Background()) })
	return s
}

// consumeN lee n records del topic desde el offset 0, en cualquier partition.
func consumeN(t *testing.T, addrs []string, n int) []*kgo.Record {
	t.Helper()
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(addrs...),
		kgo.ConsumeTopics(testTopic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var out []*kgo.Record
	for len(out) < n {
		fs := cl.PollFetches(ctx)
		if ctx.Err() != nil {
			t.Fatalf("solo llegaron %d de %d records", len(out), n)
		}
		fs.EachError(func(topic string, p int32, err error) { t.Fatalf("fetch %s/%d: %v", topic, p, err) })
		out = append(out, fs.Records()...)
	}
	return out
}

func header(r *kgo.Record, key string) string {
	for _, h := range r.Headers {
		if h.Key == key {
			return string(h.Value)
		}
	}
	return ""
}

func TestKafkaKey(t *testing.T) {
	ev := Event{IPHash: "ip1", JA4: "t13d1517h2_8daaf6152771_cb7bf5808d99"}
	if got := string(KafkaKey(ev, KafkaKeyIPHash)); got != "ip1" {
		t.Fatalf("ip_hash: got %q", got)
	}
	if got := string(KafkaKey(ev, KafkaKeyJA4)); got != ev.JA4 {
		t.Fatalf("ja4: got %q", got)
	}
	if got := KafkaKey(ev, KafkaKeyNone); got != nil {
		t.Fatalf("none debe ser nil, got %q", got)
	}
	if got := string(KafkaKey(Event{JA4: "solo-ja4"}, KafkaKeyIPHash)); got != "solo-ja4" {
		t.Fatalf("sin ip_hash cae al JA4, got %q", got)
	}
	if got := string(KafkaKey(Event{}, KafkaKeyIPHash)); got != "unknown" {
		t.Fatalf("sin nada debe ser unknown, got %q", got)
	}
}

func TestKafkaWithDefaults(t *testing.T) {
	k := (Config{Sink: "kafka"}).WithDefaults().Kafka
	if k.ClientID != "guardian" || k.Key != KafkaKeyIPHash || k.Compression != "zstd" ||
		k.Linger != 5*time.Millisecond || k.DeliveryTimeout != 4*time.Second || k.ConsumerGroup != "guardian-aggregator" {
		t.Fatalf("defaults inesperados: %+v", k)
	}
	k = (KafkaConfig{Key: " JA4 ", Compression: "LZ4", Linger: 20 * time.Millisecond}).WithDefaults()
	if k.Key != "ja4" || k.Compression != "lz4" || k.Linger != 20*time.Millisecond {
		t.Fatalf("WithDefaults pisó o no normalizó valores explícitos: %+v", k)
	}
}

func TestKafkaValidate(t *testing.T) {
	ok := KafkaConfig{Brokers: []string{"kafka:9092"}, Topic: testTopic}
	cases := []struct {
		name    string
		mutate  func(*KafkaConfig)
		wantErr string
	}{
		{"mínimo válido", func(*KafkaConfig) {}, ""},
		{"sin brokers", func(k *KafkaConfig) { k.Brokers = nil }, "events.kafka.brokers es obligatorio"},
		{"broker sin puerto", func(k *KafkaConfig) { k.Brokers = []string{"kafka"} }, "host:puerto"},
		{"sin topic", func(k *KafkaConfig) { k.Topic = " " }, "events.kafka.topic"},
		{"key inválida", func(k *KafkaConfig) { k.Key = "route" }, "events.kafka.key"},
		{"compresión inválida", func(k *KafkaConfig) { k.Compression = "brotli" }, "events.kafka.compression"},
		{"linger negativo", func(k *KafkaConfig) { k.Linger = -time.Millisecond }, "events.kafka.linger"},
		{"delivery_timeout muy corto", func(k *KafkaConfig) { k.DeliveryTimeout = 500 * time.Millisecond }, "events.kafka.delivery_timeout"},
		{"delivery_timeout mayor que sendTimeout", func(k *KafkaConfig) { k.DeliveryTimeout = 10 * time.Second }, "events.kafka.delivery_timeout"},
		{"iam sin tls", func(k *KafkaConfig) { k.SASL.Mechanism = "aws_msk_iam" }, "tls.enabled"},
		{"iam con tls", func(k *KafkaConfig) { k.SASL.Mechanism = "aws_msk_iam"; k.TLS.Enabled = true }, ""},
		{"sasl desconocido", func(k *KafkaConfig) { k.SASL.Mechanism = "plain"; k.TLS.Enabled = true }, "events.kafka.sasl.mechanism"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := ok
			k.Brokers = append([]string(nil), ok.Brokers...)
			c.mutate(&k)
			err := (Config{Enabled: true, Sink: "kafka", Kafka: k}).Validate()
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("no esperaba error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, quiero que contenga %q", err, c.wantErr)
			}
		})
	}
}

func TestKafkaClientOptsSCRAMNeedsEnvAndCAFileMustBePEM(t *testing.T) {
	t.Setenv(EnvKafkaUsername, "")
	t.Setenv(EnvKafkaPassword, "")
	k := KafkaConfig{Brokers: []string{"b:9096"}, Topic: "t", TLS: KafkaTLSConfig{Enabled: true}, SASL: KafkaSASLConfig{Mechanism: "scram-sha-512"}}
	if _, err := KafkaClientOpts(t.Context(), k); err == nil || !strings.Contains(err.Error(), EnvKafkaUsername) {
		t.Fatalf("scram sin credenciales: err = %v", err)
	}
	t.Setenv(EnvKafkaUsername, "guardian")
	t.Setenv(EnvKafkaPassword, "secreto")
	if _, err := KafkaClientOpts(t.Context(), k); err != nil {
		t.Fatalf("scram con credenciales: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(bad, []byte("no soy un PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	k = KafkaConfig{Brokers: []string{"b:9094"}, Topic: "t", TLS: KafkaTLSConfig{Enabled: true, CAFile: bad}}
	if _, err := KafkaClientOpts(t.Context(), k); err == nil || !strings.Contains(err.Error(), "PEM") {
		t.Fatalf("ca_file inválido: err = %v", err)
	}
}

func TestKafkaSenderDeliversOldEventsWithKeyAndHeaders(t *testing.T) {
	addrs := newKafkaCluster(t)
	s := testKafkaSender(t, addrs, nil)
	ts := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	evs := []Event{
		{Time: ts, IPHash: "ip-a", JA4: "ja4-chrome", Route: "/api", Decision: "allow", TraceID: "8512d511aaaabbbbccccddddeeeeffff"},
		{Time: ts, IPHash: "ip-b", JA4: "ja4-chrome", Route: "/api", Decision: "challenge"},
	}
	start := time.Now().Add(-time.Second)
	res, err := s.Send(t.Context(), evs)
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent != 2 || res.Lost != 0 || res.Requests < 1 {
		t.Fatalf("res = %+v, quiero Sent 2, Lost 0 y al menos 1 Produce request", res)
	}
	got := map[string]*kgo.Record{}
	for _, r := range consumeN(t, addrs, 2) {
		got[string(r.Key)] = r
	}
	a, ok := got["ip-a"]
	if !ok {
		t.Fatalf("falta el record con key ip-a: %v", got)
	}
	var ev Event
	if err := json.Unmarshal(a.Value, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.IPHash != "ip-a" || ev.Route != "/api" || ev.TraceID != evs[0].TraceID {
		t.Fatalf("value = %+v", ev)
	}
	// El evento es "viejo" (ts fijo en el pasado) y aun así se entrega: el
	// timestamp del record es la hora de producción, no ev.Time.
	if a.Timestamp.Before(start) || !ev.Time.Equal(ts) {
		t.Fatalf("record ts = %v (quiero >= %v), ev.Time = %v (quiero %v)", a.Timestamp, start, ev.Time, ts)
	}
	if header(a, "content-type") != "application/json" || header(a, "trace_id") != evs[0].TraceID {
		t.Fatalf("headers = %+v", a.Headers)
	}
	if b := got["ip-b"]; b == nil || header(b, "trace_id") != "" {
		t.Fatalf("sin trace_id no debe ir el header: %+v", b)
	}
}

func TestKafkaSenderSameKeySamePartitionInOrder(t *testing.T) {
	addrs := newKafkaCluster(t)
	s := testKafkaSender(t, addrs, nil)
	const clients, perClient = 8, 25
	var evs []Event
	for i := range perClient {
		for c := range clients {
			evs = append(evs, Event{IPHash: fmt.Sprintf("ip-%d", c), Route: fmt.Sprintf("/r/%d", i)})
		}
	}
	if _, err := s.Send(t.Context(), evs); err != nil {
		t.Fatal(err)
	}
	partOf := map[string]int32{}
	next := map[string]int{}
	used := map[int32]bool{}
	for _, r := range consumeN(t, addrs, len(evs)) {
		k := string(r.Key)
		if p, seen := partOf[k]; seen && p != r.Partition {
			t.Fatalf("key %s llegó a las partitions %d y %d", k, p, r.Partition)
		}
		partOf[k] = r.Partition
		used[r.Partition] = true
		var ev Event
		if err := json.Unmarshal(r.Value, &ev); err != nil {
			t.Fatal(err)
		}
		// Dentro de una partition el orden se respeta: /r/0, /r/1, ... por cliente.
		if want := fmt.Sprintf("/r/%d", next[k]); ev.Route != want {
			t.Fatalf("key %s: route %s, esperaba %s (orden roto)", k, ev.Route, want)
		}
		next[k]++
	}
	if len(used) < 2 {
		t.Fatalf("8 ip_hash distintos deberían repartirse en varias partitions, usaron %d", len(used))
	}
}

func TestKafkaSenderJA4KeyGroupsByTool(t *testing.T) {
	addrs := newKafkaCluster(t)
	s := testKafkaSender(t, addrs, func(k *KafkaConfig) { k.Key = KafkaKeyJA4 })
	var evs []Event
	for i := range 20 {
		evs = append(evs, Event{IPHash: fmt.Sprintf("ip-%d", i), JA4: "t13d1517h2_8daaf6152771_cb7bf5808d99"})
	}
	if _, err := s.Send(t.Context(), evs); err != nil {
		t.Fatal(err)
	}
	parts := map[int32]int{}
	for _, r := range consumeN(t, addrs, len(evs)) {
		if string(r.Key) != evs[0].JA4 {
			t.Fatalf("key = %q, quiero el JA4", r.Key)
		}
		parts[r.Partition]++
	}
	// 20 IPs distintas, un solo JA4: TODO cae en una partition (la hot partition).
	if len(parts) != 1 {
		t.Fatalf("con key ja4 todo debe caer en una partition, got %v", parts)
	}
}

func TestKafkaSenderUnknownTopicCountsLost(t *testing.T) {
	addrs := newKafkaCluster(t)
	s := testKafkaSender(t, addrs, func(k *KafkaConfig) { k.Topic = "no-existe" })
	ctx, cancel := context.WithTimeout(t.Context(), sendTimeout)
	defer cancel()
	res, err := s.Send(ctx, []Event{{IPHash: "ip-a"}, {IPHash: "ip-b"}})
	if err == nil || res.Lost != 2 || res.Sent != 0 {
		t.Fatalf("res = %+v err = %v, quiero 2 perdidos y error", res, err)
	}
}

func TestNewSinkBuildsKafkaAndAsyncDeliversOnClose(t *testing.T) {
	addrs := newKafkaCluster(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{Enabled: true, Sink: "kafka", BatchSize: 4, FlushInterval: time.Hour,
		Kafka: KafkaConfig{Brokers: addrs, Topic: testTopic}}
	reg := prometheus.NewRegistry()
	sink, err := NewSink(cfg, log, reg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sink.(*Batcher); !ok {
		t.Fatalf("quiero un *Batcher, got %T", sink)
	}
	a := NewAsync(sink, cfg, reg)
	for i := range 10 {
		a.Emit(Event{IPHash: fmt.Sprintf("ip-%d", i%3), Route: "/api"})
	}
	// 10 eventos con batch_size 4: salen 4 + 4 por tamaño y 2 en el Close.
	if err := a.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := len(consumeN(t, addrs, 10)); got != 10 {
		t.Fatalf("llegaron %d", got)
	}
	if v := counterValue(t, reg, "guardian_events_api_requests_total", "kafka"); v < 1 {
		t.Fatalf("guardian_events_api_requests_total{sink=kafka} = %v", v)
	}
	if v := counterValue(t, reg, "guardian_events_send_failures_total", "kafka"); v != 0 {
		t.Fatalf("guardian_events_send_failures_total{sink=kafka} = %v", v)
	}
}

func TestNewSinkKafkaStartsEvenIfBrokerIsDown(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := Config{Enabled: true, Sink: "kafka", Kafka: KafkaConfig{Brokers: []string{"127.0.0.1:1"}, Topic: testTopic}}
	sink, err := NewSink(cfg, log, prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("Kafka caído no debe impedir arrancar: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_ = sink.Close(ctx)
}

func counterValue(t *testing.T, reg *prometheus.Registry, name, sink string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "sink" && l.GetValue() == sink {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	t.Fatalf("no encontré %s{sink=%q}", name, sink)
	return 0
}

func TestKafkaClientOptsMSKIAMUsesAWSCredentialChain(t *testing.T) {
	isolateAWSEnv(t)
	k := KafkaConfig{Brokers: []string{"b-1.guardian.abc123.c2.kafka.us-east-1.amazonaws.com:9098"}, Topic: "t",
		TLS: KafkaTLSConfig{Enabled: true}, SASL: KafkaSASLConfig{Mechanism: "aws_msk_iam"}}
	if _, err := KafkaClientOpts(t.Context(), k); err == nil || !strings.Contains(err.Error(), "AWS_REGION") {
		t.Fatalf("sin región: err = %v", err)
	}
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	if _, err := KafkaClientOpts(t.Context(), k); err != nil {
		t.Fatalf("con credenciales: %v", err)
	}
}
