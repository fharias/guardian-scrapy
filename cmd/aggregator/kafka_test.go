package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kfake"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/fharias/guardian-scrapy/internal/events"
	"github.com/fharias/guardian-scrapy/internal/reputation"
)

// fakeApplier guarda lo aplicado y puede fallar las primeras llamadas.
type fakeApplier struct {
	mu        sync.Mutex
	got       []events.Event
	failFirst int
	calls     int
}

func (f *fakeApplier) Apply(_ context.Context, evs []events.Event) ([]reputation.Marked, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failFirst {
		return nil, errors.New("valkey caído")
	}
	f.got = append(f.got, evs...)
	return nil, nil
}

func (f *fakeApplier) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

func produce(t *testing.T, addrs []string, values ...[]byte) {
	t.Helper()
	cl, err := kgo.NewClient(kgo.SeedBrokers(addrs...), kgo.DefaultProduceTopic("guardian-events"))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	recs := make([]*kgo.Record, len(values))
	for i, v := range values {
		recs[i] = &kgo.Record{Key: []byte(fmt.Sprintf("ip-%d", i%3)), Value: v}
	}
	if err := cl.ProduceSync(t.Context(), recs...).FirstErr(); err != nil {
		t.Fatal(err)
	}
}

func eventJSON(t *testing.T, ip string) []byte {
	t.Helper()
	b, err := json.Marshal(events.Event{Time: time.Now().UTC(), IPHash: ip, JA4: "t13d4907h2_0d8feac7bc37_7395dae3b2f3"})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// consumeUntil corre runKafka con un consumer nuevo del grupo hasta que el
// applier tenga want eventos, y luego lo apaga como lo haría SIGTERM.
func consumeUntil(t *testing.T, addrs []string, agg *fakeApplier, want int) {
	t.Helper()
	k := events.KafkaConfig{Brokers: addrs, Topic: "guardian-events", ConsumerGroup: "guardian-aggregator"}
	cl, err := newKafkaConsumer(t.Context(), k)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.CloseAllowingRebalance()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runKafka(ctx, cl, agg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	deadline := time.Now().Add(15 * time.Second)
	for agg.count() < want {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("el applier recibió %d de %d eventos", agg.count(), want)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestKafkaConsumerAppliesRetriesAndCommits(t *testing.T) {
	old := applyRetryDelay
	applyRetryDelay = 10 * time.Millisecond
	t.Cleanup(func() { applyRetryDelay = old })

	c, err := kfake.NewCluster(kfake.NumBrokers(1), kfake.SeedTopics(3, "guardian-events"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	addrs := c.ListenAddrs()

	// 5 eventos buenos + 1 poison message.
	produce(t, addrs, eventJSON(t, "a"), eventJSON(t, "b"), eventJSON(t, "c"),
		[]byte("{no es json"), eventJSON(t, "d"), eventJSON(t, "e"))

	// Valkey "falla" la primera vez: el lote se reintenta, no se pierde.
	agg := &fakeApplier{failFirst: 1}
	consumeUntil(t, addrs, agg, 5)
	if agg.calls < 2 {
		t.Fatalf("esperaba al menos un retry de Apply, calls = %d", agg.calls)
	}

	// Llegan 2 eventos más y arranca OTRO proceso del mismo consumer group.
	// Si el commit funcionó, solo ve los 2 nuevos (no los 5 viejos).
	produce(t, addrs, eventJSON(t, "f"), eventJSON(t, "g"))
	agg2 := &fakeApplier{}
	consumeUntil(t, addrs, agg2, 2)
	time.Sleep(200 * time.Millisecond)
	if n := agg2.count(); n != 2 {
		t.Fatalf("el segundo consumer aplicó %d eventos; con commit correcto son 2", n)
	}
}
