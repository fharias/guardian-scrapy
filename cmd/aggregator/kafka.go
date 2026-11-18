package main

// Consumer de Kafka del aggregator. Misma semántica que SQS:
// at-least-once. El offset se hace commit SOLO después de aplicar el lote en
// Valkey; si el proceso muere antes, el consumer group reentrega desde el
// último commit, y como Apply es idempotente (PFADD), no pasa nada.

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/fharias/guardian-scrapy/internal/events"
	"github.com/fharias/guardian-scrapy/internal/reputation"
)

const kafkaMaxPollRecords = 500 // tope de records por lote

// applyRetryDelay es la espera entre intentos de Apply cuando Valkey falla.
// Variable (no const) para que los tests no esperen de verdad.
var applyRetryDelay = 2 * time.Second

// applier es lo único que el consumer necesita del aggregator.
// *reputation.Aggregator lo cumple tal cual.
type applier interface {
	Apply(ctx context.Context, evs []events.Event) ([]reputation.Marked, error)
}

// newKafkaConsumer arma un cliente de franz-go miembro del consumer group
// events.kafka.consumer_group. Conexión (brokers, TLS, SASL/IAM) igual que el
// producer de guardian: sale de events.KafkaClientOpts.
func newKafkaConsumer(ctx context.Context, k events.KafkaConfig, extra ...kgo.Opt) (*kgo.Client, error) {
	k = k.WithDefaults()
	opts, err := events.KafkaClientOpts(ctx, k)
	if err != nil {
		return nil, err
	}
	opts = append(opts,
		kgo.ConsumerGroup(k.ConsumerGroup),
		kgo.ConsumeTopics(k.Topic),
		// Sin autocommit: franz-go haría commit cada 5s de lo ya ENTREGADO por
		// PollRecords, aunque todavía no esté en Valkey (at-most-once si muere).
		kgo.DisableAutoCommit(),
		// Mientras procesamos un lote no nos quitan partitions: el rebalance
		// espera a AllowRebalance. Así nadie más procesa el mismo lote a la vez.
		kgo.BlockRebalanceOnPoll(),
		// Un grupo nuevo (sin offsets guardados) empieza en lo más viejo retenido.
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	opts = append(opts, extra...)
	return kgo.NewClient(opts...)
}

// runKafka es el loop: poll, aplicar, commit. Sale cuando ctx se cancela.
func runKafka(ctx context.Context, cl *kgo.Client, agg applier, log *slog.Logger) {
	for {
		fetches := cl.PollRecords(ctx, kafkaMaxPollRecords)
		if ctx.Err() != nil || fetches.IsClientClosed() {
			cl.AllowRebalance() // con BlockRebalanceOnPoll, un poll sin AllowRebalance traba el Close
			return
		}
		failed := false
		fetches.EachError(func(topic string, p int32, err error) {
			failed = true
			log.Warn("fetch", "topic", topic, "partition", p, "err", err)
		})
		recs := fetches.Records()
		if len(recs) == 0 {
			cl.AllowRebalance()
			if failed {
				sleep(ctx, 2*time.Second) // ej. el topic no existe: no martilles al broker
			}
			continue
		}
		ok := handleKafka(ctx, cl, agg, recs, log)
		cl.AllowRebalance()
		if !ok {
			return // apagado a mitad de lote: sin commit, se reentrega al volver
		}
	}
}

// handleKafka decodifica, aplica (con retry mientras Valkey falle) y SOLO
// entonces hace commit. Devuelve false si ctx se canceló antes de aplicar.
//
// Diferencia clave con SQS: en Kafka NO hay visibility timeout. Si no haces
// commit y sigues con el siguiente poll, el cliente avanza igual en memoria
// y ese lote no vuelve hasta un reinicio o rebalance. Por eso el retry es aquí,
// bloqueando la partition, y no "dejarlo para después".
func handleKafka(ctx context.Context, cl *kgo.Client, agg applier, recs []*kgo.Record, log *slog.Logger) bool {
	evs := make([]events.Event, 0, len(recs))
	for _, r := range recs {
		var ev events.Event
		if err := json.Unmarshal(r.Value, &ev); err != nil {
			// Poison message: se salta y su offset se commitea con el resto.
			log.Warn("record inválido descartado", "partition", r.Partition, "offset", r.Offset, "err", err)
			continue
		}
		evs = append(evs, ev)
	}

	var marked []reputation.Marked
	for attempt := 1; ; attempt++ {
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		m, err := agg.Apply(actx, evs)
		cancel()
		if err == nil {
			marked = m
			break
		}
		log.Warn("lote no aplicado; reintento sin commit", "records", len(recs), "intento", attempt, "err", err)
		sleep(ctx, applyRetryDelay)
		if ctx.Err() != nil {
			return false
		}
	}
	for _, mk := range marked {
		log.Info("ja4_marcado", "ja4", mk.JA4, "distinct_ips", mk.DistinctIPs)
	}

	// CommitRecords guarda, por partition, el offset del último record + 1.
	// Contexto propio: si llegó SIGTERM, igual guardamos lo ya aplicado.
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := cl.CommitRecords(cctx, recs...); err != nil {
		// Ya aplicado; si se reentrega, Apply es idempotente.
		log.Warn("commit falló; el lote puede reentregarse", "records", len(recs), "err", err)
	}
	log.Info("lote", "records", len(recs), "eventos", len(evs), "marcados", len(marked))
	return true
}
