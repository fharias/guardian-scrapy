// Command aggregator consume los eventos de guardian desde SQS (paso 21) o
// desde Kafka/MSK (paso 22, kafka.go), según events.sink del mismo YAML,
// cuenta IPs distintas por JA4 con HyperLogLog en Valkey y marca con TTL
// los JA4 que aparecen en demasiadas IPs. guardian lee esa marca en el scorer.
//
// Semántica: at-least-once. Un mensaje se borra de SQS (o su offset se
// commitea en Kafka) SOLO después de aplicarlo en Valkey. Si el proceso muere
// en medio, se reentrega, y como Apply es idempotente, no pasa nada.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/redis/go-redis/v9"

	"github.com/fharias/guardian-scrapy/internal/config"
	"github.com/fharias/guardian-scrapy/internal/events"
	"github.com/fharias/guardian-scrapy/internal/reputation"
)

const (
	waitTimeSeconds   = 20 // long polling: la llamada espera hasta 20 s si la cola está vacía
	maxMessages       = 10 // el máximo de SQS por ReceiveMessage
	visibilityTimeout = 30 // segundos que el mensaje queda oculto a otros consumidores
)

// SQSAPI es lo único que usamos del cliente. *sqs.Client la cumple.
type SQSAPI interface {
	ReceiveMessage(ctx context.Context, in *sqs.ReceiveMessageInput, optFns ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error)
	DeleteMessageBatch(ctx context.Context, in *sqs.DeleteMessageBatchInput, optFns ...func(*sqs.Options)) (*sqs.DeleteMessageBatchOutput, error)
}

func main() {
	path := flag.String("config", "guardian-config.yml", "el MISMO YAML de guardian")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load(*path)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	if !cfg.Reputation.Enabled {
		log.Error("reputation.enabled es false: el aggregator no tiene nada que hacer")
		os.Exit(1)
	}
	if cfg.Events.Sink != events.SinkSQS && cfg.Events.Sink != events.SinkKafka {
		log.Error("el aggregator consume de SQS o Kafka (Kinesis: Not Implemented Yet)", "sink", cfg.Events.Sink)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rdb := redis.NewUniversalClient(&redis.UniversalOptions{Addrs: []string{cfg.RedisAddr}})
	defer rdb.Close()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Error("valkey", "addr", cfg.RedisAddr, "err", err)
		os.Exit(1)
	}

	agg := reputation.NewAggregator(rdb, cfg.App, cfg.Reputation)
	rep := cfg.Reputation // ya trae defaults: config.Load los aplicó

	if cfg.Events.Sink == events.SinkKafka {
		k := cfg.Events.Kafka // ya trae defaults: config.Load los aplicó
		cl, err := newKafkaConsumer(ctx, k)
		if err != nil {
			log.Error("kafka", "err", err)
			os.Exit(1)
		}
		// Sale del consumer group: sus partitions pasan a otra réplica de inmediato.
		// CloseAllowingRebalance (no Close) porque usamos BlockRebalanceOnPoll.
		defer cl.CloseAllowingRebalance()
		log.Info("aggregator", "source", "kafka", "brokers", k.Brokers, "topic", k.Topic,
			"group", k.ConsumerGroup, "redis", cfg.RedisAddr,
			"window", rep.Window.String(), "bucket", rep.Bucket.String(),
			"min_distinct_ips", rep.MinDistinctIPs, "ttl", rep.TTL.String())
		runKafka(ctx, cl, agg, log)
		log.Info("aggregator detenido")
		return
	}

	client, err := events.NewSQSClient(ctx)
	if err != nil {
		log.Error("sqs", "err", err)
		os.Exit(1)
	}
	log.Info("aggregator", "queue", cfg.Events.SQS.QueueURL, "redis", cfg.RedisAddr,
		"window", rep.Window.String(), "bucket", rep.Bucket.String(),
		"min_distinct_ips", rep.MinDistinctIPs, "ttl", rep.TTL.String())

	run(ctx, client, cfg.Events.SQS.QueueURL, agg, log)
	log.Info("aggregator detenido")
}

// run es el loop: recibir, aplicar, borrar. Sale cuando ctx se cancela.
func run(ctx context.Context, api SQSAPI, queueURL string, agg *reputation.Aggregator, log *slog.Logger) {
	for ctx.Err() == nil {
		out, err := api.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
			QueueUrl:            aws.String(queueURL),
			MaxNumberOfMessages: maxMessages,
			WaitTimeSeconds:     waitTimeSeconds,
			VisibilityTimeout:   visibilityTimeout,
		})
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			log.Warn("receive", "err", err)
			sleep(ctx, 2*time.Second) // no martilles SQS si está fallando
			continue
		}
		if len(out.Messages) == 0 {
			continue // el long poll venció sin mensajes
		}
		if err := handle(ctx, api, queueURL, agg, out.Messages, log); err != nil {
			// No borramos: volverán tras el visibility timeout (at-least-once).
			log.Warn("lote no aplicado; SQS lo reentregará", "msgs", len(out.Messages), "err", err)
		}
	}
}

// handle decodifica, aplica en Valkey y SOLO entonces borra de SQS.
// Usa un contexto propio: si llega SIGTERM a mitad de lote, igual terminamos
// de aplicar y borrar lo que ya tenemos en mano.
func handle(parent context.Context, api SQSAPI, queueURL string, agg *reputation.Aggregator, msgs []types.Message, log *slog.Logger) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 10*time.Second)
	defer cancel()

	evs := make([]events.Event, 0, len(msgs))
	for _, m := range msgs {
		var ev events.Event
		if err := json.Unmarshal([]byte(aws.ToString(m.Body)), &ev); err != nil {
			// Poison message: reintentarlo no lo arregla. Se borra igual (abajo)
			// para que no vuelva para siempre. En AWS, una DLQ lo guardaría.
			log.Warn("mensaje inválido descartado", "id", aws.ToString(m.MessageId), "err", err)
			continue
		}
		evs = append(evs, ev)
	}

	marked, err := agg.Apply(ctx, evs)
	if err != nil {
		return err
	}
	for _, mk := range marked {
		log.Info("ja4_marcado", "ja4", mk.JA4, "distinct_ips", mk.DistinctIPs)
	}

	entries := make([]types.DeleteMessageBatchRequestEntry, len(msgs))
	for i, m := range msgs {
		entries[i] = types.DeleteMessageBatchRequestEntry{Id: aws.String(strconv.Itoa(i)), ReceiptHandle: m.ReceiptHandle}
	}
	out, err := api.DeleteMessageBatch(ctx, &sqs.DeleteMessageBatchInput{QueueUrl: aws.String(queueURL), Entries: entries})
	if err != nil {
		return err // ya aplicado; si se reentrega, Apply es idempotente
	}
	for _, f := range out.Failed {
		log.Warn("delete falló; el mensaje volverá", "id", aws.ToString(f.Id), "code", aws.ToString(f.Code))
	}
	log.Info("lote", "msgs", len(msgs), "eventos", len(evs), "marcados", len(marked))
	return nil
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
