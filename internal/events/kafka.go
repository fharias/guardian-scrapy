package events

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl"
	saslaws "github.com/twmb/franz-go/pkg/sasl/aws"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

// Valores de events.kafka.key: qué campo del evento va como key del record.
const (
	KafkaKeyIPHash = "ip_hash" // default: reparte parejo y ordena por cliente
	KafkaKeyJA4    = "ja4"     // igual que Kinesis: agrupa por herramienta (ojo hot partition)
	KafkaKeyNone   = "none"    // sin key: el partitioner arma batches grandes, sin orden

	// Mecanismos de events.kafka.sasl.mechanism.
	KafkaSASLNone   = ""
	KafkaSASLScram  = "scram-sha-512" // MSK: usuario y clave en Secrets Manager
	KafkaSASLMSKIAM = "aws_msk_iam"   // MSK: el rol de la tarea de ECS, sin claves

	DefaultKafkaClientID        = "guardian"
	DefaultKafkaCompression     = "zstd"
	DefaultKafkaLinger          = 5 * time.Millisecond
	DefaultKafkaDeliveryTimeout = 4 * time.Second // menor que sendTimeout (5s)
	DefaultKafkaConsumerGroup   = "guardian-aggregator"

	// Las credenciales SCRAM NUNCA van en el YAML.
	EnvKafkaUsername = "GUARDIAN_KAFKA_USERNAME"
	EnvKafkaPassword = "GUARDIAN_KAFKA_PASSWORD"

	// kafkaProduceKey es el código del Produce request en el protocolo de Kafka.
	kafkaProduceKey int16 = 0
)

// KafkaTLSConfig vive bajo events.kafka.tls. En MSK el puerto TLS es el 9094
// (9098 con IAM). El certificado de MSK lo firma una CA pública de Amazon,
// así que basta con las raíces del sistema; ca_file es para clusters propios.
type KafkaTLSConfig struct {
	Enabled bool   `yaml:"enabled"`
	CAFile  string `yaml:"ca_file"`
}

// KafkaSASLConfig vive bajo events.kafka.sasl.
type KafkaSASLConfig struct {
	Mechanism string `yaml:"mechanism"` // "" | scram-sha-512 | aws_msk_iam
}

// KafkaConfig vive bajo events.kafka.
type KafkaConfig struct {
	Brokers         []string        `yaml:"brokers"`          // seed brokers host:puerto; con uno basta para descubrir el resto
	Topic           string          `yaml:"topic"`            // el topic debe existir: guardian no lo crea
	ClientID        string          `yaml:"client_id"`        // aparece en los logs y quotas del broker; default guardian
	Key             string          `yaml:"key"`              // ip_hash (default) | ja4 | none
	Compression     string          `yaml:"compression"`      // none | gzip | snappy | lz4 | zstd (default)
	Linger          time.Duration   `yaml:"linger"`           // espera por partition antes de cortar un request; default 5ms
	DeliveryTimeout time.Duration   `yaml:"delivery_timeout"` // tope por record, con retries; entre 1s y 5s; default 4s
	ConsumerGroup   string          `yaml:"consumer_group"`   // solo lo usa cmd/aggregator; default guardian-aggregator
	TLS             KafkaTLSConfig  `yaml:"tls"`
	SASL            KafkaSASLConfig `yaml:"sasl"`
}

// WithDefaults rellena lo que el YAML no trae. Config.WithDefaults la llama.
func (k KafkaConfig) WithDefaults() KafkaConfig {
	if strings.TrimSpace(k.ClientID) == "" {
		k.ClientID = DefaultKafkaClientID
	}
	k.Key = strings.ToLower(strings.TrimSpace(k.Key))
	if k.Key == "" {
		k.Key = KafkaKeyIPHash
	}
	k.Compression = strings.ToLower(strings.TrimSpace(k.Compression))
	if k.Compression == "" {
		k.Compression = DefaultKafkaCompression
	}
	if k.Linger == 0 {
		k.Linger = DefaultKafkaLinger
	}
	if k.DeliveryTimeout == 0 {
		k.DeliveryTimeout = DefaultKafkaDeliveryTimeout
	}
	if strings.TrimSpace(k.ConsumerGroup) == "" {
		k.ConsumerGroup = DefaultKafkaConsumerGroup
	}
	k.SASL.Mechanism = strings.ToLower(strings.TrimSpace(k.SASL.Mechanism))
	return k
}

// Validate revisa events.kafka. Config.Validate la llama solo con sink kafka.
func (k KafkaConfig) Validate() error {
	var errs []error
	if len(k.Brokers) == 0 {
		errs = append(errs, errors.New("events.kafka.brokers es obligatorio con sink kafka, ej. [\"kafka:9092\"] o los bootstrap brokers de MSK"))
	}
	for _, b := range k.Brokers {
		if _, port, err := net.SplitHostPort(strings.TrimSpace(b)); err != nil || port == "" {
			errs = append(errs, fmt.Errorf("events.kafka.brokers: %q debe ser host:puerto", b))
		}
	}
	if strings.TrimSpace(k.Topic) == "" {
		errs = append(errs, errors.New("events.kafka.topic es obligatorio con sink kafka"))
	}
	switch strings.ToLower(strings.TrimSpace(k.Key)) {
	case "", KafkaKeyIPHash, KafkaKeyJA4, KafkaKeyNone:
	default:
		errs = append(errs, fmt.Errorf("events.kafka.key %q no es válido: usa ip_hash, ja4 o none", k.Key))
	}
	if _, err := compressionCodec(k.Compression); err != nil {
		errs = append(errs, err)
	}
	if k.Linger < 0 || k.Linger > time.Second {
		errs = append(errs, errors.New("events.kafka.linger debe estar entre 0 y 1s"))
	}
	// franz-go exige al menos 1s; más de sendTimeout no sirve porque el Batcher
	// corta el envío a los 5s de todas formas.
	if k.DeliveryTimeout != 0 && (k.DeliveryTimeout < time.Second || k.DeliveryTimeout > sendTimeout) {
		errs = append(errs, fmt.Errorf("events.kafka.delivery_timeout debe estar entre 1s y %s", sendTimeout))
	}
	switch strings.ToLower(strings.TrimSpace(k.SASL.Mechanism)) {
	case KafkaSASLNone:
	case KafkaSASLScram, KafkaSASLMSKIAM:
		if !k.TLS.Enabled {
			errs = append(errs, fmt.Errorf("events.kafka.sasl.mechanism %s exige events.kafka.tls.enabled: true (MSK no acepta SASL sin TLS)", k.SASL.Mechanism))
		}
	default:
		errs = append(errs, fmt.Errorf("events.kafka.sasl.mechanism %q no es válido: usa scram-sha-512, aws_msk_iam o déjalo vacío", k.SASL.Mechanism))
	}
	return errors.Join(errs...)
}

func compressionCodec(name string) (kgo.CompressionCodec, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "zstd":
		return kgo.ZstdCompression(), nil
	case "none":
		return kgo.NoCompression(), nil
	case "gzip":
		return kgo.GzipCompression(), nil
	case "snappy":
		return kgo.SnappyCompression(), nil
	case "lz4":
		return kgo.Lz4Compression(), nil
	default:
		return kgo.CompressionCodec{}, fmt.Errorf("events.kafka.compression %q no es válido: usa none, gzip, snappy, lz4 o zstd", name)
	}
}

// KafkaKey arma la key del record. Kafka aplica murmur2 a la key y la reduce
// módulo el número de partitions: misma key, misma partition, mismo orden.
//   - ip_hash: miles de valores distintos, reparto parejo; orden por cliente.
//   - ja4: igual que la partition key de Kinesis (PartitionKey); un JA4 muy
//     común (el de Chrome) concentra el tráfico en UNA partition.
//   - none: nil; el partitioner llena una partition y salta a otra (sticky).
func KafkaKey(ev Event, mode string) []byte {
	switch mode {
	case KafkaKeyNone:
		return nil
	case KafkaKeyJA4:
		return []byte(PartitionKey(ev))
	default:
		if ev.IPHash != "" {
			return []byte(ev.IPHash)
		}
		return []byte(PartitionKey(ev)) // sin IP: JA4 o "unknown"
	}
}

// KafkaClientOpts son las opciones de conexión que comparten el producer de
// guardian y el consumer de cmd/aggregator: brokers, client_id, TLS y SASL.
func KafkaClientOpts(ctx context.Context, k KafkaConfig) ([]kgo.Opt, error) {
	k = k.WithDefaults()
	brokers := make([]string, 0, len(k.Brokers))
	for _, b := range k.Brokers {
		brokers = append(brokers, strings.TrimSpace(b))
	}
	opts := []kgo.Opt{
		kgo.SeedBrokers(brokers...),
		kgo.ClientID(k.ClientID),
	}
	if k.TLS.Enabled {
		tc := &tls.Config{MinVersion: tls.VersionTLS12}
		if k.TLS.CAFile != "" {
			pem, err := os.ReadFile(k.TLS.CAFile)
			if err != nil {
				return nil, fmt.Errorf("events.kafka.tls.ca_file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("events.kafka.tls.ca_file %s no tiene certificados PEM", k.TLS.CAFile)
			}
			tc.RootCAs = pool
		}
		opts = append(opts, kgo.DialTLSConfig(tc))
	}
	mech, err := kafkaSASL(ctx, k.SASL.Mechanism)
	if err != nil {
		return nil, err
	}
	if mech != nil {
		opts = append(opts, kgo.SASL(mech))
	}
	return opts, nil
}

func kafkaSASL(ctx context.Context, mechanism string) (sasl.Mechanism, error) {
	switch mechanism {
	case KafkaSASLNone:
		return nil, nil
	case KafkaSASLScram:
		user, pass := os.Getenv(EnvKafkaUsername), os.Getenv(EnvKafkaPassword)
		if user == "" || pass == "" {
			return nil, fmt.Errorf("sasl scram-sha-512 necesita %s y %s", EnvKafkaUsername, EnvKafkaPassword)
		}
		return scram.Auth{User: user, Pass: pass}.AsSha512Mechanism(), nil
	case KafkaSASLMSKIAM:
		// Las mismas credenciales que SQS y Kinesis: la cadena estándar del SDK
		// (rol de la tarea de ECS en producción). Se piden en CADA autenticación
		// porque las credenciales de un rol rotan; el SDK las cachea.
		awsCfg, err := loadAWSConfig(ctx)
		if err != nil {
			return nil, err
		}
		return saslaws.ManagedStreamingIAM(func(ctx context.Context) (saslaws.Auth, error) {
			c, err := awsCfg.Credentials.Retrieve(ctx)
			if err != nil {
				return saslaws.Auth{}, err
			}
			return saslaws.Auth{AccessKey: c.AccessKeyID, SecretKey: c.SecretAccessKey, SessionToken: c.SessionToken, UserAgent: "guardian"}, nil
		}), nil
	default:
		return nil, fmt.Errorf("events.kafka.sasl.mechanism %q no es válido", mechanism)
	}
}

// produceCounter cuenta los Produce requests que el cliente escribe a los
// brokers. Es el equivalente de "llamadas a la API" de SQS y Kinesis.
type produceCounter struct{ n atomic.Int64 }

func (c *produceCounter) OnBrokerWrite(_ kgo.BrokerMetadata, key int16, _ int, _, _ time.Duration, err error) {
	if key == kafkaProduceKey && err == nil {
		c.n.Add(1)
	}
}

// KafkaSender envía batches de eventos a un topic de Kafka (MSK en AWS).
// Cumple BatchSender: el Batcher, el Async y las métricas son los mismos de
// SQS y Kinesis. Los retries los hace franz-go por dentro (con el producer
// idempotente no duplican), acotados por delivery_timeout.
type KafkaSender struct {
	client  *kgo.Client
	topic   string
	keyMode string
	reqs    *produceCounter
}

// NewKafkaSender crea el cliente de franz-go. No abre conexiones todavía:
// franz-go conecta en el primer uso. extra existe para los tests.
func NewKafkaSender(ctx context.Context, k KafkaConfig, retry RetryPolicy, extra ...kgo.Opt) (*KafkaSender, error) {
	k = k.WithDefaults()
	opts, err := KafkaClientOpts(ctx, k)
	if err != nil {
		return nil, err
	}
	codec, err := compressionCodec(k.Compression)
	if err != nil {
		return nil, err
	}
	reqs := &produceCounter{}
	opts = append(opts,
		kgo.DefaultProduceTopic(k.Topic),
		// acks=all: el leader responde cuando TODAS las réplicas in-sync
		// escribieron. Con min.insync.replicas=2 en MSK sobrevive a perder un broker.
		kgo.RequiredAcks(kgo.AllISRAcks()),
		// El producer idempotente viene prendido por defecto en franz-go (NO
		// llamamos DisableIdempotentWrite): cada record lleva producer ID +
		// sequence number y el broker descarta los duplicados de un retry.
		kgo.ProducerBatchCompression(codec, kgo.NoCompression()),
		kgo.ProducerLinger(k.Linger),
		kgo.RecordDeliveryTimeout(k.DeliveryTimeout),
		// murmur2 sobre la key, igual que el cliente Java: la misma key cae en
		// la misma partition sin importar qué cliente la produjo.
		kgo.RecordPartitioner(kgo.UniformBytesPartitioner(64<<10, true, true, nil)),
		kgo.RetryBackoffFn(func(n int) time.Duration { return retry.delay(max(n, 1)) }),
		kgo.WithHooks(reqs),
	)
	opts = append(opts, extra...)
	client, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("creando el cliente de Kafka: %w", err)
	}
	return &KafkaSender{client: client, topic: k.Topic, keyMode: k.Key, reqs: reqs}, nil
}

func (s *KafkaSender) Name() string { return SinkKafka }

// Ping pregunta metadata a algún broker. NewSink lo usa para avisar en el log
// al arrancar, sin impedir que guardian arranque (los eventos no son críticos).
func (s *KafkaSender) Ping(ctx context.Context) error { return s.client.Ping(ctx) }

// Send serializa el batch y lo entrega con ProduceSync: franz-go agrupa los
// records por partition en record batches, los comprime y manda un Produce
// request por broker. Devuelve cuando todos tienen ack o fallaron.
func (s *KafkaSender) Send(ctx context.Context, batch []Event) (SendResult, error) {
	var res SendResult
	var errs []error
	recs := make([]*kgo.Record, 0, len(batch))
	for _, ev := range batch {
		b, err := json.Marshal(ev)
		if err != nil {
			res.Lost++
			errs = append(errs, fmt.Errorf("serializando evento: %w", err))
			continue
		}
		// Timestamp se deja en cero A PROPÓSITO: franz-go le pone time.Now() y
		// mide delivery_timeout desde ahí. Si pusiéramos ev.Time, un evento que
		// esperó más de 4s en el buffer nacería vencido. La hora real va en "ts".
		r := &kgo.Record{
			Key:     KafkaKey(ev, s.keyMode),
			Value:   b,
			Headers: []kgo.RecordHeader{{Key: "content-type", Value: []byte("application/json")}},
		}
		if ev.TraceID != "" {
			r.Headers = append(r.Headers, kgo.RecordHeader{Key: "trace_id", Value: []byte(ev.TraceID)})
		}
		recs = append(recs, r)
	}
	if len(recs) > 0 {
		results := s.client.ProduceSync(ctx, recs...)
		reason := ""
		failed := 0
		for _, pr := range results {
			if pr.Err != nil {
				failed++
				reason = pr.Err.Error()
			}
		}
		res.Sent += len(recs) - failed
		res.Lost += failed
		if failed > 0 {
			errs = append(errs, fmt.Errorf("%d eventos no se entregaron a %s (último error: %s)", failed, s.topic, reason))
		}
	}
	// Produce requests escritos desde el último Send. Con Sends concurrentes la
	// cuenta se reparte distinto entre batches, pero el total es exacto.
	res.Requests = int(s.reqs.n.Swap(0))
	return res, errors.Join(errs...)
}

// Close espera lo que quede en el buffer de franz-go (Flush) y cierra las
// conexiones. El Batcher lo llama después de enviar el último batch.
func (s *KafkaSender) Close(ctx context.Context) error {
	err := s.client.Flush(ctx)
	s.client.Close()
	return err
}
