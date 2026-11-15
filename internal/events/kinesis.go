package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/kinesis/types"
)

// Límites de PutRecords según la documentación de AWS: hasta 500 registros
// y 10 MiB por llamada, contando las partition keys.
const (
	kinesisMaxRecords      = 500
	kinesisMaxBytes        = 10 << 20
	kinesisMaxPartitionKey = 256
)

// KinesisAPI es lo único que usamos del cliente de Kinesis.
// *kinesis.Client la cumple tal cual.
type KinesisAPI interface {
	PutRecords(ctx context.Context, in *kinesis.PutRecordsInput, optFns ...func(*kinesis.Options)) (*kinesis.PutRecordsOutput, error)
}

// KinesisSender envía batches de eventos a un stream con PutRecords.
type KinesisSender struct {
	api    KinesisAPI
	stream string
	retry  RetryPolicy
}

func NewKinesisSender(api KinesisAPI, streamName string, retry RetryPolicy) *KinesisSender {
	return &KinesisSender{api: api, stream: streamName, retry: retry}
}

func (s *KinesisSender) Name() string                { return SinkKinesis }
func (s *KinesisSender) Close(context.Context) error { return nil }

type kinesisRecord struct {
	data []byte
	key  string
}

func (r kinesisRecord) size() int { return len(r.data) + len(r.key) }

// PartitionKey elige la partition key de Kinesis: el JA4 del cliente y, si no
// hay (HTTP plano, ja4.source none), el ip_hash. Kinesis aplica MD5 a la key
// para escoger el shard, así que todos los eventos de un mismo JA4 caen en
// el mismo shard y llegan en orden al aggregator del paso 21.
func PartitionKey(ev Event) string {
	key := ev.JA4
	if key == "" {
		key = ev.IPHash
	}
	if key == "" {
		key = "unknown"
	}
	if len(key) > kinesisMaxPartitionKey {
		key = key[:kinesisMaxPartitionKey]
	}
	return key
}

// Send parte el batch en llamadas de a lo sumo 500 registros (y 10 MiB) y
// envía cada una haciendo retry solo de los registros que fallaron.
func (s *KinesisSender) Send(ctx context.Context, batch []Event) (SendResult, error) {
	var total SendResult
	var errs []error
	recs := make([]kinesisRecord, 0, len(batch))
	for _, ev := range batch {
		b, err := json.Marshal(ev)
		if err != nil {
			total.Lost++
			errs = append(errs, fmt.Errorf("serializando evento: %w", err))
			continue
		}
		recs = append(recs, kinesisRecord{data: b, key: PartitionKey(ev)})
	}
	for _, group := range chunk(recs, kinesisMaxRecords, kinesisMaxBytes, kinesisRecord.size) {
		res, err := sendWithRetry(ctx, s.retry, group, s.attempt)
		total.add(res)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return total, errors.Join(errs...)
}

// attempt hace UNA llamada PutRecords. Con HTTP 200 puede venir
// FailedRecordCount > 0: la respuesta trae un resultado por registro, en el
// mismo orden que la petición, y los fallidos tienen ErrorCode.
func (s *KinesisSender) attempt(ctx context.Context, recs []kinesisRecord) (attemptResult[kinesisRecord], error) {
	entries := make([]types.PutRecordsRequestEntry, len(recs))
	for i, r := range recs {
		entries[i] = types.PutRecordsRequestEntry{Data: r.data, PartitionKey: aws.String(r.key)}
	}
	out, err := s.api.PutRecords(ctx, &kinesis.PutRecordsInput{
		StreamName: aws.String(s.stream),
		Records:    entries,
	})
	if err != nil {
		return attemptResult[kinesisRecord]{}, err
	}
	var r attemptResult[kinesisRecord]
	if aws.ToInt32(out.FailedRecordCount) == 0 {
		return r, nil
	}
	if len(out.Records) != len(recs) {
		// Respuesta que no podemos alinear con la petición: haz retry de todo.
		r.Reason = "respuesta de PutRecords con tamaño inesperado"
		r.Retry = recs
		return r, nil
	}
	for i, res := range out.Records {
		if res.ErrorCode == nil {
			continue
		}
		r.Reason = fmt.Sprintf("%s: %s", aws.ToString(res.ErrorCode), aws.ToString(res.ErrorMessage))
		r.Retry = append(r.Retry, recs[i])
	}
	return r, nil
}
