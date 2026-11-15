package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

// Límites de SendMessageBatch según la documentación de AWS:
// hasta 10 mensajes y 1 MiB (1.048.576 bytes) de payload total.
const (
	sqsMaxEntries = 10
	sqsMaxBytes   = 1 << 20
)

// SQSAPI es lo único que usamos del cliente de SQS. Una interfaz pequeña
// en el lado de quien consume deja probar sin red con un fake.
// *sqs.Client la cumple tal cual.
type SQSAPI interface {
	SendMessageBatch(ctx context.Context, in *sqs.SendMessageBatchInput, optFns ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error)
}

// SQSSender envía batches de eventos a una cola de SQS con SendMessageBatch.
type SQSSender struct {
	api      SQSAPI
	queueURL string
	retry    RetryPolicy
}

func NewSQSSender(api SQSAPI, queueURL string, retry RetryPolicy) *SQSSender {
	return &SQSSender{api: api, queueURL: queueURL, retry: retry}
}

func (s *SQSSender) Name() string                { return SinkSQS }
func (s *SQSSender) Close(context.Context) error { return nil }

// Send parte el batch en llamadas de a lo sumo 10 mensajes (y 1 MiB) y
// envía cada una con retries de las entradas que fallaron.
func (s *SQSSender) Send(ctx context.Context, batch []Event) (SendResult, error) {
	var total SendResult
	var errs []error
	bodies := make([]string, 0, len(batch))
	for _, ev := range batch {
		b, err := json.Marshal(ev)
		if err != nil {
			total.Lost++
			errs = append(errs, fmt.Errorf("serializando evento: %w", err))
			continue
		}
		bodies = append(bodies, string(b))
	}
	for _, group := range chunk(bodies, sqsMaxEntries, sqsMaxBytes, func(b string) int { return len(b) }) {
		res, err := sendWithRetry(ctx, s.retry, group, s.attempt)
		total.add(res)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return total, errors.Join(errs...)
}

// attempt hace UNA llamada SendMessageBatch. La respuesta puede ser HTTP 200
// y aun así traer entradas en Failed: hay que revisarlas siempre.
func (s *SQSSender) attempt(ctx context.Context, bodies []string) (attemptResult[string], error) {
	entries := make([]types.SendMessageBatchRequestEntry, len(bodies))
	byID := make(map[string]string, len(bodies))
	for i, body := range bodies {
		id := strconv.Itoa(i) // el Id solo debe ser único dentro de la llamada
		entries[i] = types.SendMessageBatchRequestEntry{Id: aws.String(id), MessageBody: aws.String(body)}
		byID[id] = body
	}
	out, err := s.api.SendMessageBatch(ctx, &sqs.SendMessageBatchInput{
		QueueUrl: aws.String(s.queueURL),
		Entries:  entries,
	})
	if err != nil {
		return attemptResult[string]{}, err
	}
	var r attemptResult[string]
	for _, f := range out.Failed {
		body, ok := byID[aws.ToString(f.Id)]
		if !ok {
			continue
		}
		r.Reason = fmt.Sprintf("%s: %s", aws.ToString(f.Code), aws.ToString(f.Message))
		if f.SenderFault {
			r.Dropped++ // culpa del mensaje (ej. contenido inválido): repetirlo no lo arregla
			continue
		}
		r.Retry = append(r.Retry, body)
	}
	return r, nil
}
