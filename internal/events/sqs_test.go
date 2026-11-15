package events

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

// fakeSQS cumple SQSAPI sin red. handle decide qué responde a cada llamada.
type fakeSQS struct {
	mu     sync.Mutex
	calls  [][]types.SendMessageBatchRequestEntry
	handle func(call int, entries []types.SendMessageBatchRequestEntry) (*sqs.SendMessageBatchOutput, error)
}

func (f *fakeSQS) SendMessageBatch(_ context.Context, in *sqs.SendMessageBatchInput, _ ...func(*sqs.Options)) (*sqs.SendMessageBatchOutput, error) {
	f.mu.Lock()
	f.calls = append(f.calls, in.Entries)
	n := len(f.calls)
	f.mu.Unlock()
	if f.handle != nil {
		return f.handle(n, in.Entries)
	}
	return &sqs.SendMessageBatchOutput{}, nil
}

func (f *fakeSQS) callSizes() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]int, len(f.calls))
	for i, c := range f.calls {
		out[i] = len(c)
	}
	return out
}

// instantRetry no espera de verdad y anota las esperas pedidas.
func instantRetry(maxRetries int, sleeps *[]time.Duration) RetryPolicy {
	return RetryPolicy{
		MaxRetries: maxRetries,
		Backoff:    100 * time.Millisecond,
		MaxBackoff: time.Second,
		Sleep: func(_ context.Context, d time.Duration) error {
			if sleeps != nil {
				*sleeps = append(*sleeps, d)
			}
			return nil
		},
	}
}

func makeEvents(n int) []Event {
	evs := make([]Event, n)
	for i := range evs {
		evs[i] = Event{Route: "/api", Method: "GET", Score: i, Decision: "allow", Mode: "monitor", IPHash: "h" + strconv.Itoa(i)}
	}
	return evs
}

func scoreOf(t *testing.T, body string) int {
	t.Helper()
	var ev Event
	if err := json.Unmarshal([]byte(body), &ev); err != nil {
		t.Fatalf("el cuerpo no es un Event en JSON: %v (%s)", err, body)
	}
	return ev.Score
}

func TestSQSSenderSplitsIntoCallsOfTen(t *testing.T) {
	api := &fakeSQS{}
	s := NewSQSSender(api, "http://q", instantRetry(3, nil))
	res, err := s.Send(context.Background(), makeEvents(25))
	if err != nil {
		t.Fatal(err)
	}
	if got := api.callSizes(); len(got) != 3 || got[0] != 10 || got[1] != 10 || got[2] != 5 {
		t.Fatalf("llamadas = %v, quiero [10 10 5]", got)
	}
	if res.Sent != 25 || res.Lost != 0 || res.Retries != 0 || res.Requests != 3 {
		t.Fatalf("res = %+v", res)
	}
	// Ids únicos dentro de cada llamada (SQS rechaza Ids repetidos) y cuerpos JSON válidos.
	for _, call := range api.calls {
		seen := map[string]bool{}
		for _, e := range call {
			id := aws.ToString(e.Id)
			if seen[id] {
				t.Fatalf("Id repetido %q en una llamada", id)
			}
			seen[id] = true
			scoreOf(t, aws.ToString(e.MessageBody))
		}
	}
}

func TestSQSSenderRetriesOnlyFailedEntries(t *testing.T) {
	var failedScores []int
	api := &fakeSQS{handle: func(call int, entries []types.SendMessageBatchRequestEntry) (*sqs.SendMessageBatchOutput, error) {
		out := &sqs.SendMessageBatchOutput{}
		if call == 1 {
			// La llamada responde 200 pero rechaza las entradas 1 y 3.
			for _, e := range entries {
				if id := aws.ToString(e.Id); id == "1" || id == "3" {
					out.Failed = append(out.Failed, types.BatchResultErrorEntry{Id: e.Id, Code: aws.String("ServiceUnavailable"), SenderFault: false})
					failedScores = append(failedScores, scoreOfBody(aws.ToString(e.MessageBody)))
				}
			}
		}
		return out, nil
	}}
	var sleeps []time.Duration
	s := NewSQSSender(api, "http://q", instantRetry(3, &sleeps))
	res, err := s.Send(context.Background(), makeEvents(5))
	if err != nil {
		t.Fatal(err)
	}
	if got := api.callSizes(); len(got) != 2 || got[0] != 5 || got[1] != 2 {
		t.Fatalf("llamadas = %v, quiero [5 2]: el retry solo lleva las 2 que fallaron", got)
	}
	var retried []int
	for _, e := range api.calls[1] {
		retried = append(retried, scoreOf(t, aws.ToString(e.MessageBody)))
	}
	if len(retried) != 2 || retried[0] != failedScores[0] || retried[1] != failedScores[1] {
		t.Fatalf("retry = %v, quiero exactamente los eventos que fallaron %v", retried, failedScores)
	}
	if res.Sent != 5 || res.Lost != 0 || res.Retries != 1 || res.Requests != 2 {
		t.Fatalf("res = %+v", res)
	}
	if len(sleeps) != 1 {
		t.Fatalf("esperas = %v, quiero 1", sleeps)
	}
}

func scoreOfBody(body string) int {
	var ev Event
	_ = json.Unmarshal([]byte(body), &ev)
	return ev.Score
}

func TestSQSSenderDoesNotRetrySenderFault(t *testing.T) {
	api := &fakeSQS{handle: func(call int, entries []types.SendMessageBatchRequestEntry) (*sqs.SendMessageBatchOutput, error) {
		return &sqs.SendMessageBatchOutput{Failed: []types.BatchResultErrorEntry{
			{Id: entries[0].Id, Code: aws.String("InvalidMessageContents"), SenderFault: true},
		}}, nil
	}}
	s := NewSQSSender(api, "http://q", instantRetry(3, nil))
	res, err := s.Send(context.Background(), makeEvents(3))
	if err == nil {
		t.Fatal("esperaba error: un evento se perdió")
	}
	if got := api.callSizes(); len(got) != 1 {
		t.Fatalf("llamadas = %v: SenderFault no tiene retry", got)
	}
	if res.Sent != 2 || res.Lost != 1 || res.Retries != 0 {
		t.Fatalf("res = %+v", res)
	}
}

func TestSQSSenderGivesUpAfterMaxRetries(t *testing.T) {
	api := &fakeSQS{handle: func(call int, entries []types.SendMessageBatchRequestEntry) (*sqs.SendMessageBatchOutput, error) {
		// Rechaza SIEMPRE la primera entrada de la llamada.
		return &sqs.SendMessageBatchOutput{Failed: []types.BatchResultErrorEntry{
			{Id: entries[0].Id, Code: aws.String("ServiceUnavailable")},
		}}, nil
	}}
	var sleeps []time.Duration
	s := NewSQSSender(api, "http://q", instantRetry(2, &sleeps))
	res, err := s.Send(context.Background(), makeEvents(4))
	if err == nil {
		t.Fatal("esperaba error al agotar retries")
	}
	// 1 intento + 2 retries = 3 llamadas. La 1ª lleva 4; las otras llevan solo la que falla.
	if got := api.callSizes(); len(got) != 3 || got[0] != 4 || got[1] != 1 || got[2] != 1 {
		t.Fatalf("llamadas = %v, quiero [4 1 1]", got)
	}
	if res.Sent != 3 || res.Lost != 1 || res.Retries != 2 || res.Requests != 3 {
		t.Fatalf("res = %+v", res)
	}
	if len(sleeps) != 2 || sleeps[1] <= sleeps[0]/2 {
		t.Fatalf("el backoff debe crecer: %v", sleeps)
	}
}

func TestSQSSenderWholeCallErrorCountsLost(t *testing.T) {
	api := &fakeSQS{handle: func(int, []types.SendMessageBatchRequestEntry) (*sqs.SendMessageBatchOutput, error) {
		return nil, errors.New("connection refused")
	}}
	s := NewSQSSender(api, "http://q", instantRetry(3, nil))
	res, err := s.Send(context.Background(), makeEvents(4))
	if err == nil {
		t.Fatal("esperaba error")
	}
	// Los errores de toda la llamada ya les hizo retry el SDK; aquí no se repiten.
	if got := api.callSizes(); len(got) != 1 {
		t.Fatalf("llamadas = %v, quiero 1", got)
	}
	if res.Sent != 0 || res.Lost != 4 {
		t.Fatalf("res = %+v", res)
	}
}

func TestSQSSenderStopsRetryingWhenContextCancelled(t *testing.T) {
	api := &fakeSQS{handle: func(_ int, entries []types.SendMessageBatchRequestEntry) (*sqs.SendMessageBatchOutput, error) {
		return &sqs.SendMessageBatchOutput{Failed: []types.BatchResultErrorEntry{{Id: entries[0].Id, Code: aws.String("X")}}}, nil
	}}
	p := instantRetry(5, nil)
	p.Sleep = func(ctx context.Context, d time.Duration) error { return context.Canceled }
	s := NewSQSSender(api, "http://q", p)
	res, err := s.Send(context.Background(), makeEvents(1))
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, quiero context.Canceled", err)
	}
	if res.Lost != 1 || len(api.callSizes()) != 1 {
		t.Fatalf("res = %+v calls=%v", res, api.callSizes())
	}
}
