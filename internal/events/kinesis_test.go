package events

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/kinesis/types"
)

// fakeKinesis cumple KinesisAPI sin red.
type fakeKinesis struct {
	mu     sync.Mutex
	calls  [][]types.PutRecordsRequestEntry
	stream string
	handle func(call int, recs []types.PutRecordsRequestEntry) (*kinesis.PutRecordsOutput, error)
}

func (f *fakeKinesis) PutRecords(_ context.Context, in *kinesis.PutRecordsInput, _ ...func(*kinesis.Options)) (*kinesis.PutRecordsOutput, error) {
	f.mu.Lock()
	f.calls = append(f.calls, in.Records)
	f.stream = aws.ToString(in.StreamName)
	n := len(f.calls)
	f.mu.Unlock()
	if f.handle != nil {
		return f.handle(n, in.Records)
	}
	return okPutRecords(len(in.Records)), nil
}

func (f *fakeKinesis) callSizes() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]int, len(f.calls))
	for i, c := range f.calls {
		out[i] = len(c)
	}
	return out
}

func okPutRecords(n int) *kinesis.PutRecordsOutput {
	recs := make([]types.PutRecordsResultEntry, n)
	for i := range recs {
		recs[i] = types.PutRecordsResultEntry{ShardId: aws.String("shardId-000000000000"), SequenceNumber: aws.String("1")}
	}
	return &kinesis.PutRecordsOutput{FailedRecordCount: aws.Int32(0), Records: recs}
}

func TestPartitionKey(t *testing.T) {
	if got := PartitionKey(Event{JA4: "t13d4907h2_0d8feac7bc37_7395dae3b2f3", IPHash: "abc"}); got != "t13d4907h2_0d8feac7bc37_7395dae3b2f3" {
		t.Fatalf("con JA4 debe usar el JA4, got %q", got)
	}
	if got := PartitionKey(Event{IPHash: "abc"}); got != "abc" {
		t.Fatalf("sin JA4 debe usar ip_hash, got %q", got)
	}
	if got := PartitionKey(Event{}); got != "unknown" {
		t.Fatalf("sin nada debe ser unknown, got %q", got)
	}
	if got := PartitionKey(Event{JA4: strings.Repeat("x", 400)}); len(got) != 256 {
		t.Fatalf("la key se corta en 256 caracteres, got %d", len(got))
	}
}

func TestKinesisSenderUsesJA4AsPartitionKeyAndStreamName(t *testing.T) {
	api := &fakeKinesis{}
	s := NewKinesisSender(api, "guardian-events", instantRetry(3, nil))
	evs := []Event{
		{JA4: "ja4-A", IPHash: "ip1", Route: "/api"},
		{IPHash: "ip2", Route: "/api"},
	}
	if _, err := s.Send(context.Background(), evs); err != nil {
		t.Fatal(err)
	}
	if api.stream != "guardian-events" {
		t.Fatalf("stream = %q", api.stream)
	}
	recs := api.calls[0]
	if aws.ToString(recs[0].PartitionKey) != "ja4-A" || aws.ToString(recs[1].PartitionKey) != "ip2" {
		t.Fatalf("partition keys = %q, %q", aws.ToString(recs[0].PartitionKey), aws.ToString(recs[1].PartitionKey))
	}
	if got := scoreOf(t, string(recs[0].Data)); got != 0 {
		t.Fatalf("el Data debe ser el Event en JSON, got score %d", got)
	}
}

func TestKinesisSenderSplitsAt500Records(t *testing.T) {
	api := &fakeKinesis{}
	s := NewKinesisSender(api, "s", instantRetry(3, nil))
	res, err := s.Send(context.Background(), makeEvents(1200))
	if err != nil {
		t.Fatal(err)
	}
	if got := api.callSizes(); len(got) != 3 || got[0] != 500 || got[1] != 500 || got[2] != 200 {
		t.Fatalf("llamadas = %v, quiero [500 500 200]", got)
	}
	if res.Sent != 1200 || res.Lost != 0 || res.Requests != 3 {
		t.Fatalf("res = %+v", res)
	}
}

func TestKinesisSenderRetriesOnlyFailedRecords(t *testing.T) {
	api := &fakeKinesis{handle: func(call int, recs []types.PutRecordsRequestEntry) (*kinesis.PutRecordsOutput, error) {
		out := okPutRecords(len(recs))
		if call == 1 {
			// 200 OK con FailedRecordCount=2: fallan los registros 0 y 4.
			for _, i := range []int{0, 4} {
				out.Records[i] = types.PutRecordsResultEntry{
					ErrorCode:    aws.String("ProvisionedThroughputExceededException"),
					ErrorMessage: aws.String("Rate exceeded for shard"),
				}
			}
			out.FailedRecordCount = aws.Int32(2)
		}
		return out, nil
	}}
	s := NewKinesisSender(api, "s", instantRetry(3, nil))
	res, err := s.Send(context.Background(), makeEvents(6))
	if err != nil {
		t.Fatal(err)
	}
	if got := api.callSizes(); len(got) != 2 || got[0] != 6 || got[1] != 2 {
		t.Fatalf("llamadas = %v, quiero [6 2]", got)
	}
	if a, b := scoreOf(t, string(api.calls[1][0].Data)), scoreOf(t, string(api.calls[1][1].Data)); a != 0 || b != 4 {
		t.Fatalf("el retry debe llevar los eventos 0 y 4, llevó %d y %d", a, b)
	}
	if res.Sent != 6 || res.Lost != 0 || res.Retries != 1 || res.Requests != 2 {
		t.Fatalf("res = %+v", res)
	}
}

func TestKinesisSenderGivesUpAfterMaxRetries(t *testing.T) {
	api := &fakeKinesis{handle: func(_ int, recs []types.PutRecordsRequestEntry) (*kinesis.PutRecordsOutput, error) {
		out := okPutRecords(len(recs))
		out.Records[0] = types.PutRecordsResultEntry{ErrorCode: aws.String("InternalFailure")}
		out.FailedRecordCount = aws.Int32(1)
		return out, nil
	}}
	s := NewKinesisSender(api, "s", instantRetry(2, nil))
	res, err := s.Send(context.Background(), makeEvents(3))
	if err == nil || !strings.Contains(err.Error(), "InternalFailure") {
		t.Fatalf("err = %v, quiero que mencione InternalFailure", err)
	}
	if got := api.callSizes(); len(got) != 3 {
		t.Fatalf("llamadas = %v, quiero 3 (1 + 2 retries)", got)
	}
	if res.Sent != 2 || res.Lost != 1 || res.Retries != 2 {
		t.Fatalf("res = %+v", res)
	}
}

func TestKinesisSenderWholeCallErrorCountsLost(t *testing.T) {
	api := &fakeKinesis{handle: func(int, []types.PutRecordsRequestEntry) (*kinesis.PutRecordsOutput, error) {
		return nil, errors.New("ResourceNotFoundException")
	}}
	s := NewKinesisSender(api, "s", instantRetry(3, nil))
	res, err := s.Send(context.Background(), makeEvents(4))
	if err == nil {
		t.Fatal("esperaba error")
	}
	if res.Lost != 4 || len(api.callSizes()) != 1 {
		t.Fatalf("res = %+v calls=%v", res, api.callSizes())
	}
}

func TestKinesisSenderMisalignedResponseRetriesEverything(t *testing.T) {
	api := &fakeKinesis{handle: func(call int, recs []types.PutRecordsRequestEntry) (*kinesis.PutRecordsOutput, error) {
		if call == 1 {
			return &kinesis.PutRecordsOutput{FailedRecordCount: aws.Int32(1)}, nil // sin Records: no se puede alinear
		}
		return okPutRecords(len(recs)), nil
	}}
	s := NewKinesisSender(api, "s", instantRetry(3, nil))
	res, err := s.Send(context.Background(), makeEvents(3))
	if err != nil {
		t.Fatal(err)
	}
	if got := api.callSizes(); len(got) != 2 || got[1] != 3 {
		t.Fatalf("llamadas = %v, quiero [3 3]", got)
	}
	if res.Sent != 3 || res.Lost != 0 {
		t.Fatalf("res = %+v", res)
	}
}
