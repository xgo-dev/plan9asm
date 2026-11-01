package gotoolprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func largeConsumerJSONFixture() *ConsumerInput {
	input := &ConsumerInput{
		Protocol: ConsumerProtocol, SignatureSourceProtocol: SignatureSourceProtocol,
		TestDependencySourceProtocol: TestDependencyProtocol, Module: "example.invalid/complete",
		Sources:          map[string]string{"probe.go": strings.Repeat("a", 64)},
		Headers:          map[string]string{"probe.go": "package complete\n"},
		Directories:      map[string][]string{".": {"probe.go", "probe_amd64.s"}},
		AsmFiles:         []string{"probe_amd64.s"},
		GeneratedHeaders: &MetadataProof{Protocol: MetadataProtocol},
		TestDependencies: &TestDependencyProof{
			Protocol: TestDependencyProtocol,
			Query: &SignatureQueryProof{
				Protocol: SignatureQueryProtocol,
				Requests: []SignatureRequest{{File: "probe_amd64.s", Symbol: "example.invalid/complete.probe"}},
			},
		},
	}
	// Transport tests preserve every field, not just a byte count or digest.
	// Source/layout authentication remains the separate consumer's job.
	for index := 0; index < 100; index++ {
		input.TestDependencies.SourceModules = append(input.TestDependencies.SourceModules, TestModuleSource{
			Protocol: TestDependencyModuleProtocol, SourceModule: "example.invalid/dependency",
			Headers: map[string]string{"bound.go": strings.Repeat(" ", 52<<10) + "package dependency\n"},
		})
	}
	return input
}

func TestConsumerJSONCompleteSourceClosureRoundTrip(t *testing.T) {
	input := largeConsumerJSONFixture()
	data, err := MarshalConsumerInput(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) <= 4<<20 || len(data) >= ConsumerInputJSONLimit {
		t.Fatalf("fixture does not exercise the old and new limits: %d", len(data))
	}
	canonical, err := json.Marshal(input)
	if err != nil || !bytes.Equal(data, canonical) {
		t.Fatal("bounded writer pruned or rewrote canonical source/type/closure bytes")
	}
	decoded, err := DecodeConsumerInput(bytes.NewReader(data))
	if err != nil || !reflect.DeepEqual(decoded, input) {
		t.Fatalf("complete closure changed in bounded transport: %v", err)
	}
}

func TestConsumerJSONExactReadByteBound(t *testing.T) {
	const object = `{"module":"exact"}`
	for _, size := range []int{ConsumerInputJSONLimit - 1, ConsumerInputJSONLimit, ConsumerInputJSONLimit + 1} {
		reader := io.MultiReader(strings.NewReader(object), io.LimitReader(consumerJSONSpaces{}, int64(size-len(object))))
		decoded, err := DecodeConsumerInput(reader)
		if size <= ConsumerInputJSONLimit {
			if err != nil || decoded.Module != "exact" {
				t.Fatalf("complete JSON at %d bytes: %#v, %v", size, decoded, err)
			}
		} else if decoded != nil || err == nil || !strings.Contains(err.Error(), "byte bound") || strings.Contains(err.Error(), "EOF") {
			t.Fatalf("overflow was not an explicit resource failure: %#v, %v", decoded, err)
		}
	}
	// A limited reader must not consume an unbounded suffix or mistake the
	// first valid JSON object for proof that the entire artifact fits.
	counted := &consumerJSONCountingReader{reader: consumerJSONSpaces{}}
	if _, err := DecodeConsumerInput(counted); err == nil || !strings.Contains(err.Error(), "byte bound") {
		t.Fatalf("infinite input did not fail at the resource bound: %v", err)
	}
	if counted.bytes != ConsumerInputJSONLimit+1 {
		t.Fatalf("reader consumed %d bytes rather than its bounded witness", counted.bytes)
	}
}

func TestConsumerJSONWriterOverflowAndNil(t *testing.T) {
	if data, err := MarshalConsumerInput(nil); data != nil || err == nil {
		t.Fatal("nil producer input became a valid artifact")
	}
	input := &ConsumerInput{Headers: map[string]string{"too-large.go": strings.Repeat(" ", ConsumerInputJSONLimit)}}
	if data, err := MarshalConsumerInput(input); data != nil || err == nil || !strings.Contains(err.Error(), "bytes, exceeds its") {
		t.Fatalf("writer did not reject its own complete oversized output: %v", err)
	}
}

func TestConsumerJSONWriterExactByteBound(t *testing.T) {
	input := &ConsumerInput{}
	base, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{ConsumerInputJSONLimit, ConsumerInputJSONLimit + 1} {
		input.Module = strings.Repeat("x", size-len(base))
		data, err := MarshalConsumerInput(input)
		if size == ConsumerInputJSONLimit {
			if err != nil || len(data) != size {
				t.Fatalf("canonical writer at its exact byte bound: %d, %v", len(data), err)
			}
		} else if data != nil || err == nil || !strings.Contains(err.Error(), "bytes, exceeds its") {
			t.Fatalf("writer at bound+1 lost its explicit resource failure: %v", err)
		}
	}
}

func TestConsumerJSONRejectsMalformedUnknownAndReaderFailures(t *testing.T) {
	for name, source := range map[string]string{
		"empty": "", "null": "null", "truncated": `{"module":"x"`,
		"unknown outer": `{"unbound":true}`, "unknown dependency": `{"test_declaration_dependencies":{"unbound":true}}`,
		"second object": `{}` + `{}`, "trailing garbage": `{}` + `!`,
	} {
		t.Run(name, func(t *testing.T) {
			if input, err := DecodeConsumerInput(strings.NewReader(source)); input != nil || err == nil {
				t.Fatal("malformed or unknown proof input was accepted")
			}
		})
	}
	if input, err := DecodeConsumerInput(nil); input != nil || err == nil {
		t.Fatal("nil reader was accepted")
	}
	witness := errors.New("owned read failed")
	reader := io.MultiReader(strings.NewReader(`{}`), consumerJSONErrorReader{err: witness})
	if input, err := DecodeConsumerInput(reader); input != nil || !errors.Is(err, witness) {
		t.Fatalf("valid prefix masked the underlying source read failure: %v", err)
	}
}

func BenchmarkConsumerJSONCompleteClosure(b *testing.B) {
	data, err := MarshalConsumerInput(largeConsumerJSONFixture())
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if _, err := DecodeConsumerInput(bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}

type consumerJSONSpaces struct{}

func (consumerJSONSpaces) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = ' '
	}
	return len(buffer), nil
}

type consumerJSONCountingReader struct {
	reader io.Reader
	bytes  int
}

func (reader *consumerJSONCountingReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	reader.bytes += count
	return count, err
}

type consumerJSONErrorReader struct{ err error }

func (reader consumerJSONErrorReader) Read([]byte) (int, error) { return 0, reader.err }
