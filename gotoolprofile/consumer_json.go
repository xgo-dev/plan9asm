package gotoolprofile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// ConsumerInputJSONLimit bounds one complete private invocation artifact.
// Test-declaration inputs retain their full original dependency/source closure;
// the old 4 MiB reader truncated valid inputs that the producer had written.
// This transport bound grants no source, signature, object or profile proof.
const ConsumerInputJSONLimit = 32 << 20

func MarshalConsumerInput(input *ConsumerInput) ([]byte, error) {
	if input == nil {
		return nil, fmt.Errorf("missing explicit feature profile input")
	}
	data, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("encode explicit feature profile: %w", err)
	}
	if len(data) > ConsumerInputJSONLimit {
		return nil, fmt.Errorf("explicit feature profile JSON has %d bytes, exceeds its %d-byte bound", len(data), ConsumerInputJSONLimit)
	}
	return data, nil
}

func DecodeConsumerInput(reader io.Reader) (*ConsumerInput, error) {
	if reader == nil {
		return nil, fmt.Errorf("missing explicit feature profile reader")
	}
	data, err := io.ReadAll(io.LimitReader(reader, ConsumerInputJSONLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read explicit feature profile JSON: %w", err)
	}
	if len(data) > ConsumerInputJSONLimit {
		return nil, fmt.Errorf("explicit feature profile JSON exceeds its %d-byte bound", ConsumerInputJSONLimit)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var input *ConsumerInput
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("decode explicit feature profile: %w", err)
	}
	if input == nil {
		return nil, fmt.Errorf("missing explicit feature profile input")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("explicit feature profile contains trailing input")
	}
	return input, nil
}
