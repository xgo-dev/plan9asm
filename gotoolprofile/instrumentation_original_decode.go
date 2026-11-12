package gotoolprofile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Original inventories are shared inputs, rather than repeated contents in
// each plan/export proof. Readers require the independently expected original
// input, source inventory, mode observation and scope; no decoded success flag
// or omitted field can supply those prerequisites.
func DecodeInstrumentationOriginalSourceInventory(reader io.Reader, input *ConsumerInput, directory string) (*InstrumentationOriginalSourceInventory, error) {
	var proof InstrumentationOriginalSourceInventory
	if err := decodeInstrumentationOriginalJSON(reader, 32<<20, &proof); err != nil {
		return nil, err
	}
	if err := ValidateInstrumentationOriginalSourceInventory(input, directory, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}

func DecodeInstrumentationOriginalExport(reader io.Reader, input *ConsumerInput, inventory *InstrumentationOriginalSourceInventory, marker *InstrumentationExportObservation, plan *InstrumentationOriginalPackagePlan) (*InstrumentationOriginalExportProof, error) {
	var proof InstrumentationOriginalExportProof
	if err := decodeInstrumentationOriginalJSON(reader, 8<<20, &proof); err != nil {
		return nil, err
	}
	if err := ValidateInstrumentationOriginalExport(input, inventory, marker, plan, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}

func decodeInstrumentationOriginalJSON(reader io.Reader, limit int64, destination any) error {
	if reader == nil {
		return fmt.Errorf("missing bounded original instrumentation proof reader")
	}
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return err
	}
	if len(data) == 0 || int64(len(data)) > limit {
		return fmt.Errorf("original instrumentation proof exceeds its JSON byte bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("original instrumentation proof contains trailing input")
	}
	return nil
}
