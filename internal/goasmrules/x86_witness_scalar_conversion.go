package goasmrules

import (
	"fmt"
	"strings"
)

type x86LegacyScalarConversionForm struct {
	fromFloat, wide bool
	mandatory       byte
	opcodeOffset    int
}

func x86LegacyScalarConversionTable(table string) bool {
	switch table {
	case "yxcvfl", "yxcvfq", "yxcvlf", "yxcvqf":
		return true
	}
	return false
}

// Validate the complete original media row before the common encoder selects
// any payload. These are bank/width roles, never numerical or memory facts.
func x86LegacyScalarConversionProperties(entry X86LegacyOpcode, row X86LegacyOperand) (x86LegacyScalarConversionForm, error) {
	f := x86LegacyScalarConversionForm{
		fromFloat: entry.Ytab == "yxcvfl" || entry.Ytab == "yxcvfq",
		wide:      entry.Ytab == "yxcvfq" || entry.Ytab == "yxcvqf",
	}
	fail := func() (x86LegacyScalarConversionForm, error) {
		return f, fmt.Errorf("legacy scalar conversion differs from its complete source role")
	}
	if !x86LegacyScalarConversionTable(entry.Ytab) || entry.Kind != "encoding" || entry.EscapeAdjustment != 0 {
		return fail()
	}
	source, destination, found := strings.Cut(entry.Opcode, "2")
	floating, integer := destination, strings.TrimPrefix(source, "CVT")
	if f.fromFloat {
		floating, integer = strings.TrimPrefix(strings.TrimPrefix(source, "CVT"), "T"), destination
	}
	if !found || !strings.HasPrefix(source, "CVT") || floating != "SS" && floating != "SD" ||
		integer != "SL" && integer != "SQ" || (integer == "SQ") != f.wide {
		return fail()
	}
	mandatory, classes, stride := "Pf2", "Yml,Yxr", 1
	f.mandatory = 0xf2
	if floating == "SS" {
		mandatory, f.mandatory = "Pf3", 0xf3
	}
	if f.fromFloat {
		classes = "Yxm,Yrl"
	}
	if f.wide {
		stride, f.opcodeOffset = 2, 1
	}
	if err := x86ScalarCompleteOperandSchema(entry, row, []string{fmt.Sprintf("Zm_r_xm/%d/%s", stride, classes)}); err != nil {
		return f, err
	}
	if len(entry.OpBytes) != stride || !f.wide && entry.Prefix != mandatory ||
		f.wide && (entry.Prefix != "Pw" || entry.OpBytes[0] != mandatory) {
		return fail()
	}
	return f, nil
}

// X86LegacyScalarConversionRows retains all four original signed scalar
// conversion tables. Legacy Q rows stay visible when Go rejects mode386.
func X86LegacyScalarConversionRows(catalog X86LegacyCatalog, arch string) ([]X86ScalarRMWRow, error) {
	if arch != "amd64" && arch != "386" {
		return nil, fmt.Errorf("legacy scalar conversion requires a Go x86 mode")
	}
	var result []X86ScalarRMWRow
	seen := map[string]bool{}
	for _, entry := range catalog.Optab {
		if !x86LegacyScalarConversionTable(entry.Ytab) {
			continue
		}
		if seen[entry.Opcode] {
			return nil, fmt.Errorf("duplicate original scalar conversion table")
		}
		seen[entry.Opcode] = true
		for _, original := range entry.Rows {
			witnesses, err := x86PackedLegacyRowWitnesses(entry, original)
			if err != nil {
				return nil, fmt.Errorf("%s/%d: %w", entry.Opcode, original.RowIndex, err)
			}
			row := X86ScalarRMWRow{ID: fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, original.RowIndex), Opcode: entry.Opcode}
			for _, witness := range witnesses {
				row.Witnesses = append(row.Witnesses, X86ScalarRMWWitness{Instruction: witness.Instruction, Destination: witness.Destination, Encoding: witness.Encoding})
			}
			if arch == "386" && entry.Prefix == "Pw" {
				row.ModeFiltered, row.Witnesses = "original Go rejects legacy REX.W in mode386", nil
			}
			result = append(result, row)
		}
	}
	if len(seen) != 12 || len(result) != 12 {
		return nil, fmt.Errorf("incomplete original scalar conversion tables")
	}
	return result, nil
}
