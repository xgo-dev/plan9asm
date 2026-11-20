package goasmrules

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func scalarConversion12OriginalEntries(t *testing.T) []X86LegacyOpcode {
	t.Helper()
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	tables := map[string]bool{"yxcvfl": true, "yxcvfq": true, "yxcvlf": true, "yxcvqf": true}
	var entries []X86LegacyOpcode
	for _, entry := range catalog.Optab {
		if !tables[entry.Ytab] {
			continue
		}
		wantClasses := []string{"Yxm", "Yrl"}
		if entry.Ytab == "yxcvlf" || entry.Ytab == "yxcvqf" {
			wantClasses = []string{"Yml", "Yxr"}
		}
		stride := 1
		if entry.Ytab == "yxcvfq" || entry.Ytab == "yxcvqf" {
			stride = 2
		}
		if entry.Kind != "encoding" || entry.EscapeAdjustment != 0 || len(entry.Rows) != 1 || entry.Rows[0].RowIndex != 0 || entry.Rows[0].UnmatchedOffset != 0 || entry.Rows[0].ZCase != "Zm_r_xm" || entry.Rows[0].ZOffset != stride || !reflect.DeepEqual(entry.Rows[0].Classes, wantClasses) || len(entry.OpBytes) != stride {
			t.Fatal("complete original scalar conversion schema changed", entry)
		}
		entries = append(entries, entry)
	}
	if len(entries) != 12 {
		t.Fatal("complete four-table conversion inventory changed", len(entries))
	}
	return entries
}

func TestX86LegacyScalarConversionCompleteSourceTransport(t *testing.T) {
	for _, entry := range scalarConversion12OriginalEntries(t) {
		t.Run(entry.Opcode, func(t *testing.T) {
			before := fmt.Sprintf("%#v", entry)
			witnesses, err := x86PackedLegacyRowWitnesses(entry, entry.Rows[0])
			if err != nil || len(witnesses) != 2 {
				t.Error("SCALAR_CONVERSION_SOURCE_TRANSPORT_GAP", entry.Opcode, err)
			}
			for _, w := range witnesses {
				if w.Instruction == "" || len(w.Encoding) == 0 || w.Destination == "" {
					t.Error("incomplete source witness", w)
				}
			}
			if before != fmt.Sprintf("%#v", entry) {
				t.Fatal("formatter mutated original source")
			}
		})
	}
}

func TestX86LegacyScalarConversionWholeSourceMetadataBoundaries(t *testing.T) {
	for _, entry := range scalarConversion12OriginalEntries(t) {
		for _, field := range []string{"kind", "row-count", "original-arity", "selected-arity", "original-offset", "selected-offset", "original-stride", "selected-stride", "selected-index", "escape-negative", "escape-overflow", "prefix", "short", "extra", "nonbyte"} {
			t.Run(entry.Opcode+"/"+field, func(t *testing.T) {
				changed, row := entry, entry.Rows[0]
				changed.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
				changed.OpBytes = append([]string(nil), entry.OpBytes...)
				maxInt := int(^uint(0) >> 1)
				switch field {
				case "kind":
					changed.Kind = "reserved"
				case "row-count":
					changed.Rows = append(changed.Rows, row)
				case "original-arity":
					changed.Rows[0].Classes = []string{strings.Join(row.Classes, ",")}
				case "selected-arity":
					row.Classes = []string{strings.Join(row.Classes, ",")}
				case "original-offset":
					changed.Rows[0].UnmatchedOffset = -maxInt - 1
				case "selected-offset":
					row.UnmatchedOffset = maxInt
				case "original-stride":
					changed.Rows[0].ZOffset = -maxInt - 1
				case "selected-stride":
					row.ZOffset = maxInt
				case "selected-index":
					row.RowIndex = maxInt
				case "escape-negative":
					changed.EscapeAdjustment = -1
				case "escape-overflow":
					changed.EscapeAdjustment = maxInt
				case "prefix":
					changed.Prefix = "P32"
				case "short":
					changed.OpBytes = nil
				case "extra":
					changed.OpBytes = append(changed.OpBytes, "0")
				case "nonbyte":
					changed.OpBytes[len(changed.OpBytes)-1] = "0x100"
				}
				defer func() {
					if failure := recover(); failure != nil {
						t.Errorf("SCALAR_CONVERSION_METADATA_PANIC: %v", failure)
					}
				}()
				if _, err := x86PackedLegacyRowWitnesses(changed, row); err == nil {
					t.Error("SCALAR_CONVERSION_MALFORMED_ACCEPTED", field)
				}
			})
		}
	}
}
