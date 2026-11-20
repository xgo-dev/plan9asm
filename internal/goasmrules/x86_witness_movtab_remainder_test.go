package goasmrules

import (
	"fmt"
	"reflect"
	"runtime"
	"testing"
)

func movtabRemainderOriginalRows(t *testing.T) []X86MoveRule {
	t.Helper()
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var rows []X86MoveRule
	for _, row := range catalog.Movtab {
		if row.Kind == "encoding" && row.Code != "movDoubleShift" && row.Code != "movTLSReg" {
			rows = append(rows, row)
		}
	}
	if len(rows) != 92 {
		t.Fatal("complete non-TLS source formatter denominator changed", len(rows))
	}
	return rows
}

func TestX86MovtabRemainderCompleteSourceTransport(t *testing.T) {
	for _, row := range movtabRemainderOriginalRows(t) {
		t.Run(fmt.Sprintf("%d/%s/%s", row.TableIndex, row.Opcode, row.Code), func(t *testing.T) {
			before := fmt.Sprintf("%#v", row)
			witnesses, err := x86MovtabRemainderRowWitnesses(row)
			if err != nil || len(witnesses) == 0 {
				t.Fatal("MOVTAB_REMAINDER_FORMATTER_FEATURE_GAP", row.TableIndex, row.Code, err)
			}
			for _, witness := range witnesses {
				if witness.Instruction == "" || len(witness.Encoding) == 0 {
					t.Fatal("source formatter returned an empty encoding", row, witness)
				}
			}
			if before != fmt.Sprintf("%#v", row) {
				t.Fatal("source formatter mutated its original capture")
			}
		})
	}
}

func TestX86MovtabRemainderPaddingAndSourceIdentity(t *testing.T) {
	for _, original := range movtabRemainderOriginalRows(t) {
		t.Run(fmt.Sprintf("%d/%s", original.TableIndex, original.Opcode), func(t *testing.T) {
			want, err := x86MovtabRemainderRowWitnesses(original)
			if err != nil {
				t.Fatal("original complete source required", err)
			}
			for _, expression := range []string{"", "obj.A" + original.Opcode} {
				row := original
				row.OpcodeExpression = expression
				if got, err := x86MovtabRemainderRowWitnesses(row); err != nil || !reflect.DeepEqual(got, want) {
					t.Fatal("equivalent source enum spelling changed output", expression, err)
				}
			}
			row := original
			for len(row.OpBytes) > 0 && (row.OpBytes[len(row.OpBytes)-1] == "0" || row.OpBytes[len(row.OpBytes)-1] == "00") {
				row.OpBytes = row.OpBytes[:len(row.OpBytes)-1]
			}
			if got, err := x86MovtabRemainderRowWitnesses(row); err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("implicit fixed-array padding changed source bytes", original, err)
			}
			if original.Code != "movLit" {
				row = original
				row.OpBytes = append([]string(nil), original.OpBytes...)
				field := 1
				if original.Code == "movRegMem2op" || original.Code == "movMemReg2op" {
					field = 2
				}
				row.OpBytes[field] = "9"
				movtabRequireMetadataRefusal(t, row, "foreign-special-register-field")
			}
		})
	}
}

func TestX86MovtabRemainderPublicSourceBoundaries(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"", "arm64", "wasm"} {
		if rows, err := X86MovtabRemainderRows(catalog, arch); err == nil || len(rows) != 0 {
			t.Fatal("source projection accepted absent or foreign mode", arch)
		}
	}
	for _, mutation := range []string{"duplicate-role", "missing-row", "index", "unknown-code"} {
		changed := catalog
		changed.Movtab = append([]X86MoveRule(nil), catalog.Movtab...)
		switch mutation {
		case "duplicate-role":
			changed.Movtab[1] = changed.Movtab[0]
			changed.Movtab[1].TableIndex = 1
		case "missing-row":
			changed.Movtab = changed.Movtab[1:]
		case "index":
			changed.Movtab[0].TableIndex = 1
		case "unknown-code":
			changed.Movtab[0].Code = "movUnknown"
		}
		if rows, err := X86MovtabRemainderRows(changed, "amd64"); err == nil || len(rows) != 0 {
			t.Fatal("incomplete original table acquired source ownership", mutation)
		}
	}
	for _, original := range catalog.Movtab {
		if original.Code == "movTLSReg" {
			if got, err := x86MovtabRemainderRowWitnesses(original); err == nil || len(got) != 0 {
				t.Fatal("TLS zero payload became successful target-independent bytes", original, got)
			}
		}
	}
}

func TestX86MovtabRemainderCompleteTableSentinel(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{
		"final-payload", "final-from", "final-code", "final-opcode",
		"shift-sentinel", "TLS-sentinel", "shift-reserved", "TLS-reserved",
	} {
		t.Run(mutation, func(t *testing.T) {
			changed := catalog
			changed.Movtab = append([]X86MoveRule(nil), catalog.Movtab...)
			switch mutation {
			case "final-payload":
				changed.Movtab[112].OpBytes = []string{"0x90"}
			case "final-from":
				changed.Movtab[112].From = "Yrl"
			case "final-code":
				changed.Movtab[112].Code = "movUnknown"
			case "final-opcode":
				changed.Movtab[112].Opcode, changed.Movtab[112].OpcodeExpression = "MOVL", "AMOVL"
			case "shift-sentinel":
				changed.Movtab[92].Kind = "sentinel"
			case "TLS-sentinel":
				changed.Movtab[110].Kind = "sentinel"
			case "shift-reserved":
				changed.Movtab[92].Kind = "reserved"
			case "TLS-reserved":
				changed.Movtab[110].Kind = "reserved"
			}
			if got, err := X86MovtabRemainderRows(changed, "amd64"); err == nil || len(got) != 0 {
				t.Fatal("MOVTAB_COMPLETE_TABLE_SENTINEL_ACCEPTED", mutation, len(got), err)
			}
		})
	}
}

// Initially the old hook rejects these different source families wholesale.
// These controls become new-formatter metadata tests when that independent
// formatter is wired in; their initial PASS is not a metadata defect repair.
func TestX86MovtabRemainderCompleteSourceMetadataBoundaries(t *testing.T) {
	for _, original := range movtabRemainderOriginalRows(t) {
		t.Run(fmt.Sprintf("%d/%s/%s", original.TableIndex, original.Opcode, original.Code), func(t *testing.T) {
			for _, field := range []string{
				"kind", "negative-index", "empty-opcode", "opcode-expression",
				"from", "from3", "to", "joined-from", "code", "empty-payload", "overflow-capacity",
			} {
				row := original
				row.OpBytes = append([]string(nil), original.OpBytes...)
				switch field {
				case "kind":
					row.Kind = "sentinel"
				case "negative-index":
					row.TableIndex = -1
				case "empty-opcode":
					row.Opcode = ""
				case "opcode-expression":
					row.OpcodeExpression = "obj.ANOP"
				case "from":
					row.From = "Yinvalid"
				case "from3":
					row.From3 = "Yrl"
				case "to":
					row.To = "Yinvalid"
				case "joined-from":
					row.From += ",Ynone"
				case "code":
					row.Code = "movUnknown"
				case "empty-payload":
					row.OpBytes = nil
				case "overflow-capacity":
					row.OpBytes = []string{"0x90", "0", "0", "0", "0"}
				}
				movtabRequireMetadataRefusal(t, row, field)
			}
			for index := range original.OpBytes {
				for _, atom := range []string{"-1", "0x100", "not-a-byte"} {
					row := original
					row.OpBytes = append([]string(nil), original.OpBytes...)
					row.OpBytes[index] = atom
					movtabRequireMetadataRefusal(t, row, fmt.Sprintf("atom-%d-%s", index, atom))
				}
			}
			if original.Code == "movLit" {
				row := original
				row.OpBytes = []string{"0x90", "0x90", "0x90", "0x90"}
				movtabRequireMetadataRefusal(t, row, "unterminated-literal")
			}
		})
	}
}

func movtabRequireMetadataRefusal(t *testing.T, row X86MoveRule, field string) {
	t.Helper()
	defer func() {
		if caught := recover(); caught != nil {
			t.Errorf("MOVTAB_REMAINDER_METADATA_PANIC row=%d field=%s panic=%v", row.TableIndex, field, caught)
		}
	}()
	if got, err := x86MovtabRemainderRowWitnesses(row); err == nil || len(got) != 0 {
		t.Errorf("MOVTAB_REMAINDER_METADATA_ACCEPTED row=%d field=%s witnesses=%v", row.TableIndex, field, got)
	}
}

func TestX86MovtabRemainderDoesNotWidenExistingDoubleShift(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	refused, accepted := 0, 0
	for _, row := range catalog.Movtab {
		if row.Kind != "encoding" {
			continue
		}
		got, err := x86ScalarDoubleShiftWitnesses(row)
		if row.Code == "movDoubleShift" {
			if err != nil || len(got) == 0 {
				t.Fatal("existing double-shift row regressed", row, err)
			}
			accepted++
		} else {
			if err == nil || len(got) != 0 {
				t.Fatal("new source family acquired old double-shift membership", row, got)
			}
			refused++
		}
	}
	if accepted != 18 || refused != 94 {
		t.Fatal("old formatter source-family boundary changed", accepted, refused)
	}
}
