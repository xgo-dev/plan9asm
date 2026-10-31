package goasmrules

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func stackControlOriginalSchemas() map[string][]string {
	return map[string][]string{
		"ycall":  {"Zcallindreg/0/Yml", "Zcallindreg/2/Yrx,Yrx", "Zcallind/2/Yindir", "Zcall/0/Ybr", "Zcallcon/1/Yi32"},
		"yloop":  {"Zloop/1/Ybr"},
		"yjmp":   {"Zo_m64/2/Yml", "Zjmp/0/Ybr", "Zjmpcon/1/Yi32"},
		"ypopl":  {"Z_rp/1/Yrl", "Zo_m/2/Ym"},
		"ypushl": {"Zrp_/1/Yrl", "Zm_o/2/Ym", "Zib_/1/Yi8", "Zil_/1/Yi32"},
		"yret":   {"Zo_iw/1/", "Zo_iw/1/Yi32"},
		"yduff":  {"Zcallduff/1/Yi32"},
	}
}

func stackControlOriginalCatalog(t *testing.T) X86LegacyCatalog {
	t.Helper()
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func TestX86StackControlCompleteOriginalSchemas(t *testing.T) {
	catalog := stackControlOriginalCatalog(t)
	schemas := stackControlOriginalSchemas()
	want := map[string]int{"ycall": 5, "yloop": 6, "yjmp": 3, "ypopl": 6, "ypushl": 12, "yret": 6, "yduff": 2}
	counts := map[string]int{}
	names := map[string]bool{}
	rows := 0
	for _, entry := range catalog.Optab {
		schema, selected := schemas[entry.Ytab]
		if !selected {
			continue
		}
		if entry.Kind != "encoding" || names[entry.Opcode] || entry.EscapeAdjustment != 0 ||
			strings.TrimPrefix(entry.OpcodeExpression, "obj.") != "A"+entry.Opcode {
			t.Fatal("complete original stack/control entry identity changed", entry)
		}
		names[entry.Opcode] = true
		for _, row := range entry.Rows {
			if err := x86ScalarCompleteOperandSchema(entry, row, schema); err != nil {
				t.Fatal("original complete operand schema changed", entry.Opcode, err)
			}
			counts[entry.Ytab]++
			rows++
		}
	}
	if rows != 40 || len(names) != 19 || len(counts) != 7 {
		t.Fatal("complete source rows/tables changed", rows, len(names), counts)
	}
	for table, count := range want {
		if counts[table] != count {
			t.Fatal("missing original table row", table, counts[table], count)
		}
	}
}

// The separate source owner supplies byte/relocation projections while the
// original scalar owner's refusal remains independently checked below.
func stackControlSourceProbe(entry X86LegacyOpcode, row X86LegacyOperand, source X86StackControlSource, arch string, capacity int) ([]X86StackControlWitness, error) {
	return x86StackControlWitnesses(entry, row, source, arch, capacity)
}

func TestX86StackControlFormatterFeature(t *testing.T) {
	catalog := stackControlOriginalCatalog(t)
	schemas := stackControlOriginalSchemas()
	source, err := LoadX86StackControlSource(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			for _, entry := range catalog.Optab {
				if schemas[entry.Ytab] == nil || entry.Prefix == "P32" && arch == "amd64" ||
					(entry.Prefix == "Py" || entry.Prefix == "Pw") && arch == "386" {
					continue
				}
				for _, row := range entry.Rows {
					t.Run(fmt.Sprintf("%s/%d", entry.Opcode, row.RowIndex), func(t *testing.T) {
						witnesses, err := stackControlSourceProbe(entry, row, source, arch, catalog.OpBytesSize)
						if err != nil || len(witnesses) == 0 {
							t.Fatal("STACK_CONTROL_FORMATTER_FEATURE_GAP", entry.Opcode, row, err)
						}
						for _, witness := range witnesses {
							if witness.Instruction == "" || len(witness.Encoding) == 0 {
								t.Fatal("source metadata is not byte evidence", entry.Opcode, witness)
							}
						}
					})
				}
			}
		})
	}
}

func TestX86StackControlCompleteMetadataBoundaries(t *testing.T) {
	catalog := stackControlOriginalCatalog(t)
	source, err := LoadX86StackControlSource(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var original X86LegacyOpcode
	for _, entry := range catalog.Optab {
		if entry.Opcode == "PUSHQ" {
			original = entry
		}
	}
	if len(original.Rows) != 4 {
		t.Fatal("missing complete PUSHQ source schema")
	}
	for name, mutate := range map[string]func(*X86LegacyOpcode){
		"captured-enum":          func(e *X86LegacyOpcode) { e.OpcodeExpression = "APUSHL" },
		"missing-earlier-row":    func(e *X86LegacyOpcode) { e.Rows = e.Rows[1:] },
		"earlier-stride":         func(e *X86LegacyOpcode) { e.Rows[0].ZOffset++ },
		"earlier-classes":        func(e *X86LegacyOpcode) { e.Rows[0].Classes = []string{"Ym"} },
		"selected-offset":        func(e *X86LegacyOpcode) { e.Rows[3].UnmatchedOffset++ },
		"selected-row-order":     func(e *X86LegacyOpcode) { e.Rows[3].RowIndex-- },
		"source-escape":          func(e *X86LegacyOpcode) { e.EscapeAdjustment = 1 },
		"missing-opcode-payload": func(e *X86LegacyOpcode) { e.OpBytes = nil },
	} {
		t.Run(name, func(t *testing.T) {
			changed := original
			changed.Rows = append([]X86LegacyOperand(nil), original.Rows...)
			changed.OpBytes = append([]string(nil), original.OpBytes...)
			mutate(&changed)
			selected := changed.Rows[len(changed.Rows)-1]
			if witnesses, err := stackControlSourceProbe(changed, selected, source, "amd64", catalog.OpBytesSize); err == nil {
				t.Fatal("STACK_CONTROL_METADATA_ACCEPTED", name, witnesses)
			}
		})
	}
	t.Log("Initial rejection by the old source helper is not a newly repaired metadata defect.")
}

func TestX86StackControlDoesNotWidenExistingScalarOwner(t *testing.T) {
	catalog := stackControlOriginalCatalog(t)
	schemas := stackControlOriginalSchemas()
	for _, entry := range catalog.Optab {
		if schemas[entry.Ytab] == nil {
			continue
		}
		for _, row := range entry.Rows {
			for _, arch := range []string{"amd64", "386"} {
				if witnesses, err := x86ScalarRMWRowWitnesses(entry, row, arch); err == nil || len(witnesses) != 0 {
					t.Fatal("separate source-control grammar widened an old scalar owner", entry.Opcode, row, arch, witnesses, err)
				}
			}
		}
	}
}

func TestX86StackControlPublicSourceBoundaries(t *testing.T) {
	original := stackControlOriginalCatalog(t)
	source, err := LoadX86StackControlSource(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := X86StackControlRows(original, source, "amd64"); err != nil {
		t.Fatal("actual complete source is a prerequisite", err)
	}
	for _, mutation := range []string{"missing-member", "duplicate-member", "retag-member", "changed-payload", "missing-enum", "capacity", "zero-source", "foreign-arch"} {
		t.Run(mutation, func(t *testing.T) {
			catalog := original
			catalog.Optab = append([]X86LegacyOpcode(nil), original.Optab...)
			captured, arch := source, "amd64"
			index := -1
			for position, entry := range catalog.Optab {
				if entry.Opcode == "CALL" {
					index = position
				}
			}
			if index < 0 {
				t.Fatal("original CALL source disappeared")
			}
			entry := catalog.Optab[index]
			switch mutation {
			case "missing-member":
				entry.Ytab = "ynone"
			case "duplicate-member":
				for _, alternative := range original.Optab {
					if alternative.Opcode == "JMP" {
						entry = alternative
						entry.TableIndex = index
					}
				}
			case "retag-member":
				entry.Opcode, entry.OpcodeExpression = "MOVL", "AMOVL"
			case "changed-payload":
				entry.OpBytes = append([]string(nil), entry.OpBytes...)
				entry.OpBytes[0] = "0xfe"
			case "missing-enum":
				entry.OpcodeExpression = ""
			case "capacity":
				catalog.OpBytesSize++
			case "zero-source":
				captured = X86StackControlSource{}
			case "foreign-arch":
				arch = "arm64"
			}
			catalog.Optab[index] = entry
			if rows, err := X86StackControlRows(catalog, captured, arch); err == nil {
				t.Fatal("uncaptured source became a complete source view", mutation, rows)
			}
		})
	}
}
