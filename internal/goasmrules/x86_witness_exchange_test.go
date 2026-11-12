package goasmrules

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func x86ExchangeSchemaForTest(name string) []string {
	if len(name) < 5 {
		return nil
	}
	stem, width := name[:len(name)-1], name[len(name)-1]
	if !strings.ContainsRune("BWLQ", rune(width)) {
		return nil
	}
	if stem == "XADD" {
		if width == 'B' {
			return []string{"Zr_m/1/Yrb,Ymb"}
		}
		return []string{"Zr_m/1/Yrl,Yml"}
	}
	if stem != "XCHG" {
		return nil
	}
	if width == 'B' {
		return []string{"Zr_m/1/Yrb,Ymb", "Zm_r/1/Ymb,Yrb"}
	}
	return []string{"Z_rp/1/Yax,Yrl", "Zrp_/1/Yrl,Yax", "Zr_m/1/Yrl,Yml", "Zm_r/1/Yml,Yrl"}
}

func TestX86ExchangeCompleteOriginalSourceTransport(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	names, rows := 0, 0
	for _, entry := range catalog.Optab {
		schema := x86ExchangeSchemaForTest(entry.Opcode)
		if schema == nil {
			continue
		}
		names++
		if len(entry.Rows) != len(schema) {
			t.Fatal("complete exchange source table changed", entry.Opcode)
		}
		for _, row := range entry.Rows {
			rows++
			t.Run(fmt.Sprintf("%s/%d", entry.Opcode, row.RowIndex), func(t *testing.T) {
				if got := fmt.Sprintf("%s/%d/%s", row.ZCase, row.ZOffset, strings.Join(row.Classes, ",")); got != schema[row.RowIndex] {
					t.Fatal("independent exchange source schema changed", got)
				}
				before := fmt.Sprintf("%#v/%#v", entry, row)
				for _, arch := range []string{"amd64", "386"} {
					witnesses, err := x86ScalarRMWRowWitnesses(entry, row, arch)
					if err != nil || len(witnesses) == 0 {
						t.Error("EXCHANGE_SOURCE_TRANSPORT_GAP", arch, err)
					}
				}
				if before != fmt.Sprintf("%#v/%#v", entry, row) {
					t.Fatal("exchange formatter mutated its original source")
				}
			})
		}
	}
	if names != 8 || rows != 18 {
		t.Fatal("complete exchange inventory changed", names, rows)
	}
}

func TestX86ExchangeCompleteSourceMetadataBoundaries(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	maxInt := int(^uint(0) >> 1)
	for _, entry := range catalog.Optab {
		if x86ExchangeSchemaForTest(entry.Opcode) == nil {
			continue
		}
		for _, selected := range entry.Rows {
			for _, field := range []string{"original-arity", "selected-arity", "original-index", "selected-index", "original-offset", "selected-offset", "original-stride", "selected-stride", "earlier-row", "row-count", "source-role", "prefix", "nonbyte", "short", "extra", "zero", "symbolic", "escape-negative", "escape-overflow", "escape-opposite"} {
				t.Run(fmt.Sprintf("%s/%d/%s", entry.Opcode, selected.RowIndex, field), func(t *testing.T) {
					changed, row := entry, selected
					changed.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
					changed.OpBytes = append([]string(nil), entry.OpBytes...)
					switch field {
					case "original-arity":
						changed.Rows[row.RowIndex].Classes = []string{strings.Join(row.Classes, ",")}
					case "selected-arity":
						row.Classes = []string{strings.Join(row.Classes, ",")}
					case "original-index":
						changed.Rows[row.RowIndex].RowIndex = -1
					case "selected-index":
						row.RowIndex = maxInt
					case "original-offset":
						changed.Rows[row.RowIndex].UnmatchedOffset = -maxInt - 1
					case "selected-offset":
						row.UnmatchedOffset = maxInt
					case "original-stride":
						changed.Rows[row.RowIndex].ZOffset = -maxInt - 1
					case "selected-stride":
						row.ZOffset = maxInt
					case "earlier-row":
						changed.Rows[0].Classes = []string{"Ynone"}
					case "row-count":
						changed.Rows = append(changed.Rows, row)
					case "source-role":
						changed.Opcode = "CMPXCHG" + entry.Opcode[len(entry.Opcode)-1:]
					case "prefix":
						changed.Prefix = "P32"
					case "nonbyte":
						changed.OpBytes[0] = "0x100"
					case "short":
						changed.OpBytes = changed.OpBytes[:len(changed.OpBytes)-1]
					case "extra":
						changed.OpBytes = append(changed.OpBytes, "0")
					case "zero":
						changed.OpBytes[0] = "0"
					case "symbolic":
						changed.OpBytes[0] = "Pm"
					case "escape-negative":
						changed.EscapeAdjustment = -maxInt - 1
					case "escape-overflow":
						changed.EscapeAdjustment = maxInt
					case "escape-opposite":
						changed.EscapeAdjustment = 1 - entry.EscapeAdjustment
					}
					defer func() {
						if failure := recover(); failure != nil {
							t.Error("EXCHANGE_SOURCE_SCHEMA_PANIC", failure)
						}
					}()
					if reflect.DeepEqual(changed, entry) && reflect.DeepEqual(row, selected) {
						t.Fatal("negative did not change source metadata")
					}
					if _, err := x86ScalarRMWRowWitnesses(changed, row, "amd64"); err == nil {
						t.Fatal("EXCHANGE_SOURCE_MALFORMED_ACCEPTED", field)
					}
				})
			}
		}
	}
}

func TestX86ExchangeSourceClosureBoundaries(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"", "arm64", "wasm"} {
		if _, err := X86ExchangeRows(catalog, mode); err == nil {
			t.Fatal("foreign mode acquired exchange source rows", mode)
		}
	}
	if _, err := X86ExchangeRows(X86LegacyCatalog{}, "amd64"); err == nil {
		t.Fatal("missing catalog acquired complete source closure")
	}
	for _, field := range []string{"missing", "duplicate", "foreign-table"} {
		changed := catalog
		changed.Optab = append([]X86LegacyOpcode(nil), catalog.Optab...)
		for index, entry := range changed.Optab {
			if entry.Opcode != "XADDL" {
				continue
			}
			switch field {
			case "missing":
				changed.Optab = append(changed.Optab[:index], changed.Optab[index+1:]...)
			case "duplicate":
				changed.Optab = append(changed.Optab, entry)
			case "foreign-table":
				changed.Optab[index].Ytab = "yaddl"
			}
			break
		}
		if _, err := X86ExchangeRows(changed, "amd64"); err == nil {
			t.Fatal("incomplete or contradictory exchange source closure", field)
		}
	}
}
