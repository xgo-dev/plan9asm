package goasmrules

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func explicitSIMD27Entries(t *testing.T) []X86LegacyOpcode {
	t.Helper()
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	schemas := map[string][]string{
		"yextractps":   {"Zibr_m/2/Yu2,Yxr,Yml"},
		"yextrw":       {"Zibm_r/2/Yu8,Yxr,Yrl", "Zibr_m/2/Yu8,Yxr,Yml"},
		"yextr":        {"Zibr_m/3/Yu8,Yxr,Ymm"},
		"yinsrw":       {"Zibm_r/2/Yu8,Yml,Yxr"},
		"yinsr":        {"Zibm_r/3/Yu8,Ymm,Yxr"},
		"yxcmpi":       {"Zm_r_i_xm/2/Yxm,Yxr,Yi8"},
		"yblendvpd":    {"Z_m_r/1/Yxr0,Yxm,Yxr"},
		"ysha1rnds4":   {"Zibm_r/2/Yu2,Yxm,Yxr"},
		"ysha256rnds2": {"Zlit_m_r/0/Yxr0,Yxm,Yxr"},
		"yxrrl":        {"Zm_r/1/Yxr,Yrl"},
		"ymskb":        {"Zm_r_xm/2/Yxr,Yrl", "Zm_r_xm/1/Ymr,Yrl"},
		"yxr":          {"Zm_r_xm/1/Yxr,Yxr"},
		"yxm_q4":       {"Zm_r/1/Yxm,Yxr"},
	}
	var entries []X86LegacyOpcode
	rows := 0
	for _, entry := range catalog.Optab {
		schema, selected := schemas[entry.Ytab]
		// These shared tables already have independently owned arithmetic,
		// extension and state rows. This closure retains their complete
		// remaining lane-move and explicit-test families, not table authority.
		if entry.Ytab == "yxr" && entry.Opcode != "MOVHLPS" && entry.Opcode != "MOVLHPS" ||
			entry.Ytab == "yxm_q4" && entry.Opcode != "PHMINPOSUW" && entry.Opcode != "PTEST" {
			continue
		}
		if entry.Opcode == "INSERTPS" {
			schema, selected = []string{"Zibm_r/2/Yu8,Yxm,Yxr"}, true
		}
		if !selected {
			continue
		}
		if entry.Kind != "encoding" || len(entry.Rows) != len(schema) {
			t.Fatal("original complete schema changed", entry)
		}
		offset := 0
		for i, row := range entry.Rows {
			if row.RowIndex != i || row.UnmatchedOffset != offset || fmt.Sprintf("%s/%d/%s", row.ZCase, row.ZOffset, strings.Join(row.Classes, ",")) != schema[i] {
				t.Fatal("original ordered schema changed", entry, row)
			}
			offset += row.ZOffset + entry.EscapeAdjustment
		}
		entries, rows = append(entries, entry), rows+len(entry.Rows)
	}
	if len(entries) != 26 || rows != 28 {
		t.Fatal("complete explicit SIMD inventory changed", len(entries), rows)
	}
	return entries
}

func TestX86LegacyExplicitSIMDCompleteSourceTransport(t *testing.T) {
	for _, entry := range explicitSIMD27Entries(t) {
		for _, row := range entry.Rows {
			t.Run(fmt.Sprintf("%s/%d", entry.Opcode, row.RowIndex), func(t *testing.T) {
				before := fmt.Sprintf("%#v", entry)
				// The original RED used the older packed-only projection. The
				// final explicit view retains GP and MMX syntax without adding
				// either bank to the packed numerical consumer.
				witnesses, err := x86LegacyExplicitSIMDRowWitnesses(entry, row)
				want := 2
				if entry.Ytab == "yextrw" || entry.Ytab == "yxrrl" || entry.Ytab == "ymskb" || entry.Ytab == "yxr" {
					want = 1
				}
				if err != nil || len(witnesses) != want {
					t.Errorf("EXPLICIT_SIMD_SOURCE_TRANSPORT_GAP: got=%d want=%d error=%v", len(witnesses), want, err)
				}
				for _, w := range witnesses {
					if w.Instruction == "" || len(w.Encoding) == 0 || w.Destination == "" {
						t.Error("incomplete or foreign witness", w)
					}
				}
				if before != fmt.Sprintf("%#v", entry) {
					t.Fatal("formatter mutated original source")
				}
			})
		}
	}
}

func TestX86LegacyExplicitSIMDWholeSourceMetadataBoundaries(t *testing.T) {
	for _, entry := range explicitSIMD27Entries(t) {
		for _, original := range entry.Rows {
			for _, field := range []string{"kind", "row-count", "original-arity", "selected-arity", "original-offset", "selected-offset", "original-stride", "selected-stride", "selected-index", "selected-zcase", "escape-negative", "escape-overflow", "prefix", "short", "extra", "nonbyte", "last-original-arity", "last-original-zcase", "last-original-offset", "last-original-stride"} {
				t.Run(fmt.Sprintf("%s/%d/%s", entry.Opcode, original.RowIndex, field), func(t *testing.T) {
					changed, row := entry, original
					changed.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
					changed.OpBytes = append([]string(nil), entry.OpBytes...)
					maxInt := int(^uint(0) >> 1)
					switch field {
					case "kind":
						changed.Kind = "reserved"
					case "row-count":
						changed.Rows = append(changed.Rows, original)
					case "original-arity":
						changed.Rows[0].Classes = []string{strings.Join(changed.Rows[0].Classes, ",")}
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
					case "selected-zcase":
						row.ZCase = "Zlit"
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
					case "last-original-arity":
						changed.Rows[len(changed.Rows)-1].Classes = nil
					case "last-original-zcase":
						changed.Rows[len(changed.Rows)-1].ZCase = "Zlit"
					case "last-original-offset":
						changed.Rows[len(changed.Rows)-1].UnmatchedOffset = maxInt
					case "last-original-stride":
						changed.Rows[len(changed.Rows)-1].ZOffset = maxInt
					}
					defer func() {
						if failure := recover(); failure != nil {
							t.Errorf("EXPLICIT_SIMD_METADATA_PANIC: %v", failure)
						}
					}()
					if reflect.DeepEqual(changed, entry) && reflect.DeepEqual(row, original) {
						t.Fatal("ineffective mutation")
					}
					if _, err := x86LegacyExplicitSIMDRowWitnesses(changed, row); err == nil {
						t.Error("EXPLICIT_SIMD_MALFORMED_ACCEPTED", field)
					}
				})
			}
		}
	}
}

func TestX86LegacyExplicitSIMDAllAtomsAndPrefixRoles(t *testing.T) {
	for _, entry := range explicitSIMD27Entries(t) {
		for _, row := range entry.Rows {
			for index := range entry.OpBytes {
				t.Run(fmt.Sprintf("%s/%d/atom%d", entry.Opcode, row.RowIndex, index), func(t *testing.T) {
					changed := entry
					changed.OpBytes = append([]string(nil), entry.OpBytes...)
					changed.OpBytes[index] = "0x100"
					if _, err := x86LegacyExplicitSIMDRowWitnesses(changed, row); err == nil {
						t.Fatal("unselected/prefix atom was not validated", index)
					}
				})
			}
			if entry.Ytab == "yxcmpi" && entry.Prefix == "Px" {
				t.Run(entry.Opcode+"/coherent-foreign-mandatory", func(t *testing.T) {
					changed := entry
					changed.OpBytes = append([]string(nil), entry.OpBytes...)
					changed.OpBytes[0] = "Pf3"
					if entry.OpBytes[0] == "Pf3" {
						changed.OpBytes[0] = "Pf2"
					}
					if _, err := x86LegacyExplicitSIMDRowWitnesses(changed, row); err == nil {
						t.Fatal("EXPLICIT_SIMD_MANDATORY_ROLE_CHANGED")
					}
				})
			}
		}
	}
}
