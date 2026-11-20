package goasmrules

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func ordinaryMoveSchemaForTest(name string, historical bool) []string {
	gp := []string{"Zr_m/1/Yrl,Yml", "Zm_r/1/Yml,Yrl", "Zil_rp/1/Yi32,Yrl", "Zilo_m/2/Yi32,Yml"}
	switch name {
	case "MOVB":
		return []string{"Zr_m/1/Yrb,Ymb", "Zm_r/1/Ymb,Yrb", "Zib_rp/1/Yi32,Yrb", "Zibo_m/2/Yi32,Ymb"}
	case "MOVW":
		return append(gp, "Zaut_r/2/Yiauto,Yrl")
	case "MOVL":
		return append(gp, "Zm_r_xm/1/Yml,Ymr", "Zr_m_xm/1/Ymr,Yml", "Zm_r_xm/2/Yml,Yxr", "Zr_m_xm/2/Yxr,Yml", "Zaut_r/2/Yiauto,Yrl")
	case "MOVQ":
		rows := []string{"Zm_r_xm_nr/1/Ym,Ymr", "Zr_m_xm_nr/1/Ymr,Ym", "Zm_r_xm_nr/2/Yxr,Ymr", "Zm_r_xm_nr/2/Yxm,Yxr", "Zr_m_xm_nr/2/Yxr,Yxm", "Zr_m/1/Yrl,Yml", "Zm_r/1/Yml,Yrl"}
		if historical {
			rows = append(rows, "Zilo_m/2/Ys32,Yrl")
		}
		return append(rows, "Ziq_rp/1/Yi64,Yrl", "Zilo_m/2/Yi32,Yml", "Zm_r_xm/1/Ymm,Ymr", "Zr_m_xm/1/Ymr,Ymm", "Zm_r_xm/2/Yml,Yxr", "Zr_m_xm/2/Yxr,Yml", "Zaut_r/1/Yiauto,Yrl")
	}
	return nil
}

func TestX86OrdinaryMoveOriginalCompleteTransport(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	names, rows := 0, 0
	for _, entry := range catalog.Optab {
		schema := ordinaryMoveSchemaForTest(entry.Opcode, len(entry.Rows) == 15)
		if schema == nil {
			continue
		}
		names++
		if len(entry.Rows) != len(schema) {
			t.Fatal("complete ordinary MOV table changed", entry.Opcode)
		}
		for _, row := range entry.Rows {
			rows++
			t.Run(fmt.Sprintf("%s/%d", entry.Opcode, row.RowIndex), func(t *testing.T) {
				if got := fmt.Sprintf("%s/%d/%s", row.ZCase, row.ZOffset, strings.Join(row.Classes, ",")); got != schema[row.RowIndex] {
					t.Fatal("independent complete source schema changed", got)
				}
				before := fmt.Sprintf("%#v/%#v", entry, row)
				witnesses, err := x86ScalarRMWRowWitnesses(entry, row, "amd64")
				if err != nil || row.ZCase != "Zaut_r" && len(witnesses) == 0 {
					t.Fatal("ORDINARY_MOV_SOURCE_TRANSPORT_GAP", err)
				}
				if before != fmt.Sprintf("%#v/%#v", entry, row) {
					t.Fatal("ordinary source formatter mutated original metadata")
				}
			})
		}
	}
	if names != 4 || rows != 32 && rows != 33 {
		t.Fatal("complete four-table source inventory changed", names, rows)
	}
}

func TestX86OrdinaryMoveCompleteMetadataBoundaries(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	maxInt := int(^uint(0) >> 1)
	for _, entry := range catalog.Optab {
		if ordinaryMoveSchemaForTest(entry.Opcode, len(entry.Rows) == 15) == nil {
			continue
		}
		for _, selected := range entry.Rows {
			for _, field := range []string{"original-arity", "selected-arity", "original-index", "selected-index", "original-offset", "selected-offset", "original-stride", "selected-stride", "earlier-row", "last-row", "row-count", "prefix", "source-role", "nonbyte", "payload-short", "payload-extra", "symbolic-marker", "opcode-zero", "opcode-escape", "escape-one", "escape-negative", "escape-overflow"} {
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
						changed.Rows[row.RowIndex].RowIndex = maxInt
					case "selected-index":
						row.RowIndex = -1
					case "original-offset":
						changed.Rows[row.RowIndex].UnmatchedOffset = -maxInt - 1
					case "selected-offset":
						row.UnmatchedOffset = maxInt
					case "original-stride":
						changed.Rows[row.RowIndex].ZOffset = maxInt
					case "selected-stride":
						row.ZOffset = -1
					case "earlier-row":
						changed.Rows[0].ZOffset = -maxInt - 1
					case "last-row":
						changed.Rows[len(changed.Rows)-1].Classes = []string{"Yiauto,Yrl"}
					case "row-count":
						changed.Rows = append(changed.Rows, row)
					case "prefix":
						changed.Prefix = "Pw"
					case "source-role":
						changed.Opcode = "MOVTLS"
					case "nonbyte":
						changed.OpBytes[0] = "0x100"
					case "payload-short":
						changed.OpBytes = changed.OpBytes[:len(changed.OpBytes)-1]
					case "payload-extra":
						changed.OpBytes = append(changed.OpBytes, "0")
					case "symbolic-marker":
						changed.OpBytes[0] = "Pe"
					case "opcode-zero":
						changed.OpBytes[0] = "0"
					case "opcode-escape":
						changed.OpBytes[0] = "0x0f"
					case "escape-one":
						changed.EscapeAdjustment = 1
					case "escape-negative":
						changed.EscapeAdjustment = -maxInt - 1
					case "escape-overflow":
						changed.EscapeAdjustment = maxInt
					}
					defer func() {
						if failure := recover(); failure != nil {
							t.Error("ORDINARY_MOV_SCHEMA_PANIC", failure)
						}
					}()
					if reflect.DeepEqual(changed, entry) && reflect.DeepEqual(row, selected) {
						t.Fatal("negative did not change original or selected metadata")
					}
					if _, err := x86ScalarRMWRowWitnesses(changed, row, "amd64"); err == nil {
						t.Fatal("ORDINARY_MOV_MALFORMED_ACCEPTED", field)
					}
				})
			}
		}
	}
}

func TestX86OrdinaryMoveSourceRolesAndModeBoundaries(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	historical := false
	for _, entry := range catalog.Optab {
		if entry.Opcode == "MOVQ" {
			historical = len(entry.Rows) == 15
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := X86OrdinaryMoveRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		roles := map[string]int{}
		filtered, rewrites := 0, 0
		for _, row := range rows {
			roles[row.Role]++
			if row.Rewrite != "" {
				if row.Role != "address" || row.Rewrite != "LEA"+row.Opcode[3:] {
					t.Fatal("address rewrite supplied a different role", row)
				}
				rewrites++
			}
			if row.ModeFiltered != "" {
				if arch != "386" || row.Opcode != "MOVQ" || len(row.Witnesses) != 0 {
					t.Fatal("mode filter supplied a witness or removed a legal mode", row)
				}
				filtered++
			} else if len(row.Witnesses) == 0 {
				t.Fatal("unfiltered original source row lacks its observation", row)
			}
		}
		gp, wantFiltered := 16, 0
		if historical {
			gp++
		}
		if arch == "386" {
			wantFiltered = 9
			if historical {
				wantFiltered++
			}
		}
		if !reflect.DeepEqual(roles, map[string]int{"GP": gp, "bank": 13, "address": 3}) || filtered != wantFiltered || rewrites != 2 {
			t.Fatal("complete source-role/mode partition changed", roles, filtered, rewrites)
		}
	}
	for _, arch := range []string{"", "arm64", "wasm"} {
		if _, err := X86OrdinaryMoveRows(catalog, arch); err == nil {
			t.Fatal("foreign mode borrowed ordinary x86 source transport", arch)
		}
	}
	if _, err := X86OrdinaryMoveRows(X86LegacyCatalog{}, "amd64"); err == nil {
		t.Fatal("missing catalog supplied an ordinary MOV closure")
	}
	for _, field := range []string{"missing", "duplicate"} {
		changed := catalog
		changed.Optab = append([]X86LegacyOpcode(nil), catalog.Optab...)
		for index, entry := range changed.Optab {
			if entry.Opcode != "MOVL" {
				continue
			}
			if field == "missing" {
				changed.Optab = append(changed.Optab[:index], changed.Optab[index+1:]...)
			} else {
				changed.Optab = append(changed.Optab, entry)
			}
			break
		}
		if _, err := X86OrdinaryMoveRows(changed, "amd64"); err == nil {
			t.Fatal("incomplete/duplicate catalog supplied an ordinary MOV closure", field)
		}
	}
}
