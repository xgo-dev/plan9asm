package goasmrules

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Inventory complete source tables, including their already joined numeric
// users. Shared encodings supply no machine-state, memory or native permission.
func stateSystemOriginalSchema(table string) []string {
	switch table {
	case "yclflush", "ysvrs_om":
		return []string{"Zo_m/2/Ym"}
	case "ysvrs_mo", "yprefetch":
		return []string{"Zm_o/2/Ym"}
	case "ydivb":
		return []string{"Zm_o/2/Ymb"}
	case "ydivl":
		return []string{"Zm_o/2/Yml"}
	case "yincq":
		return []string{"Zo_m/2/Yml"}
	case "ywrfsbase":
		return []string{"Zm_o/2/Yrl"}
	case "yrdrand":
		return []string{"Zo_m/2/Yrl"}
	case "yrl_m":
		return []string{"Zr_m/1/Yrl,Ym"}
	case "yrl_ml":
		return []string{"Zr_m/1/Yrl,Yml"}
	case "ym_rl":
		return []string{"Zm_r/1/Ym,Yrl"}
	case "ycrc32l":
		return []string{"Zlitm_r/0/Yml,Yrl"}
	case "yin":
		return []string{"Zib_/1/Yi32", "Zlit/1/"}
	case "yint":
		return []string{"Zib_/1/Yi32"}
	case "yxabort":
		return []string{"Zib_/1/Yu8"}
	case "yxbegin":
		return []string{"Zjmp/1/Ybr"}
	}
	return nil
}

func stateSystemOriginalEntries(t *testing.T) []X86LegacyOpcode {
	t.Helper()
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{
		"yclflush": 15, "ysvrs_mo": 9, "ysvrs_om": 6, "yin": 12,
		"yint": 1, "ydivl": 20, "ydivb": 5, "ywrfsbase": 7,
		"ycrc32l": 7, "yprefetch": 4, "yincq": 13, "yrdrand": 10,
		"ym_rl": 12, "yrl_m": 2, "yrl_ml": 10, "yxbegin": 1, "yxabort": 1,
	}
	var entries []X86LegacyOpcode
	counts, seen, total := map[string]int{}, map[string]bool{}, 0
	for _, entry := range catalog.Optab {
		schema := stateSystemOriginalSchema(entry.Ytab)
		if schema == nil {
			continue
		}
		if entry.Kind != "encoding" || seen[entry.Opcode] || len(entry.Rows) != len(schema) {
			t.Fatal("complete state/system original entry changed", entry)
		}
		seen[entry.Opcode] = true
		if entry.Opcode == "RDPID" {
			want["yrdrand"]++
		}
		offset := 0
		for index, row := range entry.Rows {
			parts := strings.Split(schema[index], "/")
			classes := []string{}
			if parts[2] != "" {
				classes = strings.Split(parts[2], ",")
			}
			shape := fmt.Sprintf("%s/%d/%s", row.ZCase, row.ZOffset, strings.Join(row.Classes, ","))
			if row.RowIndex != index || row.UnmatchedOffset != offset || shape != schema[index] ||
				!reflect.DeepEqual(row.Classes, classes) {
				t.Fatal("complete state/system original row changed", entry, row)
			}
			offset += row.ZOffset + entry.EscapeAdjustment
			counts[entry.Ytab]++
			total++
		}
		entries = append(entries, entry)
	}
	rows, entryCount := 135, 129
	if seen["RDPID"] {
		rows++
		entryCount++
	}
	if total != rows || len(entries) != entryCount || !reflect.DeepEqual(counts, want) {
		t.Fatal("complete state/system source denominator changed", total, len(entries), counts, want)
	}
	return entries
}

func TestX86StateSystemMemoryCompleteOriginalInventory(t *testing.T) {
	stateSystemOriginalEntries(t)
}

// The first RED uses the existing helper. A refusal here identifies a missing
// complete source projection, not a numerical or privileged execution bug.
func TestX86StateSystemMemoryExistingTransportCompleteOriginalRows(t *testing.T) {
	for _, entry := range stateSystemOriginalEntries(t) {
		for _, row := range entry.Rows {
			for _, arch := range []string{"amd64", "386"} {
				if arch == "amd64" && entry.Prefix == "P32" ||
					arch == "386" && (entry.Prefix == "Pw" || entry.Prefix == "Pfw") {
					continue // Original row retained; separate actual-Go mode refusals below.
				}
				t.Run(fmt.Sprintf("%s/%s/%d", arch, entry.Opcode, row.RowIndex), func(t *testing.T) {
					witnesses, err := x86ScalarRMWRowWitnesses(entry, row, arch)
					if err != nil || len(witnesses) == 0 {
						t.Fatal("complete source transport feature missing", entry.Ytab, row, err)
					}
				})
			}
		}
	}
}

func stateSystemClone(entry X86LegacyOpcode) X86LegacyOpcode {
	entry.OpBytes = append([]string(nil), entry.OpBytes...)
	entry.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
	for index := range entry.Rows {
		entry.Rows[index].Classes = append([]string(nil), entry.Rows[index].Classes...)
	}
	return entry
}

// Keep old-consumer observations even when the new projection is added. A
// malformed rejection alone is not evidence that the corresponding original
// source row was accepted: the independent positive owner above supplies that.
func TestX86StateSystemMemoryCompleteOriginalMetadataBoundaries(t *testing.T) {
	for _, original := range stateSystemOriginalEntries(t) {
		for _, selected := range original.Rows {
			t.Run(fmt.Sprintf("%s/%d", original.Opcode, selected.RowIndex), func(t *testing.T) {
				for _, mutation := range []string{
					"negative-escape", "overflow-escape", "negative-selected-index",
					"past-selected-index", "original-index", "original-class",
					"selected-class", "selected-arity", "selected-offset",
					"original-stride", "nonbyte-tail", "enum-identity",
				} {
					entry := stateSystemClone(original)
					row := entry.Rows[selected.RowIndex]
					switch mutation {
					case "negative-escape", "overflow-escape":
						entry.EscapeAdjustment = -3
						if mutation == "overflow-escape" {
							entry.EscapeAdjustment = int(^uint(0) >> 1)
						}
						offset := 0
						for index := range entry.Rows {
							entry.Rows[index].UnmatchedOffset = offset
							offset += entry.Rows[index].ZOffset + entry.EscapeAdjustment
						}
						row = entry.Rows[selected.RowIndex]
					case "negative-selected-index":
						row.RowIndex = -1
					case "past-selected-index":
						row.RowIndex = len(entry.Rows)
					case "original-index":
						entry.Rows[0].RowIndex = -1
					case "original-class":
						entry.Rows[0].Classes = []string{"Yinvalid"}
					case "selected-class":
						row.Classes = []string{"Yinvalid"}
					case "selected-arity":
						row.Classes = append(append([]string(nil), row.Classes...), "Ynone")
					case "selected-offset":
						row.UnmatchedOffset = -1
					case "original-stride":
						entry.Rows[0].ZOffset = -1
					case "nonbyte-tail":
						entry.OpBytes[len(entry.OpBytes)-1] = "256"
					case "enum-identity":
						entry.OpcodeExpression = "ANOP"
					}
					func() {
						defer func() {
							if value := recover(); value != nil {
								t.Errorf("%s panicked: %v", mutation, value)
							}
						}()
						if witnesses, err := x86ScalarRMWRowWitnesses(entry, row, "amd64"); err == nil {
							t.Errorf("%s admitted damaged captured source: %+v", mutation, witnesses)
						}
					}()
				}
			})
		}
	}
}
