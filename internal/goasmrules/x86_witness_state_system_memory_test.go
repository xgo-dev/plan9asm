package goasmrules

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func stateSystemOriginalUnaryDestinations(t *testing.T) map[string]bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/obj6.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]bool{}
	for _, declaration := range file.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range group.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || value.Names[0].Name != "unaryDst" || len(value.Values) != 1 {
				continue
			}
			literal, ok := value.Values[0].(*ast.CompositeLit)
			if !ok {
				t.Fatal("original unaryDst is not a complete source literal")
			}
			for _, element := range literal.Elts {
				pair := element.(*ast.KeyValueExpr)
				key, setting := pair.Key.(*ast.Ident), pair.Value.(*ast.Ident)
				if !strings.HasPrefix(key.Name, "A") || setting.Name != "true" && setting.Name != "false" {
					t.Fatal("original unaryDst key/value changed", element)
				}
				result[strings.TrimPrefix(key.Name, "A")] = setting.Name == "true"
			}
		}
	}
	if len(result) == 0 {
		t.Fatal("actual SDK has no captured unaryDst source roles")
	}
	return result
}

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

func TestX86StateSystemMemoryRequiresCompleteSourceOrigin(t *testing.T) {
	original, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	frontend, err := LoadX86UnaryDestinations(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < reflect.TypeOf(frontend).NumField(); index++ {
		if reflect.TypeOf(frontend).Field(index).PkgPath == "" {
			t.Fatal("caller can modify captured frontend roles directly")
		}
	}
	if _, err := X86StateSystemMemoryRows(original, frontend, "amd64"); err != nil {
		t.Fatal("original complete source is a prerequisite", err)
	}
	for _, mutation := range []string{"duplicate-member", "missing-complete-table", "incomplete-frontend", "zero-frontend"} {
		t.Run(mutation, func(t *testing.T) {
			catalog := original
			catalog.Optab = append([]X86LegacyOpcode(nil), original.Optab...)
			roles := frontend
			first, replacement := -1, X86LegacyOpcode{}
			for index, entry := range original.Optab {
				if entry.Ytab == "yclflush" {
					if first < 0 {
						first = index
					} else {
						replacement = entry
						break
					}
				}
			}
			if first < 0 || replacement.Opcode == "" {
				t.Fatal("complete source counterexample lost its original members")
			}
			switch mutation {
			case "duplicate-member":
				replacement.TableIndex = first
				catalog.Optab[first] = replacement
			case "missing-complete-table":
				for _, entry := range original.Optab {
					if entry.Ytab == "ydivb" {
						replacement = entry
						break
					}
				}
				for index, entry := range original.Optab {
					if entry.Ytab == "yprefetch" {
						copy := replacement
						copy.TableIndex = index
						copy.Opcode = fmt.Sprintf("SOURCE%d", index)
						copy.OpcodeExpression = "A" + copy.Opcode
						catalog.Optab[index] = copy
					}
				}
			case "incomplete-frontend":
				roles = X86UnaryDestinations{roles: map[string]bool{"NOP": true}}
			case "zero-frontend":
				roles = X86UnaryDestinations{}
			}
			if rows, err := X86StateSystemMemoryRows(catalog, roles, "amd64"); err == nil {
				t.Fatal("incomplete original source was admitted", mutation, len(rows))
			}
		})
	}
}

// The first RED uses the existing helper. A refusal here identifies a missing
// complete source projection, not a numerical or privileged execution bug.
func TestX86StateSystemMemoryExistingTransportCompleteOriginalRows(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	unary := stateSystemOriginalUnaryDestinations(t)
	frontend := 0
	for _, entry := range stateSystemOriginalEntries(t) {
		for _, row := range entry.Rows {
			for _, arch := range []string{"amd64", "386"} {
				if arch == "amd64" && entry.Prefix == "P32" ||
					arch == "386" && (entry.Prefix == "Pw" || entry.Prefix == "Pfw") {
					continue // Original row retained; separate actual-Go mode refusals below.
				}
				if (row.ZCase == "Zm_o" || row.ZCase == "Zo_m") && unary[entry.Opcode] != (row.ZCase == "Zo_m") {
					frontend++
					t.Logf("ORIGINAL_FRONTEND_SLOT_REJECTION %s %s/%d: unaryDst disagrees with %s, retained in the complete inventory", arch, entry.Opcode, row.RowIndex, row.ZCase)
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/%d", arch, entry.Opcode, row.RowIndex), func(t *testing.T) {
					witnesses, err := x86StateSystemMemoryWitnesses(entry, row, catalog.OpBytesSize)
					if err != nil || len(witnesses) == 0 {
						t.Fatal("complete source transport feature missing", entry.Ytab, row, err)
					}
					old, oldErr := x86ScalarRMWRowWitnesses(entry, row, arch)
					t.Logf("STATE_SYSTEM_OLD_CONSUMER %s/%s/%d accepted=%t", arch, entry.Opcode, row.RowIndex, oldErr == nil && len(old) != 0)
				})
			}
		}
	}
	if frontend != 2 {
		t.Fatal("original per-mode frontend slot boundary changed", frontend)
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
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range stateSystemOriginalEntries(t) {
		for _, selected := range original.Rows {
			t.Run(fmt.Sprintf("%s/%d", original.Opcode, selected.RowIndex), func(t *testing.T) {
				for _, mutation := range []string{
					"negative-escape", "overflow-escape", "negative-selected-index",
					"past-selected-index", "original-index", "original-class",
					"selected-class", "selected-arity", "selected-offset",
					"original-stride", "nonbyte-tail", "enum-identity", "enum-missing",
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
					case "enum-missing":
						entry.OpcodeExpression = ""
					}
					func() {
						defer func() {
							if value := recover(); value != nil {
								t.Errorf("%s panicked: %v", mutation, value)
							}
						}()
						if witnesses, err := x86ScalarRMWRowWitnesses(entry, row, "amd64"); mutation != "enum-missing" && err == nil {
							t.Errorf("%s admitted damaged captured source: %+v", mutation, witnesses)
						}
						if witnesses, err := x86StateSystemMemoryWitnesses(entry, row, catalog.OpBytesSize); err == nil {
							t.Errorf("%s admitted damaged source in the new projection: %+v", mutation, witnesses)
						}
					}()
				}
			})
		}
	}
}
