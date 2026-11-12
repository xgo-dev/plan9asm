package goasmrules

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// These are the complete original source tables. Their shared operand shapes
// do not grant physical MMX, implicit DI, x87 status or numerical permission.
func mediaX87OriginalSchema(table string) []string {
	return map[string][]string{
		"yxcvm1":     {"Zm_r_xm/2/Yxm,Yxr", "Zm_r_xm/2/Yxm,Ymr"},
		"yxcvm2":     {"Zm_r_xm/2/Yxm,Yxr", "Zm_r_xm/2/Ymm,Yxr"},
		"ylddqu":     {"Zm_r/1/Ym,Yxr"},
		"yxr":        {"Zm_r_xm/1/Yxr,Yxr"},
		"ymr":        {"Zm_r/1/Ymr,Ymr"},
		"yxr_ml":     {"Zr_m_xm/1/Yxr,Yml"},
		"ymr_ml":     {"Zr_m_xm/1/Ymr,Yml"},
		"ymrxr":      {"Zm_r/1/Ymr,Yxr", "Zm_r_xm/1/Yxm,Yxr"},
		"ymmxmm0f38": {"Zlitm_r/3/Ymm,Ymr", "Zlitm_r/5/Yxm,Yxr"},
		"ymshuf":     {"Zibm_r/2/Yi8,Ymm,Ymr"},
		"yfxch":      {"Zo_m/2/Yf0,Yrf", "Zm_o/2/Yrf,Yf0"},
		"ystsw":      {"Zo_m/2/Ym", "Zlit/1/Yax"},
	}[table]
}

func mediaX87OriginalEntries(t *testing.T) []X86LegacyOpcode {
	t.Helper()
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts, rows := map[string]int{}, 0
	var entries []X86LegacyOpcode
	for _, entry := range catalog.Optab {
		schema := mediaX87OriginalSchema(entry.Ytab)
		if schema == nil {
			continue
		}
		if entry.Kind != "encoding" || len(entry.Rows) != len(schema) {
			t.Fatal("complete media/x87 original source table changed", entry)
		}
		offset := 0
		for index, row := range entry.Rows {
			shape := fmt.Sprintf("%s/%d/%s", row.ZCase, row.ZOffset, strings.Join(row.Classes, ","))
			if row.RowIndex != index || row.UnmatchedOffset != offset || shape != schema[index] ||
				len(row.Classes) != strings.Count(strings.Split(schema[index], "/")[2], ",")+1 {
				t.Fatal("complete media/x87 original row order or arity changed", entry, row)
			}
			offset += row.ZOffset + entry.EscapeAdjustment
			counts[entry.Ytab]++
			rows++
		}
		entries = append(entries, entry)
	}
	want := map[string]int{"yxcvm1": 8, "yxcvm2": 4, "ylddqu": 2, "yxr": 3,
		"ymr": 1, "yxr_ml": 3, "ymr_ml": 1, "ymrxr": 2, "ymmxmm0f38": 2,
		"ymshuf": 1, "yfxch": 2, "ystsw": 2}
	if rows != 31 || len(entries) != 21 || !reflect.DeepEqual(counts, want) {
		t.Fatal("complete media/x87 original source denominator changed", rows, len(entries), counts)
	}
	return entries
}

// The initial feature RED called existing transport, rather than a missing
// new API. Keep that old source-consumer boundary observable after adding the
// explicit projection; no physical-state permission follows from either view.
func mediaX87ExistingWitnesses(entry X86LegacyOpcode, row X86LegacyOperand) ([]X86ScalarRMWWitness, error) {
	if entry.Ytab == "yfxch" || entry.Ytab == "ystsw" {
		return x86X87RowWitnesses(entry, row)
	}
	if entry.Ytab == "yxr" {
		return x86LegacyExplicitSIMDRowWitnesses(entry, row)
	}
	packed, err := x86PackedLegacyRowWitnesses(entry, row)
	var result []X86ScalarRMWWitness
	for _, witness := range packed {
		result = append(result, X86ScalarRMWWitness{
			Instruction: witness.Instruction, Destination: witness.Destination, Encoding: witness.Encoding,
		})
	}
	return result, err
}

func TestX86LegacyMediaX87CompleteOriginalSourceInventory(t *testing.T) {
	mediaX87OriginalEntries(t)
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"", "arm64", "wasm"} {
		if rows, err := X86LegacyMediaX87Rows(catalog, arch); err == nil || len(rows) != 0 {
			t.Fatal("source view accepted an absent or foreign physical Go mode", arch, err)
		}
	}
	mediaX87CapturedPublicViews(t, catalog)
}

func mediaX87CapturedPublicViews(t *testing.T, catalog X86LegacyCatalog) {
	t.Helper()
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for index, entry := range catalog.Optab {
		view := X86PackedNumericConversionRows
		atom := 3 // The unselected MMX conversion opcode.
		if entry.Ytab == "ymmxmm0f38" {
			view, atom = X86PackedHorizontalIntegerRows, 2
		} else if entry.Ytab != "yxcvm1" && entry.Ytab != "yxcvm2" {
			continue
		} else if entry.Prefix == "Pm" {
			atom = 2 // This source uses a zero stride placeholder at atom3.
		}
		before, err := view(catalog, avx)
		if err != nil {
			t.Fatal("original public view must pass before metadata mutations", entry.Opcode, err)
		}
		for _, field := range []string{"empty-expression", "unselected-byte", "captured-expression-without-rows", "missing-expression-invalid-original-index", "neither-capture-field"} {
			t.Run("public-source/"+entry.Opcode+"/"+field, func(t *testing.T) {
				changed := catalog
				changed.Optab = append([]X86LegacyOpcode(nil), catalog.Optab...)
				item := &changed.Optab[index]
				item.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
				item.OpBytes = append([]string(nil), entry.OpBytes...)
				switch field {
				case "empty-expression":
					item.OpcodeExpression = ""
				case "unselected-byte":
					item.OpBytes[atom] = "not-a-byte"
				case "captured-expression-without-rows":
					item.Rows = nil
				case "missing-expression-invalid-original-index":
					item.OpcodeExpression, item.Rows[0].RowIndex = "", -1
				case "neither-capture-field":
					item.OpcodeExpression, item.Rows = "", nil
				}
				got, err := view(changed, avx)
				if field == "empty-expression" {
					if err != nil || !reflect.DeepEqual(got, before) {
						t.Fatal("existing empty-expression whole-row contract changed", err)
					}
				} else if err == nil || len(got) != 0 {
					t.Fatal("incomplete or corrupt capture acquired public source-view authority", field, got, err)
				}
			})
		}
	}
}

func TestX86LegacyMediaX87ExistingTransportCompleteOriginalRows(t *testing.T) {
	for _, entry := range mediaX87OriginalEntries(t) {
		for _, row := range entry.Rows {
			t.Run(fmt.Sprintf("%s/%d", entry.Opcode, row.RowIndex), func(t *testing.T) {
				before := fmt.Sprintf("%#v", entry)
				witnesses, err := x86LegacyMediaX87RowWitnesses(entry, row)
				if err != nil || len(witnesses) == 0 {
					t.Fatal("MEDIA_X87_COMPLETE_SOURCE_TRANSPORT_FEATURE_GAP", err)
				}
				for _, witness := range witnesses {
					if witness.Instruction == "" || witness.Destination == "" || len(witness.Encoding) == 0 {
						t.Fatal("source-only witness lost its original operand roles", entry, row, witness)
					}
				}
				if before != fmt.Sprintf("%#v", entry) {
					t.Fatal("source formatter mutated the original table")
				}
				previous, previousErr := mediaX87ExistingWitnesses(entry, row)
				old := (entry.Ytab == "yxcvm1" || entry.Ytab == "yxcvm2") && row.RowIndex == 0 ||
					entry.Ytab == "ymmxmm0f38" && row.RowIndex == 1 || entry.Ytab == "yxr" && entry.Prefix == "Pm"
				if old && (previousErr != nil || !reflect.DeepEqual(witnesses, previous)) || !old && (previousErr == nil || len(previous) != 0) {
					t.Fatal("explicit source projection changed the original packed/x87 consumer boundary", previousErr, previous)
				}
				withoutExpression := entry
				withoutExpression.OpcodeExpression = ""
				if got, err := x86LegacyMediaX87RowWitnesses(withoutExpression, row); err != nil || !reflect.DeepEqual(got, witnesses) {
					t.Fatal("whole-row validation incorrectly required a source expression", err)
				}
				if old && entry.Ytab != "yxr" {
					// Historical pure-format fixtures have neither captured
					// rows nor an expression. Retain their old partial result;
					// they cannot produce a complete-source view or NUM facts.
					withoutExpression.Rows = nil
					got, err := mediaX87ExistingWitnesses(withoutExpression, row)
					if err != nil || !reflect.DeepEqual(got, previous) {
						t.Fatal("uncaptured synthetic format contract changed", err)
					}
					if got, err := x86LegacyMediaX87RowWitnesses(withoutExpression, row); err == nil || len(got) != 0 {
						t.Fatal("partial synthetic fixture acquired complete-source authority", got, err)
					}
				}
			})
		}
	}
}

func mediaX87RequireMetadataRefusal(t *testing.T, entry X86LegacyOpcode, row X86LegacyOperand, field string) {
	t.Helper()
	for _, consumer := range []struct {
		name string
		read func(X86LegacyOpcode, X86LegacyOperand) ([]X86ScalarRMWWitness, error)
	}{{"original", mediaX87ExistingWitnesses}, {"complete", x86LegacyMediaX87RowWitnesses}} {
		func() {
			defer func() {
				if caught := recover(); caught != nil {
					t.Errorf("MEDIA_X87_METADATA_PANIC %s/%d/%s: consumer=%s %v", entry.Opcode, row.RowIndex, field, consumer.name, caught)
				}
			}()
			if got, err := consumer.read(entry, row); err == nil || len(got) != 0 {
				t.Errorf("MEDIA_X87_METADATA_ACCEPTED %s/%d/%s: consumer=%s %v", entry.Opcode, row.RowIndex, field, consumer.name, got)
			}
		}()
	}
}

func TestX86LegacyMediaX87CompleteOriginalMetadataBoundaries(t *testing.T) {
	for _, entry := range mediaX87OriginalEntries(t) {
		for _, original := range entry.Rows {
			t.Run(fmt.Sprintf("%s/%d", entry.Opcode, original.RowIndex), func(t *testing.T) {
				for _, field := range []string{
					"kind", "row-count", "original-arity", "selected-arity", "original-comma-arity", "selected-comma-arity",
					"original-class", "selected-class", "original-index", "selected-index", "original-zcase", "selected-zcase",
					"negative-stride", "overflow-stride", "selected-stride", "negative-offset", "selected-offset",
					"negative-escape", "overflow-escape", "prefix", "opcode-expression", "empty-payload", "truncated-payload", "extra-payload",
					"captured-expression-without-rows", "missing-expression-invalid-original-index",
				} {
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
						changed.Rows[0].Classes = append(append([]string(nil), entry.Rows[0].Classes...), "Ynone")
					case "selected-arity":
						row.Classes = append(append([]string(nil), row.Classes...), "Ynone")
					case "original-comma-arity":
						changed.Rows[0].Classes = []string{strings.Join(entry.Rows[0].Classes, ",")}
						if len(entry.Rows[0].Classes) == 1 {
							changed.Rows[0].Classes = nil
						}
					case "selected-comma-arity":
						row.Classes = []string{strings.Join(row.Classes, ",")}
						if len(original.Classes) == 1 {
							row.Classes = nil
						}
					case "original-class":
						changed.Rows[0].Classes = append([]string(nil), entry.Rows[0].Classes...)
						changed.Rows[0].Classes[0] = "Yinvalid"
					case "selected-class":
						row.Classes = append([]string(nil), row.Classes...)
						row.Classes[0] = "Yinvalid"
					case "original-index":
						changed.Rows[0].RowIndex = -1
					case "selected-index":
						row.RowIndex = maxInt
					case "original-zcase":
						changed.Rows[0].ZCase = "Zinvalid"
					case "selected-zcase":
						row.ZCase = "Zinvalid"
					case "negative-stride":
						changed.Rows[0].ZOffset = -maxInt - 1
					case "overflow-stride":
						changed.Rows[0].ZOffset = maxInt
					case "selected-stride":
						row.ZOffset = maxInt
					case "negative-offset":
						changed.Rows[0].UnmatchedOffset = -maxInt - 1
					case "selected-offset":
						row.UnmatchedOffset = maxInt
					case "negative-escape":
						changed.EscapeAdjustment = -1
					case "overflow-escape":
						changed.EscapeAdjustment = maxInt
					case "prefix":
						changed.Prefix = "Pinvalid"
					case "opcode-expression":
						changed.OpcodeExpression = "obj.ANOP"
					case "captured-expression-without-rows":
						changed.Rows = nil
					case "missing-expression-invalid-original-index":
						changed.OpcodeExpression = ""
						changed.Rows[0].RowIndex = -1
					case "empty-payload":
						changed.OpBytes = nil
					case "truncated-payload":
						changed.OpBytes = changed.OpBytes[:len(changed.OpBytes)-1]
					case "extra-payload":
						changed.OpBytes = append(changed.OpBytes, "0x90")
					}
					mediaX87RequireMetadataRefusal(t, changed, row, field)
				}
				// Every original atom is validated, including an unselected
				// row's prefix, opcode, field fragment and literal terminator.
				for index := range entry.OpBytes {
					for _, atom := range []string{"not-a-byte", "0x100"} {
						changed := entry
						changed.OpBytes = append([]string(nil), entry.OpBytes...)
						changed.OpBytes[index] = atom
						mediaX87RequireMetadataRefusal(t, changed, original, fmt.Sprintf("payload-atom-%d-%s", index, atom))
					}
				}
			})
		}
	}
}
