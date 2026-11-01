package goasmrules

import (
	"bytes"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// This inventory is independent of a new formatter. It names the four whole
// source tables, not an opcode-byte registry or a numerical x87 permission.
var x86X87SourceTableNames = map[string]string{
	"yfmvx": `FMOVB FMOVV FMOVX FCOMF FCOMFP FCOML FCOMLP FCOMW FCOMWP
		FADDW FADDL FADDF FMULW FMULL FMULF FSUBW FSUBL FSUBF
		FSUBRW FSUBRL FSUBRF FDIVW FDIVL FDIVF FDIVRW FDIVRL FDIVRF`,
	"yfadd": "FCOMD FCOMDP FADDD FMULD FSUBD FSUBRD FDIVD FDIVRD",
	"yfcmv": `FCMOVCC FCMOVCS FCMOVEQ FCMOVHI FCMOVLS FCMOVB FCMOVBE
		FCMOVNB FCMOVNBE FCMOVE FCMOVNE FCMOVNU FCMOVU FCMOVUN FCOMI FCOMIP`,
	"ycompp": `FCOMDPP FUCOM FUCOMI FUCOMIP FUCOMP FUCOMPP
		FADDDP FMULDP FSUBDP FSUBRDP FDIVDP FDIVRDP`,
}

func x86X87SourceTableMember(entry X86LegacyOpcode) bool {
	_, found := x86X87SourceTableNames[entry.Ytab]
	return found
}

func TestX86LegacyX87CompleteOriginalSourceInventory(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	schemas := map[string][]string{
		"yfmvx":  {"Zm_o/2/Ym,Yf0"},
		"yfadd":  {"Zm_o/2/Ym,Yf0", "Zm_o/2/Yrf,Yf0", "Zo_m/2/Yf0,Yrf"},
		"yfcmv":  {"Zm_o/2/Yrf,Yf0"},
		"ycompp": {"Zo_m/2/Yf0,Yrf"},
	}
	counts, names, identities := map[string]int{}, map[string]bool{}, map[string]bool{}
	fragments := 0
	for _, entry := range catalog.Optab {
		if !x86X87SourceTableMember(entry) {
			continue
		}
		if names[entry.Opcode] || !strings.Contains(" "+strings.Join(strings.Fields(x86X87SourceTableNames[entry.Ytab]), " ")+" ", " "+entry.Opcode+" ") {
			t.Fatal("missing, repeated or foreign x87 source member", entry)
		}
		names[entry.Opcode] = true
		if entry.Kind != "encoding" || entry.Prefix != "Px" || entry.EscapeAdjustment != 0 ||
			len(entry.Rows) != len(schemas[entry.Ytab]) || len(entry.OpBytes) != 2*len(entry.Rows) {
			t.Fatal("complete x87 source schema changed", entry)
		}
		for index, row := range entry.Rows {
			id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex)
			if identities[id] || row.RowIndex != index || row.UnmatchedOffset != 2*index ||
				fmt.Sprintf("%s/%d/%s", row.ZCase, row.ZOffset, strings.Join(row.Classes, ",")) != schemas[entry.Ytab][index] {
				t.Fatal("original ordered x87 row identity changed", id, row)
			}
			identities[id] = true
			counts[entry.Ytab]++
			for atom := 0; atom < 2; atom++ {
				value, err := strconv.ParseUint(entry.OpBytes[2*index+atom], 0, 8)
				if err != nil || atom == 0 && (value < 0xd8 || value > 0xdf) {
					t.Fatal("x87 row lost an actual opcode/ModRM source atom", id, err)
				}
				if atom == 1 && value > 7 {
					fragments++
					if entry.Opcode != "FUCOMPP" || value != 13 {
						t.Fatal("source ModRM field-fragment inventory changed", id, value)
					}
				}
			}
		}
	}
	for table, expected := range map[string]int{"yfmvx": 27, "yfadd": 24, "yfcmv": 16, "ycompp": 12} {
		if counts[table] != expected {
			t.Fatal("incomplete x87 original row family", table, counts[table], expected)
		}
	}
	if len(identities) != 79 || len(names) != 63 || fragments != 1 {
		t.Fatal("x87 row/name/field-fragment union changed", len(identities), len(names), fragments)
	}
}

// The recorded feature RED called the old helper. The new explicit x87
// projection preserves that packed-only refusal and all its original views.
func TestX86LegacyX87ExplicitCarrierTransportRequired(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range catalog.Optab {
		if !x86X87SourceTableMember(entry) {
			continue
		}
		for _, row := range entry.Rows {
			t.Run(fmt.Sprintf("%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex), func(t *testing.T) {
				witnesses, err := x86X87RowWitnesses(entry, row)
				if err != nil || len(witnesses) != 2 {
					t.Fatal("complete original x87 row has no explicit carrier transport", err)
				}
				if previous, err := x86PackedLegacyRowWitnesses(entry, row); err == nil || len(previous) != 0 {
					t.Fatal("x87 projection widened the old packed-only contract", previous, err)
				}
			})
		}
	}
}

func TestX86LegacyX87TransportRejectsForeignSourceAxes(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range catalog.Optab {
		if !x86X87SourceTableMember(original) {
			continue
		}
		for _, selected := range original.Rows {
			for _, control := range []string{"kind", "table", "prefix", "escape", "index", "classes", "zcase", "stride", "offset", "extent", "selected-byte", "unselected-byte"} {
				t.Run(fmt.Sprintf("%s/%d/%s", original.Opcode, selected.RowIndex, control), func(t *testing.T) {
					entry, row := original, selected
					entry.OpBytes = append([]string(nil), original.OpBytes...)
					switch control {
					case "kind":
						entry.Kind = "special"
					case "table":
						entry.Ytab = "unmodeled"
					case "prefix":
						entry.Prefix = "Pw"
					case "escape":
						entry.EscapeAdjustment++
					case "index":
						row.RowIndex = len(entry.Rows)
					case "classes":
						row.Classes = []string{"Yxm", "Yxr"}
					case "zcase":
						row.ZCase = "Zm_r_xm"
					case "stride":
						row.ZOffset++
					case "offset":
						row.UnmatchedOffset++
					case "extent":
						entry.OpBytes = append(entry.OpBytes, "0")
					case "selected-byte":
						entry.OpBytes[row.UnmatchedOffset] = "Pe"
					case "unselected-byte":
						entry.OpBytes[len(entry.OpBytes)-1] = "invalid"
					}
					if witnesses, err := x86X87RowWitnesses(entry, row); err == nil || len(witnesses) != 0 {
						t.Fatal("foreign source attributes supplied an x87 carrier transport", control, witnesses, err)
					}
				})
			}
		}
	}
}

// The remaining MOVE tables form a separate view. Their original row IDs
// must not enlarge the already qualified 79-row projection.
var x86X87MoveSourceSchemas = map[string][]string{
	"yfmvd":  {"Zm_o/2/Ym,Yf0", "Zo_m/2/Yf0,Ym", "Zm_o/2/Yrf,Yf0", "Zo_m/2/Yf0,Yrf"},
	"yfmvdp": {"Zo_m/2/Yf0,Ym", "Zo_m/2/Yf0,Yrf"},
	"yfmvf":  {"Zm_o/2/Ym,Yf0", "Zo_m/2/Yf0,Ym"},
	"yfmvp":  {"Zo_m/2/Yf0,Ym"},
}

func TestX86LegacyX87MoveCompleteOriginalInventory(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts, names, ids := map[string]int{}, map[string]bool{}, map[string]bool{}
	for _, entry := range catalog.Optab {
		schema := x86X87MoveSourceSchemas[entry.Ytab]
		if schema == nil {
			continue
		}
		if names[entry.Opcode] || entry.Kind != "encoding" || entry.Prefix != "Px" ||
			entry.EscapeAdjustment != 0 || len(entry.Rows) != len(schema) || len(entry.OpBytes) != 2*len(schema) {
			t.Fatal("complete original MOVE entry changed", entry)
		}
		names[entry.Opcode] = true
		for index, row := range entry.Rows {
			id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex)
			if ids[id] || row.RowIndex != index || row.UnmatchedOffset != 2*index ||
				fmt.Sprintf("%s/%d/%s", row.ZCase, row.ZOffset, strings.Join(row.Classes, ",")) != schema[index] {
				t.Fatal("original ordered MOVE identity changed", id, row)
			}
			ids[id] = true
			counts[entry.Ytab]++
		}
	}
	for table, expected := range map[string]int{"yfmvd": 4, "yfmvdp": 2, "yfmvf": 6, "yfmvp": 6} {
		if counts[table] != expected {
			t.Fatal("incomplete original MOVE family", table, counts[table], expected)
		}
	}
	if len(ids) != 18 || len(names) != 11 {
		t.Fatal("MOVE source-row/name denominator changed", len(ids), len(names))
	}
}

// RED uses the existing renderer's actual refusal, not an absent new API or
// a claim that the initialized translator cannot execute this instruction.
func TestX86LegacyX87MoveTransportCompleteDirections(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range catalog.Optab {
		if x86X87MoveSourceSchemas[entry.Ytab] == nil {
			continue
		}
		for _, row := range entry.Rows {
			t.Run(fmt.Sprintf("%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex), func(t *testing.T) {
				id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex)
				expected := map[string]X86ScalarRMWWitness{}
				opcode, firstErr := strconv.ParseUint(entry.OpBytes[row.UnmatchedOffset], 0, 8)
				fragment, lastErr := strconv.ParseUint(entry.OpBytes[row.UnmatchedOffset+1], 0, 8)
				if firstErr != nil || lastErr != nil {
					t.Fatal("independent original MOVE payload", id, firstErr, lastErr)
				}
				for _, lane := range []byte{1, 7} {
					first, last := fmt.Sprint("F", lane), "F0"
					code := []byte{byte(opcode), 0xc0 | lane | byte(fragment<<3)}
					if row.Classes[0] == "Ym" || row.Classes[1] == "Ym" {
						first, code = "(AX)", []byte{byte(opcode), byte(fragment << 3)}
						if lane == 7 {
							first, code = "7(AX)", []byte{byte(opcode), 0x40 | byte(fragment<<3), 7}
						}
					}
					if row.ZCase == "Zo_m" {
						first, last = last, first
					}
					instruction := entry.Opcode + " " + first + "," + last
					expected[id+"/"+instruction] = X86ScalarRMWWitness{Instruction: instruction, Destination: last, Encoding: code}
				}
				witnesses, err := x86X87RowWitnesses(entry, row)
				if err != nil || len(witnesses) != 2 {
					t.Fatal("X87_MOVE_SOURCE_TRANSPORT_FEATURE_GAP", err)
				}
				for _, witness := range witnesses {
					key := id + "/" + witness.Instruction
					want, found := expected[key]
					if !found || !bytes.Equal(witness.Encoding, want.Encoding) || witness.Destination != want.Destination {
						t.Fatal("MOVE transport differs from the independent actual-Go source cases", key, witness, want)
					}
					delete(expected, key)
				}
				if len(expected) != 0 {
					t.Fatal("MOVE transport omitted an independent original source case", id, expected)
				}
			})
		}
	}
}

func TestX86LegacyX87MoveRejectsChangedPayloadAndDirection(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range catalog.Optab {
		if x86X87MoveSourceSchemas[original.Ytab] == nil {
			continue
		}
		for _, selected := range original.Rows {
			for _, control := range []string{"prefix", "stride", "offset", "extent", "row-order", "direction", "unselected-byte", "memory-digit"} {
				if control == "memory-digit" && selected.Classes[0] != "Ym" && selected.Classes[1] != "Ym" {
					continue
				}
				t.Run(fmt.Sprintf("%s/%d/%s", original.Opcode, selected.RowIndex, control), func(t *testing.T) {
					entry, row := original, selected
					entry.OpBytes = append([]string(nil), original.OpBytes...)
					entry.Rows = append([]X86LegacyOperand(nil), original.Rows...)
					switch control {
					case "prefix":
						entry.Prefix = "Pw"
					case "stride":
						row.ZOffset++
					case "offset":
						row.UnmatchedOffset++
					case "extent":
						entry.OpBytes = append(entry.OpBytes, "0")
					case "row-order":
						entry.Rows[0].RowIndex++
					case "direction":
						row.ZCase = "Zlit"
					case "unselected-byte":
						entry.OpBytes[len(entry.OpBytes)-1] = "invalid"
					case "memory-digit":
						entry.OpBytes[row.UnmatchedOffset+1] = "8"
					}
					if witnesses, err := x86X87RowWitnesses(entry, row); err == nil || len(witnesses) != 0 {
						t.Fatal("changed original MOVE source acquired a format witness", control, witnesses, err)
					}
				})
			}
		}
	}
}

func TestX86LegacyX87MoveViewPreservesOriginalProjection(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		original, err := X86X87Rows(catalog, arch)
		if err != nil || len(original) != 79 {
			t.Fatal("MOVE closure enlarged the original x87 projection", arch, err)
		}
		seen := map[string]bool{}
		for _, row := range original {
			seen[row.ID] = true
		}
		moves, err := X86X87MoveRows(catalog, arch)
		if err != nil || len(moves) != 18 {
			t.Fatal("remaining MOVE projection lost its complete rows", arch, err)
		}
		for _, row := range moves {
			if seen[row.ID] || len(row.Witnesses) != 2 {
				t.Fatal("new MOVE source identity repeated or overlapped the original view", arch, row)
			}
			seen[row.ID] = true
		}
		if len(seen) != 97 {
			t.Fatal("old/new original x87 source union changed", arch, len(seen))
		}
	}
	for _, arch := range []string{"", "arm", "arm64", "wasm"} {
		if rows, err := X86X87MoveRows(catalog, arch); err == nil || len(rows) != 0 {
			t.Fatal("MOVE source projection inferred a missing or foreign x86 mode", arch, rows, err)
		}
	}
}

func TestX86LegacyX87MoveRejectsMalformedClassTuples(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range catalog.Optab {
		if x86X87MoveSourceSchemas[original.Ytab] == nil {
			continue
		}
		for _, selected := range original.Rows {
			for _, owner := range []string{"original", "selected"} {
				t.Run(fmt.Sprintf("%s/%d/%s", original.Opcode, selected.RowIndex, owner), func(t *testing.T) {
					entry, row := original, selected
					entry.Rows = append([]X86LegacyOperand(nil), original.Rows...)
					// Joining class names is not injective. This malformed
					// single class has the same text as the two-class schema.
					malformed := []string{strings.Join(selected.Classes, ",")}
					if owner == "original" {
						entry.Rows[selected.RowIndex].Classes = malformed
					} else {
						row.Classes = malformed
					}
					defer func() {
						if value := recover(); value != nil {
							t.Fatal("X87_MOVE_MALFORMED_CLASS_TUPLE_PANIC", owner, value)
						}
					}()
					if witnesses, err := x86X87RowWitnesses(entry, row); err == nil || len(witnesses) != 0 {
						t.Fatal("malformed class tuple acquired a source witness", owner, witnesses, err)
					}
				})
			}
		}
	}
}
