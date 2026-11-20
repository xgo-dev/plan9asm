package goasmrules

import (
	"bytes"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestX86ScalarMoveExtensionOriginalTransport(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range catalog.Optab {
		if !strings.HasPrefix(entry.Opcode, "MOV") || entry.Ytab != "ymb_rl" && entry.Ytab != "yml_rl" {
			continue
		}
		count++
		t.Run(entry.Opcode, func(t *testing.T) {
			witnesses, err := x86ScalarRMWRowWitnesses(entry, entry.Rows[0], "amd64")
			if err != nil || len(witnesses) != 2 {
				t.Fatal("SCALAR_EXTENSION_SOURCE_FEATURE_GAP", err)
			}
		})
	}
	if count != 14 {
		t.Fatal("complete extension source family changed", count)
	}
}

func TestX86ScalarMoveExtensionCompleteRowsAndModes(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := X86ScalarMoveExtensionRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		seen, filtered, witnesses := map[string]bool{}, 0, 0
		for _, row := range rows {
			if row.ID == "" || seen[row.ID] || row.Opcode == "MOVLQZX" && row.ModeFiltered != "" {
				t.Fatal("source identity or legal mode32 MOVLQZX lost", row)
			}
			seen[row.ID] = true
			if row.ModeFiltered != "" {
				filtered++
				if len(row.Witnesses) != 0 {
					t.Fatal("mode32 Pw form acquired selected syntax")
				}
			}
			witnesses += len(row.Witnesses)
		}
		if len(rows) != 14 || filtered != map[string]int{"amd64": 0, "386": 5}[arch] || witnesses != map[string]int{"amd64": 28, "386": 18}[arch] {
			t.Fatal("complete extension source/mode closure changed", arch, len(rows), filtered, witnesses)
		}
	}
	for _, arch := range []string{"", "arm64", "wasm"} {
		if _, err := X86ScalarMoveExtensionRows(catalog, arch); err == nil {
			t.Fatal("foreign mode acquired x86 extension source rows", arch)
		}
	}
	if _, err := X86ScalarMoveExtensionRows(X86LegacyCatalog{}, "amd64"); err == nil {
		t.Fatal("empty extension source silently passed")
	}
	for index, entry := range catalog.Optab {
		if entry.Opcode != "MOVSWW" {
			continue
		}
		changed := catalog
		changed.Optab = append(append([]X86LegacyOpcode(nil), catalog.Optab[:index]...), catalog.Optab[index+1:]...)
		if _, err := X86ScalarMoveExtensionRows(changed, "amd64"); err == nil {
			t.Fatal("missing word-word source silently passed")
		}
		changed.Optab = append(append([]X86LegacyOpcode(nil), catalog.Optab...), entry)
		if _, err := X86ScalarMoveExtensionRows(changed, "amd64"); err == nil {
			t.Fatal("duplicate extension source silently passed")
		}
		break
	}
}

func TestX86ScalarMoveExtensionCompleteMetadataBoundaries(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	maxInt := int(^uint(0) >> 1)
	for _, entry := range catalog.Optab {
		if !strings.HasPrefix(entry.Opcode, "MOV") || entry.Ytab != "ymb_rl" && entry.Ytab != "yml_rl" {
			continue
		}
		for _, field := range []string{"original-arity", "selected-arity", "original-index", "selected-index", "original-offset",
			"selected-offset", "original-stride", "selected-stride", "zcase", "row-count", "prefix", "source-role", "opcode", "nonbyte", "payload-short", "payload-extra"} {
			t.Run(entry.Opcode+"/"+field, func(t *testing.T) {
				changed, row := entry, entry.Rows[0]
				changed.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
				changed.OpBytes = append([]string(nil), entry.OpBytes...)
				switch field {
				case "original-arity":
					changed.Rows[0].Classes = []string{strings.Join(row.Classes, ",")}
				case "selected-arity":
					row.Classes = []string{strings.Join(row.Classes, ",")}
				case "original-index":
					changed.Rows[0].RowIndex++
				case "selected-index":
					row.RowIndex = -1
				case "original-offset":
					changed.Rows[0].UnmatchedOffset = -1
				case "selected-offset":
					row.UnmatchedOffset = maxInt
				case "original-stride":
					changed.Rows[0].ZOffset = maxInt
				case "selected-stride":
					row.ZOffset = -1
				case "zcase":
					changed.Rows[0].ZCase, row.ZCase = "Zr_m", "Zr_m"
				case "row-count":
					changed.Rows = append(changed.Rows, row)
				case "prefix":
					changed.Prefix = "P32"
				case "source-role":
					changed.Ytab, row.ZCase, row.Classes = "yml_rl", "Zm_r", []string{"Yml", "Yrl"}
					if entry.Ytab == "yml_rl" {
						changed.Ytab, row.ZCase, row.Classes = "ymb_rl", "Zmb_r", []string{"Ymb", "Yrl"}
					}
					changed.Rows[0] = row
				case "opcode":
					changed.Opcode += ".BAD"
				case "nonbyte":
					changed.OpBytes[0] = "0x100"
				case "payload-short":
					changed.OpBytes = changed.OpBytes[:len(changed.OpBytes)-1]
				case "payload-extra":
					changed.OpBytes = append(changed.OpBytes, "0")
				}
				if _, err := x86ScalarRMWRowWitnesses(changed, row, "amd64"); err == nil {
					t.Fatal("SCALAR_EXTENSION_MALFORMED_ACCEPTED", field)
				}
			})
		}
		for _, escape := range []int{-4, -1, 2, maxInt - 1, maxInt} {
			t.Run(fmt.Sprintf("%s/escape%d", entry.Opcode, escape), func(t *testing.T) {
				changed := entry
				changed.EscapeAdjustment = escape
				defer func() {
					if failure := recover(); failure != nil {
						t.Error("SCALAR_EXTENSION_METADATA_PANIC", failure)
					}
				}()
				if _, err := x86ScalarRMWRowWitnesses(changed, changed.Rows[0], "amd64"); err == nil {
					t.Fatal("SCALAR_EXTENSION_MALFORMED_ACCEPTED", escape)
				}
			})
		}
	}
}

func TestX86ScalarImplicitMulDivOriginalSourceTransport(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	selected, excluded := 0, 0
	numeric := regexp.MustCompile(`^(?:I?MUL|I?DIV)[BWLQ]$`)
	for _, entry := range catalog.Optab {
		if numeric.MatchString(entry.Opcode) && (entry.Ytab == "ydivb" || entry.Ytab == "ydivl" || entry.Ytab == "yimul") {
			selected++
			t.Run(entry.Opcode, func(t *testing.T) {
				witnesses, err := x86ScalarRMWRowWitnesses(entry, entry.Rows[0], "amd64")
				if err != nil || len(witnesses) != 2 {
					t.Fatal("SCALAR_IMPLICIT_MULDIV_SOURCE_FEATURE_GAP", err)
				}
			})
		} else if entry.Ytab == "ydivb" || entry.Ytab == "ydivl" {
			excluded++
			t.Run("separate-state-or-nop/"+entry.Opcode, func(t *testing.T) {
				if _, err := x86ScalarRMWRowWitnesses(entry, entry.Rows[0], "amd64"); err == nil {
					t.Fatal("descriptor/state/NOP acquired the numerical source transport")
				}
			})
		}
	}
	if selected != 16 || excluded != 12 {
		t.Fatal("complete numerical/state source partition changed", selected, excluded)
	}
}

func TestX86ScalarImplicitMulDivCompleteRowsAndModes(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := X86ScalarImplicitMulDivRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		seen, filtered, witnesses := map[string]bool{}, 0, 0
		for _, row := range rows {
			if row.ID == "" || seen[row.ID] {
				t.Fatal("implicit source identity is absent or repeated", row.ID)
			}
			seen[row.ID] = true
			if row.ModeFiltered != "" {
				filtered++
				if len(row.Witnesses) != 0 {
					t.Fatal("386 Q source acquired a named witness")
				}
			}
			for _, witness := range row.Witnesses {
				if witness.Destination != "AX" {
					t.Fatal("implicit primary result lost AX/AL:AH carrier", witness)
				}
				witnesses++
			}
		}
		if len(rows) != 16 || filtered != map[string]int{"amd64": 0, "386": 4}[arch] ||
			witnesses != map[string]int{"amd64": 32, "386": 24}[arch] {
			t.Fatal("complete implicit source/mode union differs", arch, len(rows), filtered, witnesses)
		}
	}
	for _, arch := range []string{"", "arm", "wasm"} {
		if _, err := X86ScalarImplicitMulDivRows(catalog, arch); err == nil {
			t.Fatal("foreign mode acquired an implicit x86 source view", arch)
		}
	}
	if _, err := X86ScalarImplicitMulDivRows(X86LegacyCatalog{}, "amd64"); err == nil {
		t.Fatal("missing source closure silently passed")
	}
	for index, entry := range catalog.Optab {
		if entry.Opcode != "DIVB" {
			continue
		}
		changed := catalog
		changed.Optab = append(append([]X86LegacyOpcode(nil), catalog.Optab[:index]...), catalog.Optab[index+1:]...)
		if _, err := X86ScalarImplicitMulDivRows(changed, "amd64"); err == nil {
			t.Fatal("missing original family member silently passed")
		}
		changed.Optab = append(append([]X86LegacyOpcode(nil), catalog.Optab...), entry)
		if _, err := X86ScalarImplicitMulDivRows(changed, "amd64"); err == nil {
			t.Fatal("duplicate original family member silently passed")
		}
		break
	}
}

func TestX86ScalarImplicitMulDivMalformedSourceIsBounded(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	numeric := regexp.MustCompile(`^(?:I?MUL|I?DIV)[BWLQ]$`)
	maxInt := int(^uint(0) >> 1)
	for _, entry := range catalog.Optab {
		if !numeric.MatchString(entry.Opcode) || entry.Ytab != "ydivb" && entry.Ytab != "ydivl" && entry.Ytab != "yimul" {
			continue
		}
		for _, mutation := range []string{"original-arity", "selected-arity", "original-index", "selected-index",
			"original-offset", "selected-offset", "original-stride", "selected-stride", "zcase", "row-count",
			"prefix", "width-and-prefix", "non-numerical-family", "payload-short", "payload-extra", "nonbyte", "extension"} {
			if mutation == "non-numerical-family" && entry.Ytab == "yimul" {
				continue // The old general ytab formatter has no family-name contract.
			}
			t.Run(entry.Opcode+"/"+mutation, func(t *testing.T) {
				changed, row := entry, entry.Rows[0]
				changed.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
				changed.OpBytes = append([]string(nil), entry.OpBytes...)
				switch mutation {
				case "original-arity":
					changed.Rows[0].Classes = append(append([]string(nil), row.Classes...), "")
				case "selected-arity":
					row.Classes = append(append([]string(nil), row.Classes...), "")
				case "original-index":
					changed.Rows[0].RowIndex++
				case "selected-index":
					row.RowIndex = -1
				case "original-offset":
					changed.Rows[0].UnmatchedOffset = -1
				case "selected-offset":
					row.UnmatchedOffset = maxInt
				case "original-stride":
					changed.Rows[0].ZOffset = maxInt
				case "selected-stride":
					row.ZOffset = -1
				case "zcase":
					changed.Rows[0].ZCase, row.ZCase = "Zo_m", "Zo_m"
				case "row-count":
					changed.Rows = append(changed.Rows, row)
				case "prefix":
					changed.Prefix = "P32"
				case "width-and-prefix":
					width, prefix := "B", "Pb"
					if strings.HasSuffix(entry.Opcode, "B") {
						width, prefix = "W", "Pe"
					}
					changed.Opcode, changed.Prefix = entry.Opcode[:len(entry.Opcode)-1]+width, prefix
				case "non-numerical-family":
					changed.Opcode = "NOP" + entry.Opcode[len(entry.Opcode)-1:]
				case "payload-short":
					changed.OpBytes = changed.OpBytes[:len(changed.OpBytes)-1]
				case "payload-extra":
					changed.OpBytes = append(changed.OpBytes, "0")
				case "nonbyte":
					changed.OpBytes[0] = "0x100"
				case "extension":
					changed.OpBytes[1] = "8"
				}
				if _, err := x86ScalarRMWRowWitnesses(changed, row, "amd64"); err == nil {
					t.Fatal("SCALAR_IMPLICIT_MULDIV_MALFORMED_ACCEPTED", mutation)
				}
			})
		}
		for _, escape := range []int{-4, -3, -1, 1, 2, maxInt - 1, maxInt} {
			t.Run(fmt.Sprintf("%s/escape%d", entry.Opcode, escape), func(t *testing.T) {
				changed := entry
				changed.EscapeAdjustment = escape
				changed.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
				offset := 0
				for index := range changed.Rows {
					changed.Rows[index].UnmatchedOffset = offset
					offset += changed.Rows[index].ZOffset + escape
				}
				defer func() {
					if failure := recover(); failure != nil {
						t.Error("SCALAR_IMPLICIT_MULDIV_METADATA_PANIC", escape, failure)
					}
				}()
				if _, err := x86ScalarRMWRowWitnesses(changed, changed.Rows[0], "amd64"); err == nil {
					t.Fatal("SCALAR_IMPLICIT_MULDIV_MALFORMED_ACCEPTED", escape)
				}
			})
		}
	}
}

func TestX86ScalarCompleteOriginalSchemaBeforeSelectedPayload(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var entry X86LegacyOpcode
	for _, candidate := range catalog.Optab {
		if candidate.Opcode == "ADDL" {
			entry = candidate
		}
	}
	if len(entry.Rows) != 5 || entry.Ytab != "yaddl" {
		t.Fatal("independent original multi-row scalar fixture changed")
	}
	if witnesses, err := x86ScalarRMWRowWitnesses(entry, entry.Rows[1], "amd64"); err != nil || len(witnesses) != 1 {
		t.Fatal("original complete source positive was not accepted", err)
	}
	maxInt := int(^uint(0) >> 1)
	minInt := -maxInt - 1
	check := func(t *testing.T, changed X86LegacyOpcode, selected X86LegacyOperand) {
		t.Helper()
		defer func() {
			if failure := recover(); failure != nil {
				t.Error("SCALAR_SHARED_SCHEMA_PANIC", failure)
			}
		}()
		if _, err := x86ScalarRMWRowWitnesses(changed, selected, "amd64"); err == nil {
			t.Fatal("SCALAR_SHARED_SCHEMA_INVALID_ACCEPTED")
		}
	}
	for index := range entry.Rows {
		for _, field := range []string{"index", "zcase", "stride", "offset", "arity"} {
			t.Run(fmt.Sprintf("original%d/%s", index, field), func(t *testing.T) {
				changed := entry
				changed.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
				original := &changed.Rows[index]
				switch field {
				case "index":
					original.RowIndex++
				case "zcase":
					original.ZCase = "Zunknown"
				case "stride":
					original.ZOffset = 0
				case "offset":
					original.UnmatchedOffset = -1
				case "arity":
					original.Classes = []string{strings.Join(original.Classes, ",")}
				}
				check(t, changed, entry.Rows[1])
			})
		}
	}
	for _, field := range []string{"arity", "index", "zcase", "stride", "offset"} {
		t.Run("selected/"+field, func(t *testing.T) {
			selected := entry.Rows[1]
			switch field {
			case "arity":
				selected.Classes = []string{strings.Join(selected.Classes, ",")}
			case "index":
				selected.RowIndex = -1
			case "zcase":
				selected.ZCase = "Zunknown"
			case "stride":
				selected.ZOffset = -1
			case "offset":
				selected.UnmatchedOffset = minInt
			}
			check(t, entry, selected)
		})
	}
	for _, value := range []int{0, minInt, maxInt} {
		t.Run(fmt.Sprintf("consistent-previous-stride%d", value), func(t *testing.T) {
			changed := entry
			changed.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
			changed.Rows[0].ZOffset = value
			selected := entry.Rows[1]
			selected.UnmatchedOffset = value
			if value == maxInt {
				selected = entry.Rows[2]
				selected.UnmatchedOffset = value + entry.Rows[1].ZOffset
			}
			// Keep the final original payload boundary untouched. The old
			// selected-offset check alone accepts zero or wrapped offsets.
			check(t, changed, selected)
		})
	}
}

// This exercises the existing scalar transport before adding a new view. A
// source-format refusal is a missing projection, not a numerical defect.
func TestX86ScalarMultiplyMOVBECompleteSourceTransport(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range catalog.Optab {
		if entry.Ytab != "yimul" && entry.Ytab != "yimul3" && entry.Ytab != "ymovbe" {
			continue
		}
		for _, row := range entry.Rows {
			count++
			t.Run(fmt.Sprintf("%s/%d", entry.Opcode, row.RowIndex), func(t *testing.T) {
				witnesses, err := x86ScalarRMWRowWitnesses(entry, row, "amd64")
				if err != nil || len(witnesses) == 0 {
					t.Fatal("SCALAR_MULTIPLY_MOVBE_SOURCE_FEATURE_GAP", err)
				}
			})
		}
	}
	if count != 24 {
		t.Fatal("complete original three-table denominator changed", count)
	}
}

func TestX86ScalarMultiplyMOVBECompleteRowsAndModes(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := X86ScalarMultiplyMOVBERows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		seen, filtered, witnesses := map[string]bool{}, 0, 0
		for _, row := range rows {
			if row.ID == "" || seen[row.ID] {
				t.Fatal("duplicate or missing original row identity", row.ID)
			}
			seen[row.ID] = true
			if row.ModeFiltered != "" {
				filtered++
				if len(row.Witnesses) != 0 {
					t.Fatal("refused source mode acquired a witness")
				}
			}
			witnesses += len(row.Witnesses)
		}
		if len(rows) != 24 || filtered != map[string]int{"amd64": 0, "386": 8}[arch] ||
			witnesses != map[string]int{"amd64": 36, "386": 24}[arch] {
			t.Fatal("complete scalar multiply/MOVBE source-mode closure changed", arch, len(rows), filtered, witnesses)
		}
	}
	for _, arch := range []string{"", "arm64", "wasm"} {
		if _, err := X86ScalarMultiplyMOVBERows(catalog, arch); err == nil {
			t.Fatal("foreign source mode acquired scalar transport", arch)
		}
	}
	if _, err := X86ScalarMultiplyMOVBERows(X86LegacyCatalog{}, "amd64"); err == nil {
		t.Fatal("empty source inventory silently passed")
	}
	for index, entry := range catalog.Optab {
		if entry.Ytab != "yimul3" {
			continue
		}
		changed := catalog
		changed.Optab = append(append([]X86LegacyOpcode(nil), catalog.Optab[:index]...), catalog.Optab[index+1:]...)
		if _, err := X86ScalarMultiplyMOVBERows(changed, "amd64"); err == nil {
			t.Fatal("missing complete source member admitted")
		}
		changed.Optab = append(append([]X86LegacyOpcode(nil), catalog.Optab...), entry)
		if _, err := X86ScalarMultiplyMOVBERows(changed, "amd64"); err == nil {
			t.Fatal("duplicate complete source member admitted")
		}
		break
	}
}

func TestX86ScalarMultiplyMOVBERejectsMalformedSource(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range catalog.Optab {
		if entry.Ytab != "yimul" && entry.Ytab != "yimul3" && entry.Ytab != "ymovbe" {
			continue
		}
		for _, row := range entry.Rows {
			mutations := []string{"original-arity", "selected-arity", "original-index", "selected-index",
				"original-zcase", "selected-zcase", "original-offset", "selected-offset",
				"original-stride", "selected-stride", "row-count", "prefix", "escape", "payload-short"}
			if entry.Ytab == "yimul3" {
				mutations = append(mutations, "original-immediate-role", "selected-immediate-role")
			}
			for _, mutation := range mutations {
				t.Run(fmt.Sprintf("%s/%d/%s", entry.Opcode, row.RowIndex, mutation), func(t *testing.T) {
					changed, selected := entry, row
					changed.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
					changed.OpBytes = append([]string(nil), entry.OpBytes...)
					original := &changed.Rows[row.RowIndex]
					switch mutation {
					case "original-arity":
						original.Classes = []string{strings.Join(original.Classes, ",")}
						if len(row.Classes) == 1 {
							original.Classes = append(original.Classes, "")
						}
					case "selected-arity":
						selected.Classes = []string{strings.Join(selected.Classes, ",")}
						if len(row.Classes) == 1 {
							selected.Classes = append(selected.Classes, "")
						}
					case "original-index":
						original.RowIndex++
					case "selected-index":
						selected.RowIndex = -1
					case "original-zcase":
						original.ZCase = "Zibr_m"
					case "selected-zcase":
						selected.ZCase = "Zibr_m"
					case "original-offset":
						original.UnmatchedOffset++
					case "selected-offset":
						selected.UnmatchedOffset++
					case "original-stride":
						original.ZOffset++
					case "selected-stride":
						selected.ZOffset++
					case "row-count":
						changed.Rows = append(changed.Rows, row)
					case "prefix":
						changed.Prefix = "P32"
					case "escape":
						changed.EscapeAdjustment++
					case "payload-short":
						changed.OpBytes = changed.OpBytes[:len(changed.OpBytes)-1]
					case "original-immediate-role":
						original.Classes = append([]string(nil), original.Classes...)
						original.Classes[0] = "Yu8"
					case "selected-immediate-role":
						selected.Classes = append([]string(nil), selected.Classes...)
						selected.Classes[0] = "Yu8"
					}
					// No malformed metadata may panic before returning a refusal.
					if _, err := x86ScalarRMWRowWitnesses(changed, selected, "amd64"); err == nil {
						t.Fatal("SCALAR_MULTIPLY_MOVBE_MALFORMED_ACCEPTED", mutation)
					}
				})
			}
			for atom := range entry.OpBytes {
				values := []string{"0x100", "not-a-byte"}
				if entry.Ytab == "yimul" {
					if atom == 1 {
						values = append(values, "8")
					} else if atom == 4 {
						values = append(values, "0x0f", "Pe")
					} else {
						values = append(values, "0")
					}
				} else if entry.OpBytes[atom] == "0" || entry.OpBytes[atom] == "00" {
					values = append(values, "1")
				} else {
					values = append(values, "0")
				}
				for _, value := range values {
					t.Run(fmt.Sprintf("%s/%d/atom%d/%s", entry.Opcode, row.RowIndex, atom, value), func(t *testing.T) {
						changed := entry
						changed.OpBytes = append([]string(nil), entry.OpBytes...)
						changed.OpBytes[atom] = value
						if _, err := x86ScalarRMWRowWitnesses(changed, row, "amd64"); err == nil {
							t.Fatal("SCALAR_MULTIPLY_MOVBE_MALFORMED_ACCEPTED", atom, value)
						}
					})
				}
			}
		}
	}
}

func TestX86ScalarMultiplyMOVBEEscapeBoundsBeforePayload(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	maxInt := int(^uint(0) >> 1)
	entries := 0
	for _, entry := range catalog.Optab {
		if entry.Ytab != "yimul" && entry.Ytab != "yimul3" && entry.Ytab != "ymovbe" {
			continue
		}
		entries++
		for _, escape := range []int{-4, -3, -1, 2, maxInt - 1, maxInt} {
			t.Run(fmt.Sprintf("%s/escape%d", entry.Opcode, escape), func(t *testing.T) {
				changed := entry
				changed.EscapeAdjustment = escape
				changed.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
				offset := 0
				for index := range changed.Rows {
					changed.Rows[index].UnmatchedOffset = offset
					offset += changed.Rows[index].ZOffset + escape
				}
				// Offsets intentionally remain consistent with the malformed
				// adjustment. An earlier unrelated row mismatch must not hide
				// a negative slice length or overflowing span calculation.
				defer func() {
					if failure := recover(); failure != nil {
						t.Error("SCALAR_MULTIPLY_MOVBE_ESCAPE_PANIC", escape, failure)
					}
				}()
				if _, err := x86ScalarRMWRowWitnesses(changed, changed.Rows[0], "amd64"); err == nil {
					t.Fatal("SCALAR_MULTIPLY_MOVBE_MALFORMED_ACCEPTED", escape)
				}
			})
		}
	}
	if entries != 9 {
		t.Fatal("escape bounds control lost complete source entries", entries)
	}
}

func TestX86ScalarMultiplyMOVBERejectsByteWidthTableMutation(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range catalog.Optab {
		if entry.Ytab != "yimul" && entry.Ytab != "yimul3" && entry.Ytab != "ymovbe" {
			continue
		}
		for _, row := range entry.Rows {
			count++
			t.Run(fmt.Sprintf("%s/%d", entry.Opcode, row.RowIndex), func(t *testing.T) {
				changed := entry
				changed.Opcode = entry.Opcode[:len(entry.Opcode)-1] + "B"
				changed.Prefix = "Pb"
				// Keep all original rows and bytes coherent. IMULB belongs to
				// the independent ydivb table, not the W/L/Q carrier grammar.
				if _, err := x86ScalarRMWRowWitnesses(changed, row, "amd64"); err == nil {
					t.Fatal("SCALAR_MULTIPLY_MOVBE_BYTE_WIDTH_ACCEPTED", entry.Ytab)
				}
			})
		}
	}
	if count != 24 {
		t.Fatal("width mutation lost complete original source rows", count)
	}
}

func TestX86ScalarRMWCompleteOrderedRowsAndModes(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []struct {
		arch                string
		filtered, witnesses int
	}{{"amd64", 2, 278}, {"386", 45, 202}} {
		rows, err := X86ScalarRMWRows(catalog, mode.arch)
		if err != nil {
			t.Fatal(err)
		}
		names, ids := map[string]bool{}, map[string]bool{}
		filtered, witnesses := 0, 0
		for _, row := range rows {
			if row.ID == "" || ids[row.ID] || row.ModeFiltered == "" && len(row.Witnesses) == 0 {
				t.Fatal("lost source identity or selected syntax", row)
			}
			ids[row.ID], names[row.Opcode] = true, true
			if row.ModeFiltered != "" {
				filtered++
				if len(row.Witnesses) != 0 {
					t.Fatal("mode-filtered row acquired a selected witness", row)
				}
			}
			for _, witness := range row.Witnesses {
				if !strings.HasPrefix(witness.Instruction, row.Opcode+" ") || len(witness.Encoding) == 0 || witness.Destination == "" {
					t.Fatal("incomplete selected scalar witness", row)
				}
				witnesses++
			}
		}
		if len(rows) != 169 || len(names) != 53 || filtered != mode.filtered || witnesses != mode.witnesses {
			t.Fatal("source/mode/selected grammar denominator changed", mode, len(rows), len(names), filtered, witnesses)
		}
	}
	if _, err := X86ScalarRMWRows(catalog, "arm64"); err == nil {
		t.Fatal("foreign mode entered x86 scalar projection")
	}
	if _, err := X86ScalarRMWRows(X86LegacyCatalog{}, "amd64"); err == nil {
		t.Fatal("missing source closure was treated as successful empty coverage")
	}
	for index, entry := range catalog.Optab {
		if entry.Opcode != "ADCB" {
			continue
		}
		changed := catalog
		changed.Optab = append(append([]X86LegacyOpcode(nil), catalog.Optab[:index]...), catalog.Optab[index+1:]...)
		if _, err := X86ScalarRMWRows(changed, "amd64"); err == nil {
			t.Fatal("missing family member admitted")
		}
		changed.Optab = append(append([]X86LegacyOpcode(nil), catalog.Optab...), entry)
		if _, err := X86ScalarRMWRows(changed, "amd64"); err == nil {
			t.Fatal("duplicate source member admitted")
		}
		break
	}
}

func TestX86ScalarRMWSelectedPayloadAnchors(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	anchors := []struct {
		mode, instruction string
		code              []byte
	}{
		{"amd64", "ADDB $128,AL", []byte{0x04, 0x80}},
		{"amd64", "ADDW $128,AX", []byte{0x66, 0x05, 0x80, 0}},
		{"amd64", "ADDL $1,BX", []byte{0x83, 0xc3, 1}},
		{"amd64", "ADDQ $128,BX", []byte{0x48, 0x81, 0xc3, 0x80, 0, 0, 0}},
		{"amd64", "SUBL CX,0(SI)", []byte{0x29, 0x0e}},
		{"amd64", "SUBL 0(SI),BX", []byte{0x2b, 0x1e}},
		{"amd64", "BTSQ $1,BX", []byte{0x48, 0x0f, 0xba, 0xeb, 1}},
		{"amd64", "BTCW CX,0(SI)", []byte{0x66, 0x0f, 0xbb, 0x0e}},
		{"amd64", "INCL BX", []byte{0xff, 0xc3}},
		{"386", "INCL BX", []byte{0x43}},
		{"386", "DECL 0(SI)", []byte{0xff, 0x0e}},
		{"amd64", "NOTB BL", []byte{0xf6, 0xd3}},
	}
	for _, anchor := range anchors {
		t.Run(anchor.mode+"/"+anchor.instruction, func(t *testing.T) {
			rows, err := X86ScalarRMWRows(catalog, anchor.mode)
			if err != nil {
				t.Fatal(err)
			}
			matches := 0
			for _, row := range rows {
				for _, witness := range row.Witnesses {
					if witness.Instruction == anchor.instruction {
						matches++
						if !bytes.Equal(witness.Encoding, anchor.code) {
							t.Fatalf("payload %x want=%x", witness.Encoding, anchor.code)
						}
					}
				}
			}
			if matches != 1 {
				t.Fatal("selected source must have one row owner", matches)
			}
		})
	}
}

func TestX86ScalarRMWRejectsChangedPhysicalAxes(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range catalog.Optab {
		if entry.Opcode != "ADDQ" {
			continue
		}
		for _, mutation := range []struct {
			name   string
			change func(*X86LegacyOpcode, *X86LegacyOperand)
		}{
			{"class", func(_ *X86LegacyOpcode, r *X86LegacyOperand) { r.Classes = []string{"Yu8", "Yml"} }},
			{"zcase", func(_ *X86LegacyOpcode, r *X86LegacyOperand) { r.ZCase = "Zm_r" }},
			{"stride", func(_ *X86LegacyOpcode, r *X86LegacyOperand) { r.ZOffset++ }},
			{"offset", func(_ *X86LegacyOpcode, r *X86LegacyOperand) { r.UnmatchedOffset++ }},
			{"index", func(_ *X86LegacyOpcode, r *X86LegacyOperand) { r.RowIndex = 1 }},
			{"prefix", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.Prefix = "Pe" }},
			{"escape", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.EscapeAdjustment = 1 }},
			{"truncated", func(e *X86LegacyOpcode, _ *X86LegacyOperand) { e.OpBytes = e.OpBytes[:1] }},
			{"extra", func(e *X86LegacyOpcode, _ *X86LegacyOperand) {
				e.OpBytes = append(append([]string(nil), e.OpBytes...), "0")
			}},
			{"symbol", func(e *X86LegacyOpcode, _ *X86LegacyOperand) {
				e.OpBytes = append([]string(nil), e.OpBytes...)
				e.OpBytes[0] = "opcode"
			}},
			{"extension", func(e *X86LegacyOpcode, _ *X86LegacyOperand) {
				e.OpBytes = append([]string(nil), e.OpBytes...)
				e.OpBytes[1] = "8"
			}},
		} {
			t.Run(mutation.name, func(t *testing.T) {
				row := entry.Rows[0]
				if witnesses, err := x86ScalarRMWRowWitnesses(entry, row, "amd64"); err != nil || len(witnesses) != 2 {
					t.Fatal("valid original failed before negative", err)
				}
				changed := entry
				mutation.change(&changed, &row)
				if _, err := x86ScalarRMWRowWitnesses(changed, row, "amd64"); err == nil {
					t.Fatal("changed physical axis admitted", fmt.Sprint(changed, row))
				}
			})
		}
		return
	}
	t.Fatal("actual Go omitted ADDQ")
}
