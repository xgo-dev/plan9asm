package goasmrules

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Existing-helper TDD draft: source tables select the complete remaining
// format group. This is not a new handwritten instruction/value registry.
func TestX86ScalarRMRegisterRemainingOriginalRows(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, names := 0, map[string]bool{}
	for _, entry := range catalog.Optab {
		if entry.Ytab != "yml_rl" || strings.HasPrefix(entry.Opcode, "CMOV") {
			continue
		}
		if names[entry.Opcode] {
			t.Fatal("duplicate original source member", entry.Opcode)
		}
		names[entry.Opcode] = true
		for _, operand := range entry.Rows {
			rows++
			t.Run(fmt.Sprint(entry.TableIndex)+"/"+entry.Opcode, func(t *testing.T) {
				if entry.Kind != "encoding" || len(entry.Rows) != 1 || operand.RowIndex != 0 ||
					operand.ZCase != "Zm_r" || operand.ZOffset != 1 || strings.Join(operand.Classes, ",") != "Yml,Yrl" {
					t.Fatal("original complete GP source table changed", entry, operand)
				}
				witnesses, err := x86ScalarRMWRowWitnesses(entry, operand, "amd64")
				if err != nil || len(witnesses) != 2 {
					t.Fatal("complete original rm-to-register row lacks register/memory witnesses", err, len(witnesses))
				}
				for index, witness := range witnesses {
					want := entry.Opcode + " CX,BX"
					if index == 1 {
						want = entry.Opcode + " 0(SI),BX"
					}
					if witness.Instruction != want || witness.Destination != "BX" || len(witness.Encoding) < 2 {
						t.Fatal("physical alternative, destination or order changed", witness, want)
					}
				}
			})
		}
	}
	if rows != 28 || len(names) != 28 {
		t.Fatal("complete remaining source-format denominator changed", rows, len(names))
	}
}

func TestX86ScalarRMRegisterPrefixTransportAndControls(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	witnesses := map[string][]byte{}
	for _, entry := range catalog.Optab {
		if entry.Ytab != "yml_rl" || strings.HasPrefix(entry.Opcode, "CMOV") {
			continue
		}
		w, err := x86ScalarRMWRowWitnesses(entry, entry.Rows[0], "amd64")
		if err != nil || len(w) != 2 {
			t.Fatal("valid original must precede prefix controls", entry.Opcode, err)
		}
		for _, witness := range w {
			witnesses[witness.Instruction] = witness.Encoding
		}
		t.Run(entry.Opcode+"/wrong-prefix", func(t *testing.T) {
			changed := entry
			changed.Prefix = "Px"
			if entry.Prefix == "Px" {
				changed.Prefix = "Pw"
			}
			if _, err := x86ScalarRMWRowWitnesses(changed, entry.Rows[0], "amd64"); err == nil {
				t.Fatal("another legal prefix class changed the original family/width envelope")
			}
		})
	}
	for _, anchor := range []struct {
		instruction string
		code        []byte
	}{
		{"ADCXL CX,BX", []byte{0x66, 0x0f, 0x38, 0xf6, 0xd9}},
		{"ADCXQ 0(SI),BX", []byte{0x66, 0x48, 0x0f, 0x38, 0xf6, 0x1e}},
		{"ADOXL CX,BX", []byte{0xf3, 0x0f, 0x38, 0xf6, 0xd9}},
		{"ADOXQ 0(SI),BX", []byte{0xf3, 0x48, 0x0f, 0x38, 0xf6, 0x1e}},
		{"LZCNTW CX,BX", []byte{0x66, 0xf3, 0x0f, 0xbd, 0xd9}},
		{"LZCNTL 0(SI),BX", []byte{0xf3, 0x0f, 0xbd, 0x1e}},
		{"POPCNTQ CX,BX", []byte{0xf3, 0x48, 0x0f, 0xb8, 0xd9}},
		{"MOVWLSX 0(SI),BX", []byte{0x0f, 0xbf, 0x1e}},
		{"MOVLQSX CX,BX", []byte{0x48, 0x63, 0xd9}},
		{"MOVLQZX 0(SI),BX", []byte{0x8b, 0x1e}},
		{"LARQ CX,BX", []byte{0x48, 0x0f, 0x02, 0xd9}},
	} {
		if !bytes.Equal(witnesses[anchor.instruction], anchor.code) {
			t.Fatal("original prefix/payload/ModRM anchor changed", anchor.instruction, witnesses[anchor.instruction], anchor.code)
		}
	}
}

func TestX86ScalarRMRegisterSourceModesAndClosure(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := X86ScalarRMRegisterRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		filtered, witnesses := 0, 0
		ids := map[string]bool{}
		for _, row := range rows {
			if ids[row.ID] || row.ID == "" {
				t.Fatal("original row identity is missing or repeated", row)
			}
			ids[row.ID] = true
			if row.ModeFiltered != "" {
				filtered++
				if len(row.Witnesses) != 0 {
					t.Fatal("refused source acquired a selected encoding", row)
				}
			} else {
				if len(row.Witnesses) != 2 {
					t.Fatal("register/memory alternative disappeared", row)
				}
				witnesses += len(row.Witnesses)
			}
		}
		wantFiltered, wantWitnesses := 0, 56
		if arch == "386" {
			wantFiltered, wantWitnesses = 11, 34
		}
		if len(rows) != 28 || filtered != wantFiltered || witnesses != wantWitnesses {
			t.Fatal("actual source/mode denominator changed", arch, len(rows), filtered, witnesses)
		}
	}
	if _, err := X86ScalarRMRegisterRows(catalog, "arm64"); err == nil {
		t.Fatal("foreign source mode acquired x86 rows")
	}
	if _, err := X86ScalarRMRegisterRows(X86LegacyCatalog{}, "amd64"); err == nil {
		t.Fatal("empty source inventory acquired a complete closure")
	}
}
