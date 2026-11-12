package goasmrules

import (
	"bytes"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// These tests intentionally call the existing row transport entry points.
// Before the shared format is implemented, they must fail on its missing
// format, rather than require an undefined future helper to compile.
func TestX86UniformByteShiftImmediateOpcodeExtensionAnchors(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, anchor := range []struct {
		opcode, instruction string
		row                 int
		encoding            []byte
	}{
		{"VPSLLD", "VPSLLD $7,X0,X2", 0, []byte{0xc5, 0xe9, 0x72, 0xf0, 7}},
		{"VPSLLD", "VPSLLD $-1,X0,X2", 1, []byte{0xc5, 0xe9, 0x72, 0xf0, 255}},
		{"VPSLLD", "VPSLLD $7,X16,X18", 6, []byte{0x62, 0xb1, 0x6d, 0x00, 0x72, 0xf0, 7}},
		{"VPSLLD", "VPSLLD.BCST.Z $7,(AX),K1,Y18", 9, []byte{0x62, 0xf1, 0x6d, 0xb1, 0x72, 0x30, 7}},
		{"VPSRLQ", "VPSRLQ X16,Z17,K1,Z18", 17, []byte{0x62, 0xa1, 0xf5, 0x41, 0xd3, 0xd0}},
		{"VPSLLDQ", "VPSLLDQ $7,(AX),Z18", 6, []byte{0x62, 0xf1, 0x6d, 0x40, 0x73, 0x38, 7}},
	} {
		t.Run(anchor.instruction, func(t *testing.T) {
			found := 0
			for _, rule := range rules {
				if rule.Opcode != anchor.opcode || rule.RowIndex != anchor.row {
					continue
				}
				witnesses, err := x86PackedAVXRowWitnesses(rule)
				if err != nil {
					t.Fatal("official shift format is not transported", err)
				}
				for _, witness := range witnesses {
					if witness.Instruction != anchor.instruction {
						continue
					}
					found++
					if !bytes.Equal(witness.Encoding, anchor.encoding) {
						t.Fatalf("opcode extension/vvvv transport: got %x, want %x", witness.Encoding, anchor.encoding)
					}
					if strings.HasPrefix(strings.Fields(witness.Instruction)[1], "$") &&
						(strings.HasPrefix(witness.First, "$") || witness.Second != "") {
						t.Fatal("immediate became a loaded register or fictitious second input", witness)
					}
				}
			}
			if found != 1 {
				t.Fatal("missing or repeated independent official row witness", found)
			}
		})
	}
}

func TestX86UniformByteShiftCompleteOfficialAVXTransport(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	names, widths := map[string]bool{}, map[int]int{}
	rows, formats := map[string]int{}, map[string]int{}
	single, broadcast := 0, 0
	for _, rule := range rules {
		if rule.Ytab != "_yvpslld" && rule.Ytab != "_yvpsraq" && rule.Ytab != "_yvpslldq" {
			continue
		}
		names[rule.Opcode] = true
		t.Run(fmt.Sprintf("%s/%s/%d", rule.Opcode, rule.Ytab, rule.RowIndex), func(t *testing.T) {
			witnesses, err := x86PackedAVXRowWitnesses(rule)
			if err != nil || len(witnesses) == 0 {
				t.Fatal("complete official row has no concrete transport", err)
			}
			generation := witnesses[0].Generation
			rows[generation]++
			if len(witnesses) == 1 {
				single++
			}
			for _, witness := range witnesses {
				formats[generation]++
				widths[witness.Width]++
				if witness.Broadcast {
					broadcast++
				}
				// Uniform register counts are always X/m128, even when
				// their independent data and destination carriers are Y/Z.
				immediate := rule.Classes[0] == "Yi8" || rule.Classes[0] == "Yu8"
				if !immediate && witness.First != "(AX)" &&
					(witness.First != "X0" && witness.First != "X16") {
					t.Fatal("uniform count inherited its data carrier width", witness)
				}
			}
		})
	}
	if len(names) != 11 || !reflect.DeepEqual(rows, map[string]int{"vex": 56, "evex": 114}) ||
		!reflect.DeepEqual(formats, map[string]int{"vex": 72, "evex": 390}) ||
		!reflect.DeepEqual(widths, map[int]int{128: 166, 256: 166, 512: 130}) || single != 40 || broadcast != 54 {
		t.Fatal("complete official AVX denominator drift", len(names), rows, formats, widths, single, broadcast)
	}
}

func TestX86UniformByteShiftCompleteOfficialLegacyTransport(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	rows, formats, single, mmx := 0, 0, 0, 0
	for _, entry := range catalog.Optab {
		if entry.Ytab != "yps" && entry.Ytab != "ypsdq" {
			continue
		}
		names[entry.Opcode] = true
		for _, row := range entry.Rows {
			if strings.Join(row.Classes, ",") == "Ymm,Ymr" || strings.Join(row.Classes, ",") == "Yi8,Ymr" {
				mmx++ // Separate physical region/EMMS/mode owner; not passed here.
				continue
			}
			t.Run(fmt.Sprintf("%s/%s/%d", entry.Opcode, entry.Ytab, row.RowIndex), func(t *testing.T) {
				witnesses, err := x86PackedLegacyRowWitnesses(entry, row)
				if err != nil || len(witnesses) == 0 {
					t.Fatal("complete original XMM row has no concrete transport", err)
				}
				rows++
				formats += len(witnesses)
				if len(witnesses) == 1 {
					single++
				}
				for _, witness := range witnesses {
					if witness.Generation != "legacy" || witness.Width != 128 || witness.Second != witness.Destination {
						t.Fatal("legacy count/data/RMW identity changed", witness)
					}
				}
			})
		}
	}
	if len(names) != 10 || rows != 18 || formats != 26 || single != 10 || mmx != 16 {
		t.Fatal("complete XMM rows or separate MMX denominator drift", len(names), rows, formats, single, mmx)
	}
}

func TestX86UniformByteShiftLegacyImmediateExtensionAnchors(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, anchor := range []struct {
		opcode string
		row    int
		bytes  []byte
	}{
		{"PSLLL", 3, []byte{0x66, 0x0f, 0x72, 0xf1, 255}},
		{"PSLLO", 0, []byte{0x66, 0x0f, 0x73, 0xf9, 255}},
	} {
		t.Run(anchor.opcode, func(t *testing.T) {
			found := 0
			for _, entry := range catalog.Optab {
				if entry.Opcode != anchor.opcode {
					continue
				}
				for _, row := range entry.Rows {
					if row.RowIndex != anchor.row {
						continue
					}
					witnesses, err := x86PackedLegacyRowWitnesses(entry, row)
					if err != nil || len(witnesses) != 1 {
						t.Fatal("legacy immediate has no exact one-row transport", err)
					}
					found++
					if !bytes.Equal(witnesses[0].Encoding, anchor.bytes) || witnesses[0].First != "" || witnesses[0].Second != "X1" {
						t.Fatal("legacy immediate acquired a fictitious first read or wrong /digit", witnesses)
					}
				}
			}
			if found != 1 {
				t.Fatal("missing or repeated original legacy immediate row", found)
			}
		})
	}
}
