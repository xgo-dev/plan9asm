package goasmrules

import (
	"bytes"
	"fmt"
	"runtime"
	"testing"
)

func TestX86ScalarCompareRemainingExistingTransport(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, entry := range catalog.Optab {
		if entry.Ytab != "ycmpl" && entry.Ytab != "ycmpb" && entry.Ytab != "ytestl" {
			continue
		}
		for _, row := range entry.Rows {
			counts[entry.Ytab]++
			t.Run(fmt.Sprintf("%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex), func(t *testing.T) {
				witnesses, err := x86ScalarRMWRowWitnesses(entry, row, "amd64")
				if err != nil || len(witnesses) == 0 {
					t.Fatal("complete original read-only scalar row has no witness transport", err)
				}
			})
		}
	}
	if fmt.Sprint(counts) != "map[ycmpb:4 ycmpl:15 ytestl:12]" {
		t.Fatal("complete original compare/test denominator changed", counts)
	}
}

func TestX86ScalarCompareOrderedOperandsModesAndPayload(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	anchors := map[string][]byte{
		"CMPB AL,$128":     {0x3c, 0x80},
		"CMPB BL,$128":     {0x80, 0xfb, 0x80},
		"CMPL BX,$1":       {0x83, 0xfb, 1},
		"CMPL AX,$128":     {0x3d, 0x80, 0, 0, 0},
		"CMPL 0(SI),BX":    {0x39, 0x1e},
		"CMPL CX,0(SI)":    {0x3b, 0x0e},
		"TESTL $128,AX":    {0xa9, 0x80, 0, 0, 0},
		"TESTW $128,0(SI)": {0x66, 0xf7, 0x06, 0x80, 0},
	}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := X86ScalarCompareRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		seen, formats, filtered := map[string]bool{}, 0, 0
		for _, row := range rows {
			if row.ID == "" || seen[row.ID] {
				t.Fatal("original compare row identity missing/repeated", row)
			}
			seen[row.ID] = true
			if row.ModeFiltered != "" {
				filtered++
				if len(row.Witnesses) != 0 {
					t.Fatal("refused source mode acquired witnesses", row)
				}
			}
			formats += len(row.Witnesses)
			for _, witness := range row.Witnesses {
				if expected, ok := anchors[witness.Instruction]; ok && !bytes.Equal(expected, witness.Encoding) {
					t.Fatal("accumulator, immediate direction or ModRM source order changed", witness, expected)
				}
			}
		}
		wantFormats, wantFiltered := 48, 0
		if arch == "386" {
			wantFormats, wantFiltered = 34, 9
		}
		if len(seen) != 31 || formats != wantFormats || filtered != wantFiltered {
			t.Fatal("original compare source/mode union changed", arch, len(seen), formats, filtered)
		}
	}
}
