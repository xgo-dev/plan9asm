package goasmrules

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86ReadOnlyBitTestCompleteRowsAndBytes(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	anchors := map[string][]byte{
		"BTW $1,BX":    {0x66, 0x0f, 0xba, 0xe3, 1},
		"BTW $1,0(SI)": {0x66, 0x0f, 0xba, 0x26, 1},
		"BTW CX,BX":    {0x66, 0x0f, 0xa3, 0xcb},
		"BTW CX,0(SI)": {0x66, 0x0f, 0xa3, 0x0e},
		"BTL $1,BX":    {0x0f, 0xba, 0xe3, 1},
		"BTL $1,0(SI)": {0x0f, 0xba, 0x26, 1},
		"BTL CX,BX":    {0x0f, 0xa3, 0xcb},
		"BTL CX,0(SI)": {0x0f, 0xa3, 0x0e},
		"BTQ $1,BX":    {0x48, 0x0f, 0xba, 0xe3, 1},
		"BTQ $1,0(SI)": {0x48, 0x0f, 0xba, 0x26, 1},
		"BTQ CX,BX":    {0x48, 0x0f, 0xa3, 0xcb},
		"BTQ CX,0(SI)": {0x48, 0x0f, 0xa3, 0x0e},
	}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := X86GPDataFlagsCPURows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		seen, seenShapes := map[string]bool{}, map[string]bool{}
		shapes, refused := 0, 0
		for _, row := range rows {
			if row.Opcode != "BTW" && row.Opcode != "BTL" && row.Opcode != "BTQ" {
				continue
			}
			if seen[row.ID] {
				t.Fatal("duplicate original read-only bit-test row", row.ID)
			}
			seen[row.ID] = true
			if row.ModeFiltered != "" {
				if arch != "386" || row.Opcode != "BTQ" || len(row.Witnesses) != 0 {
					t.Fatal("original mode refusal acquired witnesses", row)
				}
				refused++
			} else if len(row.Witnesses) != 2 {
				t.Fatal("original row lost its register/memory pair", row)
			}
			for _, witness := range row.Witnesses {
				want, found := anchors[witness.Instruction]
				if !found || seenShapes[witness.Instruction] || !bytes.Equal(witness.Encoding, want) {
					t.Fatal("original row lost its independent byte anchor", row.ID, witness)
				}
				seenShapes[witness.Instruction] = true
				shapes++
			}
		}
		wantShapes, wantRefused := 12, 0
		if arch == "386" {
			wantShapes, wantRefused = 8, 2
		}
		if len(seen) != 6 || shapes != wantShapes || refused != wantRefused {
			t.Fatal("complete read-only bit-test family/mode join changed", arch, len(seen), shapes, refused)
		}
	}
}

func TestX86ReadOnlyBitTestUnknownSchemaReportsOriginalRow(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for index, original := range catalog.Optab {
		if original.Opcode != "BTW" && original.Opcode != "BTL" && original.Opcode != "BTQ" {
			continue
		}
		for _, axis := range []string{"table", "classes", "emission", "payload"} {
			t.Run(original.Opcode+"/"+axis, func(t *testing.T) {
				changed := catalog
				changed.Optab = append([]X86LegacyOpcode(nil), catalog.Optab...)
				entry := &changed.Optab[index]
				entry.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
				switch axis {
				case "table":
					entry.Ytab = "unmodeled_bit_test_table"
				case "classes":
					entry.Rows[0].Classes = []string{"unmodeled_bit_test_operand"}
				case "emission":
					entry.Rows[0].ZCase = "unmodeled_bit_test_emission"
				case "payload":
					entry.OpBytes = []string{"unmodeled_bit_test_byte"}
				}
				id := fmt.Sprintf("optab/%d/%s/%s/0", entry.TableIndex, entry.Opcode, entry.Ytab)
				for _, arch := range []string{"amd64", "386"} {
					rows, err := X86GPDataFlagsCPURows(changed, arch)
					if err == nil || len(rows) != 0 || !strings.Contains(err.Error(), id) {
						t.Errorf("%s unresolved source row silently disappeared: rows=%d err=%v, want %s", arch, len(rows), err, id)
					}
				}
			})
		}
	}
}
