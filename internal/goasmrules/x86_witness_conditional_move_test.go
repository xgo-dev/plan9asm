package goasmrules

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func TestX86ConditionalMoveCompleteOfficialRowsAndModes(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, names := 0, map[string]bool{}
	for _, entry := range catalog.Optab {
		if !strings.HasPrefix(entry.Opcode, "CMOV") {
			continue
		}
		names[entry.Opcode] = true
		for _, operand := range entry.Rows {
			rows++
			t.Run(entry.Opcode, func(t *testing.T) {
				witnesses, err := x86ScalarRMWRowWitnesses(entry, operand, "amd64")
				if err != nil || len(witnesses) != 2 {
					t.Fatal("complete original CMOV Yml-to-Yrl row lacks register/memory witnesses", err, len(witnesses))
				}
			})
		}
	}
	if rows != 48 || len(names) != 48 {
		t.Fatal("complete independent conditional-move source closure changed", rows, len(names))
	}
	for _, arch := range []string{"amd64", "386"} {
		rows, err := X86ConditionalMoveRows(catalog, arch)
		if err != nil {
			t.Fatal(err)
		}
		filtered, witnesses := 0, 0
		ids := map[string]bool{}
		for _, row := range rows {
			if row.ID == "" || ids[row.ID] || !names[row.Opcode] {
				t.Fatal("conditional move lost its unique original source identity", row)
			}
			ids[row.ID] = true
			if row.ModeFiltered != "" {
				if arch != "386" || row.Opcode[4] != 'Q' || len(row.Witnesses) != 0 {
					t.Fatal("mode filtering invented or removed a physical witness", row)
				}
				filtered++
			} else {
				if len(row.Witnesses) != 2 {
					t.Fatal("conditional register/memory source alternative disappeared", row)
				}
				witnesses += len(row.Witnesses)
			}
		}
		wantFiltered, wantWitnesses := 0, 96
		if arch == "386" {
			wantFiltered, wantWitnesses = 16, 64
		}
		if len(rows) != 48 || filtered != wantFiltered || witnesses != wantWitnesses {
			t.Fatal("source/mode denominator changed", arch, len(rows), filtered, witnesses)
		}
	}
}

func TestX86ConditionalMoveOrderedPayloadAnchorsAndControls(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := X86ConditionalMoveRows(catalog, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	for _, anchor := range []struct {
		instruction string
		code        []byte
	}{
		{"CMOVWCC CX,BX", []byte{0x66, 0x0f, 0x43, 0xd9}},
		{"CMOVLCC 0(SI),BX", []byte{0x0f, 0x43, 0x1e}},
		{"CMOVQCC CX,BX", []byte{0x48, 0x0f, 0x43, 0xd9}},
	} {
		found := 0
		for _, row := range rows {
			for _, witness := range row.Witnesses {
				if witness.Instruction == anchor.instruction {
					found++
					if !bytes.Equal(witness.Encoding, anchor.code) {
						t.Fatal("original complete prefix/opcode/ModRM changed", anchor.instruction, witness.Encoding, anchor.code)
					}
				}
			}
		}
		if found != 1 {
			t.Fatal("missing or repeated independent payload anchor", anchor.instruction, found)
		}
	}
	if _, err := X86ConditionalMoveRows(catalog, "arm64"); err == nil {
		t.Fatal("foreign mode acquired x86 source rows")
	}
	if _, err := X86ConditionalMoveRows(X86LegacyCatalog{}, "amd64"); err == nil {
		t.Fatal("empty source closure accepted")
	}
	for index, entry := range catalog.Optab {
		if entry.Opcode != "CMOVLCC" {
			continue
		}
		for _, change := range []string{"missing", "duplicate", "prefix", "classes", "zcase", "zoffset", "rowindex", "offset", "extent", "foreign-table"} {
			t.Run(change, func(t *testing.T) {
				copy := catalog
				copy.Optab = append([]X86LegacyOpcode(nil), catalog.Optab...)
				modified := entry
				modified.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
				modified.OpBytes = append([]string(nil), entry.OpBytes...)
				switch change {
				case "missing":
					copy.Optab = append(copy.Optab[:index], copy.Optab[index+1:]...)
				case "duplicate":
					copy.Optab = append(copy.Optab, entry)
				case "prefix":
					modified.Prefix = "Px"
				case "classes":
					modified.Rows[0].Classes = []string{"Yxm", "Yxr"}
				case "zcase":
					modified.Rows[0].ZCase = "Zr_m"
				case "zoffset":
					modified.Rows[0].ZOffset++
				case "rowindex":
					modified.Rows[0].RowIndex++
				case "offset":
					modified.Rows[0].UnmatchedOffset++
				case "extent":
					modified.OpBytes = append(modified.OpBytes, "0")
				case "foreign-table":
					modified.Ytab = "yaddl"
				}
				if change != "missing" && change != "duplicate" {
					copy.Optab[index] = modified
				}
				if _, err := X86ConditionalMoveRows(copy, "amd64"); err == nil {
					t.Fatal("changed complete source attributes were accepted", change)
				}
			})
		}
		break
	}
}
