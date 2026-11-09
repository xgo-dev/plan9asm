package goasmrules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestX86ScalarCompareCompleteFamilyOriginalRowIDs(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	// Membership is independent of the operand table used by each SDK entry.
	// In particular, TESTB shares yxorb with a different numerical family.
	members := map[string]bool{}
	for _, name := range strings.Fields("CMPB CMPW CMPL CMPQ TESTB TESTW TESTL TESTQ") {
		members[name] = false
	}
	var expected []string
	for _, entry := range catalog.Optab {
		if _, selected := members[entry.Opcode]; !selected {
			continue
		}
		if members[entry.Opcode] {
			t.Fatal("duplicate original family member", entry.Opcode)
		}
		members[entry.Opcode] = true
		for _, row := range entry.Rows {
			expected = append(expected, fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex))
		}
	}
	for name, found := range members {
		if !found {
			t.Fatal("actual SDK lost a complete scalar compare/test member", name)
		}
	}
	if len(expected) != 35 {
		t.Fatal("complete original eight-member row set changed", len(expected))
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			rows, err := X86ScalarCompareRows(catalog, arch)
			if err != nil {
				t.Fatal(err)
			}
			// Retain the actual row payload for before/after identity checks.
			projection, err := json.Marshal(rows)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("projected_rows=%s", projection)
			var actual []string
			for _, row := range rows {
				actual = append(actual, row.ID)
			}
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("family-first original row join differs:\nactual=%v\nwant=%v", actual, expected)
			}
		})
	}
}

func TestX86ScalarCompareFamilyRowsCannotDisappear(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	selected := -1
	for index, entry := range catalog.Optab {
		if entry.Opcode == "TESTB" {
			selected = index
		}
	}
	if selected < 0 {
		t.Fatal("actual SDK is missing TESTB")
	}
	for _, axis := range []string{"table", "kind", "empty", "duplicate-member", "missing-member", "row-index", "classes", "zcase", "payload"} {
		t.Run(axis, func(t *testing.T) {
			changed := catalog
			changed.Optab = append([]X86LegacyOpcode(nil), catalog.Optab...)
			entry := &changed.Optab[selected]
			entry.Rows = append([]X86LegacyOperand(nil), entry.Rows...)
			switch axis {
			case "table":
				entry.Ytab = "unmodeled_test_table"
			case "kind":
				entry.Kind = "pseudo"
			case "empty":
				entry.Rows = nil
			case "duplicate-member":
				changed.Optab = append(changed.Optab, *entry)
			case "missing-member":
				changed.Optab = append(changed.Optab[:selected], changed.Optab[selected+1:]...)
			case "row-index":
				entry.Rows[0].RowIndex++
			case "classes":
				entry.Rows[0].Classes = []string{"unmodeled_test_operand"}
			case "zcase":
				entry.Rows[0].ZCase = "unmodeled_test_emission"
			case "payload":
				entry.OpBytes = []string{"unmodeled_test_byte"}
			}
			for _, arch := range []string{"amd64", "386"} {
				if rows, err := X86ScalarCompareRows(changed, arch); err == nil || len(rows) != 0 {
					t.Errorf("%s accepted or partially projected an unresolved original member: rows=%d err=%v", arch, len(rows), err)
				}
			}
		})
	}
}

func TestX86ScalarCompareRemainingExistingTransport(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, entry := range catalog.Optab {
		if !strings.Contains(" CMPB CMPW CMPL CMPQ TESTB TESTW TESTL TESTQ ", " "+entry.Opcode+" ") {
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
	if fmt.Sprint(counts) != "map[ycmpb:4 ycmpl:15 ytestl:12 yxorb:4]" {
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
		"TESTB $128,AL":    {0xa8, 0x80},
		"TESTB $128,BL":    {0xf6, 0xc3, 0x80},
		"TESTB $128,0(SI)": {0xf6, 0x06, 0x80},
		"TESTB CL,BL":      {0x84, 0xcb},
		"TESTB CL,0(SI)":   {0x84, 0x0e},
		"TESTB 0(SI),BL":   {0x84, 0x1e},
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
		wantFormats, wantFiltered := 54, 0
		if arch == "386" {
			wantFormats, wantFiltered = 40, 9
		}
		if len(seen) != 35 || formats != wantFormats || filtered != wantFiltered {
			t.Fatal("original compare source/mode union changed", arch, len(seen), formats, filtered)
		}
	}
}
