package goasmrules

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86ScalarShiftCompleteOriginalRecords(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	originals := map[string]string{}
	for _, entry := range catalog.Optab {
		if entry.Ytab != "yshb" && entry.Ytab != "yshl" {
			continue
		}
		for _, row := range entry.Rows {
			originals[fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex)] = entry.Opcode
		}
	}
	for _, row := range catalog.Movtab {
		if row.Code == "movDoubleShift" {
			originals[fmt.Sprintf("ymovtab/%d/%s/movDoubleShift", row.TableIndex, row.Opcode)] = row.Opcode
		}
	}
	for _, mode := range []struct {
		arch             string
		filtered, shapes int
	}{{"amd64", 0, 356}, {"386", 38, 264}} {
		rows, err := X86ScalarShiftRotateRows(catalog, mode.arch)
		if err != nil {
			t.Fatal(err)
		}
		seen, names, syntax := map[string]bool{}, map[string]bool{}, map[string]bool{}
		filtered, shapes := 0, 0
		for _, row := range rows {
			if originals[row.ID] != row.Opcode || seen[row.ID] {
				t.Fatal("lost original shift source record", row)
			}
			seen[row.ID], names[row.Opcode] = true, true
			if row.ModeFiltered != "" {
				if mode.arch != "386" || !strings.HasSuffix(row.Opcode, "Q") || len(row.Witnesses) != 0 {
					t.Fatal("wrong mode filter", row)
				}
				filtered++
				continue
			}
			for _, w := range row.Witnesses {
				if syntax[w.Instruction] || !strings.HasPrefix(w.Instruction, row.Opcode+" ") || len(w.Encoding) < 2 {
					t.Fatal("duplicate or lost selected syntax", row, w)
				}
				syntax[w.Instruction] = true
				shapes++
				args := strings.Split(strings.Fields(w.Instruction)[1], ",")
				destination := "BX"
				if strings.HasSuffix(row.Opcode, "B") {
					destination = "BL"
				}
				if args[len(args)-1] != w.Destination || w.Destination != destination && w.Destination != "0(SI)" {
					t.Fatal("data/count/destination roles changed", w)
				}
				if strings.HasPrefix(row.ID, "ymovtab/") && (len(args) != 3 || args[1] != "AX") || strings.HasPrefix(row.ID, "optab/") && len(args) != 2 {
					t.Fatal("Group2 and double-shift roles conflated", row, w)
				}
			}
		}
		if len(rows) != 138 || len(originals) != 138 || len(seen) != 138 || len(names) != 32 || filtered != mode.filtered || shapes != mode.shapes {
			t.Fatal("source/mode/projection changed", mode.arch, len(rows), len(seen), len(names), filtered, shapes)
		}
	}
}

func TestX86ScalarShiftRejectsForeignPhysicalAxes(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var original X86LegacyOpcode
	for _, entry := range catalog.Optab {
		if entry.Ytab == "yshl" {
			original = entry
			break
		}
	}
	if _, err := x86ScalarGroup2Witnesses(original, original.Rows[1]); err != nil {
		t.Fatal("valid Group2 required", err)
	}
	if _, err := x86ScalarRMWRowWitnesses(original, original.Rows[1], "amd64"); err == nil {
		t.Fatal("Group2 must not weaken the separate six-table GP grammar")
	}
	for _, mutation := range []string{"prefix", "signed count", "zoffset", "offset", "digit8", "digit mismatch", "payload", "row index", "destination", "empty opcode"} {
		t.Run("Group2/"+mutation, func(t *testing.T) {
			entry := original
			entry.OpBytes = append([]string(nil), original.OpBytes...)
			entry.Rows = append([]X86LegacyOperand(nil), original.Rows...)
			for i := range entry.Rows {
				entry.Rows[i].Classes = append([]string(nil), entry.Rows[i].Classes...)
			}
			row := entry.Rows[1]
			switch mutation {
			case "prefix":
				entry.Prefix = "Pf3"
			case "signed count":
				entry.Rows[1].Classes[0] = "Yi8"
				row = entry.Rows[1]
			case "zoffset":
				row.ZOffset++
			case "offset":
				row.UnmatchedOffset++
			case "digit8":
				entry.OpBytes[3] = "8"
			case "digit mismatch":
				entry.OpBytes[3] = "0"
			case "payload":
				entry.OpBytes = entry.OpBytes[:len(entry.OpBytes)-1]
			case "row index":
				row.RowIndex = 20
			case "destination":
				entry.Rows[1].Classes[1] = "Yxr"
				row = entry.Rows[1]
			case "empty opcode":
				entry.Opcode = ""
			}
			if _, err := x86ScalarGroup2Witnesses(entry, row); err == nil {
				t.Fatal("foreign Group2 format accepted", mutation)
			}
		})
	}
	var move X86MoveRule
	for _, row := range catalog.Movtab {
		if row.Code == "movDoubleShift" {
			move = row
			break
		}
	}
	if _, err := x86ScalarDoubleShiftWitnesses(move); err != nil {
		t.Fatal("valid double-shift required", err)
	}
	for _, mutation := range []string{"count", "data", "destination", "padding", "payload", "opcode", "code"} {
		t.Run("double/"+mutation, func(t *testing.T) {
			row := move
			row.OpBytes = append([]string(nil), move.OpBytes...)
			switch mutation {
			case "count":
				row.From = "Yu8"
			case "data":
				row.From3 = "Yxr"
			case "destination":
				row.To = "Ymb"
			case "padding":
				row.OpBytes[3] = "1"
			case "payload":
				row.OpBytes = row.OpBytes[:3]
			case "opcode":
				row.Opcode = "RCLL"
			case "code":
				row.Code = "movLit"
			}
			if _, err := x86ScalarDoubleShiftWitnesses(row); err == nil {
				t.Fatal("foreign double-shift accepted", mutation)
			}
		})
	}
}
