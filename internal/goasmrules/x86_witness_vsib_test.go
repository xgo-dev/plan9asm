package goasmrules

import (
	"runtime"
	"strings"
	"testing"
)

func TestX86VSIBCompleteOfficialRows(t *testing.T) {
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := X86IndexedMemoryRows(X86LegacyCatalog{}, avx)
	if err != nil || len(rows) != 80 {
		t.Fatal("complete gather/scatter/prefetch source family", len(rows), err)
	}
	names := make(map[string]bool)
	for _, row := range rows {
		names[row.Opcode] = true
		t.Run(row.ID, func(t *testing.T) {
			if len(row.Witnesses) != 4 {
				t.Fatal("all four legal VSIB scales must retain each source row", row)
			}
			for _, w := range row.Witnesses {
				if len(w.Encoding) == 0 || w.Second == "" || !w.Memory ||
					!strings.Contains(w.Instruction, "(AX)("+w.Second+"*") {
					t.Fatal("VSIB index disappeared into an ordinary contiguous memory form", w)
				}
			}
		})
	}
	if len(names) != 32 {
		t.Fatal("complete VSIB namespace changed", len(names))
	}
}

func TestX86VSIBSourceControls(t *testing.T) {
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range avx {
		if !x86VSIBTable(original.Ytab) {
			continue
		}
		if _, err := x86VSIBFormatForRule(original); err != nil {
			t.Fatal("valid original must precede negative metadata", original, err)
		}
		for _, axis := range []string{"index", "prefix", "row", "payload", "mask", "mask-encoding"} {
			changed := original
			changed.Classes = append([]string(nil), original.Classes...)
			changed.OpBytes = append([]string(nil), original.OpBytes...)
			switch axis {
			case "index":
				for index, class := range changed.Classes {
					if strings.Contains(class, "vm") {
						changed.Classes[index] = "Yml"
					}
				}
			case "prefix":
				changed.Prefix = "Pm"
			case "row":
				changed.RowIndex += 100
			case "payload":
				changed.OpBytes[changed.EncodingOffset] += "|evexInventedPermission"
			case "mask":
				for index, class := range changed.Classes {
					if class == "Yknot0" {
						changed.Classes[index] = "Yk0"
					}
				}
				if changed.ZCase == "Zvex_v_rm_r" {
					changed.Classes[0] = "Yknot0"
				}
			case "mask-encoding":
				if changed.ZCase != "Zvex_v_rm_r" {
					continue
				}
				changed.Classes[0] += "Evex"
			}
			if _, err := x86VSIBFormatForRule(changed); err == nil {
				t.Fatal("corrupted original metadata granted a VSIB format", axis, original, changed)
			}
		}
	}
}
