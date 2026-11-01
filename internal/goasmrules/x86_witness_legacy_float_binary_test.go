package goasmrules

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86LegacyFloatingBinaryCompleteExistingTransport(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	names := `ADDPD ADDPS ADDSD ADDSS DIVPD DIVPS DIVSD DIVSS
        MAXPD MAXPS MAXSD MAXSS MINPD MINPS MINSD MINSS
        MULPD MULPS MULSD MULSS SUBPD SUBPS SUBSD SUBSS`
	selected := map[string]bool{}
	for _, name := range strings.Fields(names) {
		selected[name] = true
	}
	originals := map[string]bool{}
	for _, entry := range catalog.Optab {
		if !selected[entry.Opcode] {
			continue
		}
		if entry.Ytab != "yxm" || len(entry.Rows) != 1 || len(entry.OpBytes) != 1 {
			t.Fatal("original complete media schema changed", entry)
		}
		row := entry.Rows[0]
		if row.RowIndex != 0 || row.ZCase != "Zm_r_xm" || row.ZOffset != 1 ||
			row.UnmatchedOffset != 0 || strings.Join(row.Classes, ",") != "Yxm,Yxr" {
			t.Fatal("original operand classes/offsets changed", entry)
		}
		originals[fmt.Sprintf("optab/%d/%s/yxm/0", entry.TableIndex, entry.Opcode)] = true
	}
	if len(originals) != 24 {
		t.Fatal("lost complete source family", len(originals))
	}
	// Existing helper only: no future selector symbol is needed to compile RED.
	rows, err := x86PackedBinaryRows(catalog, nil, names)
	if err != nil {
		t.Fatal("complete legacy FP source-prefix transport", err)
	}
	seen, shapes := map[string]bool{}, 0
	for _, row := range rows {
		if !originals[row.ID] || seen[row.ID] || len(row.Witnesses) != 2 {
			t.Fatal("source row lost/duplicated", row)
		}
		seen[row.ID] = true
		for _, w := range row.Witnesses {
			if w.Generation != "legacy" || w.Width != 128 || w.Second != "X1" ||
				w.Destination != "X1" || w.Masked || w.Zeroing || w.Broadcast || w.MaskResult {
				t.Fatal("legacy RMW roles/controls changed", w)
			}
			shapes++
		}
	}
	if len(seen) != 24 || shapes != 48 {
		t.Fatal("source projection changed", len(seen), shapes)
	}
}

func TestX86LegacyFloatingBinaryMediaPrefixControls(t *testing.T) {
	catalog, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	var scalar X86LegacyOpcode
	checked := 0
	for _, entry := range catalog.Optab {
		if !x86LegacyFloatingBinaryMember(entry.Opcode) {
			continue
		}
		if _, err := x86PackedLegacyRowWitnesses(entry, entry.Rows[0]); err != nil {
			t.Fatal("valid original media source required", err)
		}
		if entry.Opcode == "ADDSD" {
			scalar = entry
		}
		t.Run(entry.Opcode+"/foreign-prefix", func(t *testing.T) {
			changed := entry
			changed.Prefix = "Pf3"
			if strings.HasSuffix(entry.Opcode, "SS") {
				changed.Prefix = "Pf2"
			}
			if _, err := x86PackedLegacyRowWitnesses(changed, entry.Rows[0]); err == nil {
				t.Fatal("media mandatory prefix borrowed from another source class", changed)
			}
		})
		checked++
	}
	if checked != 24 || scalar.Opcode != "ADDSD" {
		t.Fatal("missing complete media controls", checked)
	}
	for _, control := range []string{"ytab", "row-index", "classes", "zcase", "zoffset", "offset", "escape", "extent", "symbolic-byte"} {
		t.Run(control, func(t *testing.T) {
			entry, row := scalar, scalar.Rows[0]
			switch control {
			case "ytab":
				entry.Ytab = "ymm"
			case "row-index":
				row.RowIndex++
			case "classes":
				row.Classes = []string{"Ymm", "Yxr"}
			case "zcase":
				row.ZCase = "Zm_r"
			case "zoffset":
				row.ZOffset++
			case "offset":
				row.UnmatchedOffset++
			case "escape":
				entry.EscapeAdjustment++
			case "extent":
				entry.OpBytes = append(append([]string(nil), entry.OpBytes...), "0")
			case "symbolic-byte":
				entry.OpBytes = []string{"Pm"}
			}
			if _, err := x86PackedLegacyRowWitnesses(entry, row); err == nil {
				t.Fatal("foreign complete media axes accepted", control)
			}
		})
	}
	for _, opcode := range []string{"ANDPD", "PABSD"} {
		for _, prefix := range []string{"Pf2", "Pf3", "Ym"} {
			t.Run(opcode+"/"+prefix, func(t *testing.T) {
				entry := scalar
				entry.Opcode, entry.Prefix = opcode, prefix
				if x86LegacyFloatingBinaryMember(opcode) {
					t.Fatal("suffix admitted an unrelated semantic family", opcode)
				}
				if _, err := x86PackedLegacyRowWitnesses(entry, entry.Rows[0]); err == nil {
					t.Fatal("floating media prefix widened the old binary/ABS grammar", opcode, prefix)
				}
			})
		}
	}
}
