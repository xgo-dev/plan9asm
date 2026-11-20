package goasmrules

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86MoveRemainderCompleteOriginalSourceRows(t *testing.T) {
	legacy, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	const members = `VLDDQU VMASKMOVDQU VMASKMOVPD VMASKMOVPS VMOVD VMOVHLPS
VMOVHPD VMOVHPS VMOVLHPS VMOVLPD VMOVLPS VMOVMSKPD VMOVMSKPS
VMOVNTDQ VMOVNTDQA VMOVNTPD VMOVNTPS VMOVQ VMOVSD VMOVSS
VPMASKMOVD VPMASKMOVQ VPMOVMSKB`
	wanted := map[string]bool{}
	for _, name := range strings.Fields(members) {
		wanted[name] = true
	}
	originals := map[string]X86AVXRule{}
	tables := map[string]int{}
	for index, rule := range avx {
		if !wanted[rule.Opcode] {
			continue
		}
		id := fmt.Sprintf("avx/%d/%s/%s/%d", index, rule.Opcode, rule.Ytab, rule.RowIndex)
		if _, duplicate := originals[id]; duplicate {
			t.Fatal("duplicate source row", id)
		}
		originals[id] = rule
		tables[rule.Ytab]++
	}
	counts := map[string]int{"_yvlddqu": 2, "_yvmaskmovdqu": 1, "_yvmaskmovpd": 16,
		"_yvmovd": 4, "_yvmovhlps": 4, "_yvmovhpd": 16, "_yvmovmskpd": 6,
		"_yvmovntdq": 15, "_yvmovntdqa": 5, "_yvmovq": 8, "_yvmovsd": 24}
	if len(wanted) != 23 || len(originals) != 101 || len(tables) != len(counts) {
		t.Fatal("complete AVX move source closure changed", len(wanted), len(originals), tables)
	}
	for table, count := range counts {
		if tables[table] != count {
			t.Fatal("original ytab group changed", table, tables[table], count)
		}
	}
	// Use the existing row helper. No future factory, selector or encoding
	// symbol is needed to establish the real format boundary on all101 rows.
	for index, rule := range avx {
		if !wanted[rule.Opcode] {
			continue
		}
		id := fmt.Sprintf("avx/%d/%s/%s/%d", index, rule.Opcode, rule.Ytab, rule.RowIndex)
		t.Run(id, func(t *testing.T) {
			if _, err := x86PackedAVXRowWitnesses(rule); err != nil {
				t.Fatal("original move row format", err)
			}
		})
	}
	if t.Failed() {
		return
	}
	rows, err := x86PackedBinaryRows(legacy, avx, members)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, row := range rows {
		original, exists := originals[row.ID]
		if !exists || seen[row.ID] || row.Opcode != original.Opcode {
			t.Fatal("source row dropped, aliased or duplicated", row.ID)
		}
		seen[row.ID] = true
	}
	if len(seen) != 101 {
		t.Fatal("source closure lost a row", len(seen))
	}
	// This is source-row retention only. In particular, no assertion here
	// calls a shadowed register alternative a hit of its later source row.
}

func TestX86MoveRemainderOriginalFormatAxesRemainBound(t *testing.T) {
	type mutation struct {
		name string
		edit func(*X86AVXRule)
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	count, evex := 0, 0
	for _, original := range avx {
		if !x86MoveRemainderTable(original.Ytab) {
			continue
		}
		witnesses, err := x86PackedAVXRowWitnesses(original)
		if err != nil {
			t.Fatal(original.Opcode, original.RowIndex, err)
		}
		for _, w := range witnesses {
			if w.Zeroing && !w.Masked || w.Broadcast || w.MaskResult ||
				w.Memory != (w.First == "(AX)") ||
				original.Ytab == "_yvmovsd" && w.Destination == "(AX)" && w.Zeroing ||
				original.Ytab == "_yvmaskmovpd" && w.Masked {
				t.Fatal("source-only memory, scalar-store or vector-mask role was broadened", original, w)
			}
		}
		mutations := []mutation{
			{"prefix", func(r *X86AVXRule) { r.Prefix = "Pe" }},
			{"classes", func(r *X86AVXRule) { r.Classes = append(r.Classes, "Yknot0") }},
			{"row", func(r *X86AVXRule) { r.RowIndex += 100 }},
			{"offset", func(r *X86AVXRule) { r.EncodingOffset++ }},
			{"stride", func(r *X86AVXRule) { r.ZOffset++ }},
			{"extent", func(r *X86AVXRule) { r.OpBytes = append(r.OpBytes, "0") }},
			{"mandatory-prefix", func(r *X86AVXRule) {
				p := &r.OpBytes[r.EncodingOffset]
				switch {
				case strings.Contains(*p, "F2"):
					*p = strings.Replace(*p, "F2", "F3", 1)
				case strings.Contains(*p, "F3"):
					*p = strings.Replace(*p, "F3", "F2", 1)
				case strings.Contains(*p, "66"):
					*p = strings.Replace(*p, "66", "F2", 1)
				default:
					*p += "|vex66"
				}
			}},
			{"word", func(r *X86AVXRule) {
				p := &r.OpBytes[r.EncodingOffset]
				if strings.Contains(*p, "W0") {
					*p = strings.Replace(*p, "W0", "W1", 1)
				} else {
					*p = strings.Replace(*p, "W1", "W0", 1)
				}
			}},
		}
		if strings.HasPrefix(original.ZCase, "Zevex_") {
			evex++
			mutations = append(mutations,
				mutation{"broadcast", func(r *X86AVXRule) { r.OpBytes[r.EncodingOffset+1] += "|evexBcstN8" }},
				mutation{"tuple", func(r *X86AVXRule) { r.OpBytes[r.EncodingOffset+1] += "|evexN64" }})
			if original.Ytab == "_yvmovsd" && (original.RowIndex == 6 || original.RowIndex == 7) {
				mutations = append(mutations, mutation{"scalar-store-zeroing", func(r *X86AVXRule) { r.OpBytes[r.EncodingOffset+1] += "|evexZeroingEnabled" }})
			}
		}
		for _, mutation := range mutations {
			changed := original
			changed.OpBytes = append([]string(nil), original.OpBytes...)
			changed.Classes = append([]string(nil), original.Classes...)
			mutation.edit(&changed)
			if _, err := x86PackedAVXRowWitnesses(changed); err == nil {
				t.Fatal("changed source metadata borrowed a legal move format", original.Opcode, original.RowIndex, mutation.name)
			}
		}
		count++
	}
	if count != 101 || evex != 44 {
		t.Fatal("original move format-negative denominator changed", count, evex)
	}
}
