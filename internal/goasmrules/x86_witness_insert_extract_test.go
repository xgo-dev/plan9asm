package goasmrules

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Source rows include alternate encodings shadowed by an earlier matching Go
// row. Their physical witnesses do not imply that named source selects them.
func TestX86InsertExtractCompleteOfficialSourceAndExistingWitnesses(t *testing.T) {
	expected := map[string]int{
		"VEXTRACTF128": 2, "VEXTRACTI128": 2,
		"VEXTRACTF32X4": 4, "VEXTRACTF64X2": 4,
		"VEXTRACTI32X4": 4, "VEXTRACTI64X2": 4,
		"VEXTRACTF32X8": 2, "VEXTRACTF64X4": 2,
		"VEXTRACTI32X8": 2, "VEXTRACTI64X4": 2,
		"VEXTRACTPS": 3, "VPEXTRB": 3, "VPEXTRD": 3,
		"VPEXTRQ": 3, "VPEXTRW": 6,
		"VINSERTF128": 1, "VINSERTI128": 1,
		"VINSERTF32X4": 4, "VINSERTF64X2": 4,
		"VINSERTI32X4": 4, "VINSERTI64X2": 4,
		"VINSERTF32X8": 2, "VINSERTF64X4": 2,
		"VINSERTI32X8": 2, "VINSERTI64X4": 2,
		"VINSERTPS": 2, "VPINSRB": 2, "VPINSRD": 2,
		"VPINSRQ": 2, "VPINSRW": 2,
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	members, tables, originals := map[string]int{}, map[string]bool{}, map[string]X86AVXRule{}
	var order []string
	for index, rule := range avx {
		if _, found := expected[rule.Opcode]; !found {
			continue
		}
		id := fmt.Sprintf("avx/%d/%s/%s/%d", index, rule.Opcode, rule.Ytab, rule.RowIndex)
		if _, duplicate := originals[id]; duplicate {
			t.Fatal("duplicate original source row", id)
		}
		originals[id], tables[rule.Ytab] = rule, true
		order = append(order, id)
		members[rule.Opcode]++
	}
	if len(originals) != 82 || len(members) != 30 || len(tables) != 10 {
		t.Fatal("complete insert/extract source closure changed", len(originals), len(members), len(tables))
	}
	for name, want := range expected {
		if members[name] != want {
			t.Fatal("original member rows changed", name, members[name], want)
		}
	}
	// First RED must reach the existing shared witness grammar. It must not
	// depend on a missing future family API or an invented encoder stub.
	physical := 0
	for _, id := range order {
		original := originals[id]
		t.Run(id, func(t *testing.T) {
			witnesses, err := x86PackedAVXRowWitnesses(original)
			if err != nil {
				t.Fatal("complete official physical row lacks an existing witness path", err)
			}
			if len(witnesses) == 0 {
				t.Fatal("empty physical row cannot establish a witness", id)
			}
			for _, witness := range witnesses {
				if len(witness.Encoding) == 0 || witness.MaskResult || witness.Broadcast {
					t.Fatal("insert/extract acquired an unowned encoding or source/result kind", id, witness)
				}
			}
			physical += len(witnesses)
		})
	}
	if physical != 197 {
		t.Fatal("complete physical projection changed, not a named-source pass count", physical)
	}
}

func TestX86InsertExtractRejectsForeignPhysicalAxes(t *testing.T) {
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, original := range avx {
		if !strings.HasPrefix(original.Ytab, "_yvextract") && !strings.HasPrefix(original.Ytab, "_yvinsert") &&
			original.Ytab != "_yvpextrw" && original.Ytab != "_yvpinsrb" {
			continue
		}
		if _, err := x86PackedAVXRowWitnesses(original); err != nil {
			t.Fatal("negative control has no valid original", original, err)
		}
		for _, axis := range []string{"prefix", "table", "ordinal", "offset", "stride", "immediate", "source", "destination", "mask", "zcase", "header", "W", "tuple", "extent"} {
			t.Run(fmt.Sprintf("%s/%d/%s", original.Opcode, original.RowIndex, axis), func(t *testing.T) {
				changed := original
				changed.Classes = append([]string(nil), original.Classes...)
				changed.OpBytes = append([]string(nil), original.OpBytes...)
				switch axis {
				case "prefix":
					changed.Prefix = "Pm"
				case "table":
					changed.Ytab = "_foreign_insert_extract"
				case "ordinal":
					changed.RowIndex += 1000
				case "offset":
					changed.EncodingOffset++
				case "stride":
					changed.ZOffset++
				case "immediate":
					changed.Classes[0] = "Yi32"
				case "source":
					changed.Classes[1] = "Yk"
				case "destination":
					changed.Classes[len(changed.Classes)-1] = "Yk"
				case "mask":
					found := false
					for index, class := range changed.Classes {
						if class == "Yknot0" {
							changed.Classes[index], found = "Yk0", true
						}
					}
					if !found {
						changed.Classes = append(changed.Classes, "Yk0")
					}
				case "zcase":
					changed.ZCase = "Zevex_rm_v_r"
				case "header":
					changed.OpBytes[changed.EncodingOffset] += "|foreignTransferAxis"
				case "W":
					from, to := "W0", "W1"
					if strings.Contains(changed.OpBytes[changed.EncodingOffset], "W1") {
						from, to = to, from
					}
					changed.OpBytes[changed.EncodingOffset] = strings.Replace(changed.OpBytes[changed.EncodingOffset], from, to, 1)
				case "tuple":
					changed.OpBytes[changed.EncodingOffset+1] = "evexN64"
				case "extent":
					changed.OpBytes = append(changed.OpBytes, "0")
				}
				if _, err := x86PackedAVXRowWitnesses(changed); err == nil {
					t.Fatal("foreign physical metadata was accepted", original, axis)
				}
			})
		}
		count++
	}
	if count != 82 {
		t.Fatal("negative controls lost an original row", count)
	}
}
