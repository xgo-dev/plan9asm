package goasmrules

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86KDataCompleteExistingRowTransport(t *testing.T) {
	legacy, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	const members = `KADDB KADDD KADDQ KADDW KANDB KANDD KANDNB KANDND KANDNQ KANDNW KANDQ KANDW KMOVB KMOVD KMOVQ KMOVW KNOTB KNOTD KNOTQ KNOTW KORB KORD KORQ KORTESTB KORTESTD KORTESTQ KORTESTW KORW KSHIFTLB KSHIFTLD KSHIFTLQ KSHIFTLW KSHIFTRB KSHIFTRD KSHIFTRQ KSHIFTRW KTESTB KTESTD KTESTQ KTESTW KUNPCKBW KUNPCKDQ KUNPCKWD KXNORB KXNORD KXNORQ KXNORW KXORB KXORD KXORQ KXORW VPMOVB2M VPMOVD2M VPMOVM2B VPMOVM2D VPMOVM2Q VPMOVM2W VPMOVQ2M VPMOVW2M`
	wanted := map[string]bool{}
	for _, name := range strings.Fields(members) {
		wanted[name] = true
	}
	originals, tables := map[string]bool{}, map[string]int{}
	oldBroadcast := 0
	for index, row := range avx {
		if row.Opcode == "VPBROADCASTMB2Q" || row.Opcode == "VPBROADCASTMW2D" {
			oldBroadcast++
		}
		if !wanted[row.Opcode] {
			continue
		}
		originals[fmt.Sprintf("avx/%d/%s/%s/%d", index, row.Opcode, row.Ytab, row.RowIndex)] = true
		tables[row.Ytab]++
	}
	expected := map[string]int{
		"_ykaddb": 27, "_yknotb": 12, "_ykmovb": 16,
		"_ykshiftlb": 8, "_yvpbroadcastmb2q": 12, "_yvpmovb2m": 12,
	}
	if len(wanted) != 59 || len(originals) != 87 || oldBroadcast != 6 || len(tables) != 6 {
		t.Fatal("complete K-data source closure lost", len(wanted), len(originals), oldBroadcast, tables)
	}
	for table, count := range expected {
		if tables[table] != count {
			t.Fatal("complete original format group lost", table, tables[table], count)
		}
	}
	// Real format RED through an existing helper, no future API symbol.
	rows, err := x86PackedBinaryRows(legacy, avx, members)
	if err != nil {
		t.Fatal("complete K-data row/source-role transport", err)
	}
	seen := map[string]bool{}
	formats := 0
	for _, row := range rows {
		if !originals[row.ID] || seen[row.ID] || len(row.Witnesses) == 0 {
			t.Fatal("source record lost/duplicated", row)
		}
		seen[row.ID] = true
		for _, w := range row.Witnesses {
			if strings.Fields(w.Instruction)[0] != row.Opcode || w.Masked || w.Zeroing || w.Broadcast {
				t.Fatal("K data borrowed writemasking/suffix capabilities", row, w)
			}
			formats++
		}
	}
	if len(seen) != 87 || formats != 91 {
		t.Fatal("source-kind canonical projection lost", len(seen), formats)
	}
}

func TestX86KDataFormatKeepsEveryPhysicalAxis(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, original := range rules {
		if x86KDataTable(original.Opcode) == "" {
			continue
		}
		count++
		for _, change := range []string{"prefix", "row", "offset", "stride", "class", "length", "W", "suffix", "control"} {
			t.Run(fmt.Sprintf("%s/%d/%s", original.Opcode, original.RowIndex, change), func(t *testing.T) {
				rule := original
				rule.Classes = append([]string(nil), original.Classes...)
				rule.OpBytes = append([]string(nil), original.OpBytes...)
				switch change {
				case "prefix":
					rule.Prefix = "Px"
				case "row":
					rule.RowIndex += 4
				case "offset":
					rule.EncodingOffset++
				case "stride":
					rule.ZOffset++
				case "class":
					rule.Classes[0] = "Yknot0"
				case "length":
					rule.OpBytes[rule.EncodingOffset] = strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(rule.OpBytes[rule.EncodingOffset], "128", "BAD"), "256", "BAD"), "512", "BAD")
				case "W":
					atom := rule.OpBytes[rule.EncodingOffset]
					if strings.Contains(atom, "W0") {
						atom = strings.ReplaceAll(atom, "W0", "W1")
					} else {
						atom = strings.ReplaceAll(atom, "W1", "W0")
					}
					rule.OpBytes[rule.EncodingOffset] = atom
				case "suffix":
					rule.Opcode += ".Z"
				case "control":
					rule.OpBytes[rule.EncodingOffset] += "|evexZeroingEnabled"
				}
				if _, err := x86KDataRowWitnesses(rule); err == nil {
					t.Fatal("K data borrowed another width/role/control", change, rule)
				}
			})
		}
	}
	if count != 87 {
		t.Fatal("complete K-data negative denominator changed", count)
	}
}
