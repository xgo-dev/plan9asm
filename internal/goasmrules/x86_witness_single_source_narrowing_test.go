package goasmrules

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const x86SingleSourceNarrowingTestMembers = `VPMOVDB VPMOVDW VPMOVQB VPMOVQD VPMOVQW VPMOVWB
	VPMOVSDB VPMOVSDW VPMOVSQB VPMOVSQD VPMOVSQW VPMOVSWB
	VPMOVUSDB VPMOVUSDW VPMOVUSQB VPMOVUSQD VPMOVUSQW VPMOVUSWB`

func TestX86SingleSourceNarrowingCompleteOfficialTransport(t *testing.T) {
	legacy, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	// Use an existing helper: RED must be a real format-admission failure,
	// never compilation against a not-yet-implemented public selector.
	rows, err := x86PackedBinaryRows(legacy, avx, x86SingleSourceNarrowingTestMembers)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 108 {
		t.Fatal("lost an official narrowing row", len(rows))
	}
	for _, group := range []struct {
		prefix string
		opcode int
	}{{"VPMOV", 0x30}, {"VPMOVS", 0x20}, {"VPMOVUS", 0x10}} {
		for _, pair := range []struct {
			suffix                string
			input, output, opcode int
		}{{"WB", 2, 1, 0}, {"DB", 4, 1, 1}, {"QB", 8, 1, 2},
			{"DW", 4, 2, 3}, {"QW", 8, 2, 4}, {"QD", 8, 4, 5}} {
			name := group.prefix + pair.suffix
			table := "_yvpmovdb"
			if pair.input/pair.output == 2 {
				table = "_yvpmovdw"
			}
			var payload []string
			for _, width := range []int{128, 256, 512} {
				payload = append(payload,
					fmt.Sprintf("avxEscape | evex%d | evexF3 | evex0F38 | evexW0", width),
					fmt.Sprintf("evexN%d | evexZeroingEnabled", width/8*pair.output/pair.input),
					fmt.Sprintf("0x%02X", group.opcode+pair.opcode))
			}
			count := 0
			for _, row := range avx {
				if row.Opcode != name {
					continue
				}
				if count >= 6 {
					t.Fatal("extra official member row", name, row)
				}
				width := 16 << (count / 2)
				source := []string{"YxrEvex", "YyrEvex", "Yzr"}[count/2]
				destination := "YxmEvex"
				if width*pair.output/pair.input > 16 {
					destination = "YymEvex"
				}
				classes, zcase := []string{source, destination}, "Zevex_r_v_rm"
				if count%2 != 0 {
					classes, zcase = []string{source, "Yknot0", destination}, "Zevex_r_k_rm"
				}
				if row.RowIndex != count || row.Ytab != table || row.Prefix != "Pavx" ||
					row.ZCase != zcase || row.ZOffset != count%2*3 || row.EncodingOffset != count/2*3 ||
					!reflect.DeepEqual(row.Classes, classes) || !reflect.DeepEqual(row.OpBytes, payload) {
					t.Fatal("source width, shrinking tuple or destination carrier changed", name, row)
				}
				count++
			}
			if count != 6 {
				t.Fatal("member lost an original Go row", name, count)
			}
		}
	}
	widths, memory, masked, zeroing := map[int]int{}, 0, 0, 0
	for _, row := range rows {
		for _, w := range row.Witnesses {
			args := strings.Split(strings.Fields(w.Instruction)[1], ",")
			if w.Generation != "evex" || w.First != args[0] || !strings.HasSuffix(w.First, "16") ||
				w.Second != "" || w.Memory || w.Broadcast || w.MaskResult ||
				w.Destination != args[len(args)-1] {
				t.Fatal("store direction was confused with source-memory or register zeroing", row.ID, w)
			}
			if w.Destination == "(AX)" {
				memory++
			} else if !strings.HasSuffix(w.Destination, "18") {
				t.Fatal("physical destination bank does not force EVEX", row.ID, w)
			}
			if w.Masked {
				masked++
			}
			if w.Zeroing {
				zeroing++
			}
			widths[w.Width]++
		}
	}
	if !reflect.DeepEqual(widths, map[int]int{128: 108, 256: 108, 512: 108}) || memory != 162 || masked != 216 || zeroing != 108 {
		t.Fatal("complete Go projection changed; 54 memory.Z forms require terminal traps, leaving 270 ordinary forms",
			widths, memory, masked, zeroing)
	}
	x86CheckPackedEncodingAnchors(t, rows, []x86PackedEncodingAnchor{
		{"VPMOVDB X16,X18", []byte{0x62, 0xa2, 0x7e, 0x08, 0x31, 0xc2}},
		{"VPMOVUSQB Y16,X18", []byte{0x62, 0xa2, 0x7e, 0x28, 0x12, 0xc2}},
		{"VPMOVSQD.Z Z16,K1,Y18", []byte{0x62, 0xa2, 0x7e, 0xc9, 0x25, 0xc2}},
		{"VPMOVWB X16,(AX)", []byte{0x62, 0xe2, 0x7e, 0x08, 0x30, 0x00}},
		{"VPMOVUSQW Z16,K1,(AX)", []byte{0x62, 0xe2, 0x7e, 0x49, 0x14, 0x00}},
	})
}

func TestX86SingleSourceNarrowingTransportRejectsForeignAxes(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"source carrier", "result carrier", "full tuple", "BCST", "SAE", "rounding", "W1", "66", "0F", "load direction", "zero mask", "row stride"} {
		t.Run(mutation, func(t *testing.T) {
			found := 0
			for _, original := range rules {
				if original.Opcode != "VPMOVUSQB" || original.RowIndex != 5 {
					continue
				}
				found++
				row := original
				row.Classes, row.OpBytes = append([]string(nil), row.Classes...), append([]string(nil), row.OpBytes...)
				header, feature := row.EncodingOffset, row.EncodingOffset+1
				switch mutation {
				case "source carrier":
					row.Classes[0] = "YxrEvex"
				case "result carrier":
					row.Classes[2] = "YymEvex"
				case "full tuple":
					row.OpBytes[feature] = strings.Replace(row.OpBytes[feature], "evexN8", "evexN64", 1)
				case "BCST":
					row.OpBytes[feature] += " | evexBcstN8"
				case "SAE":
					row.OpBytes[feature] += " | evexSaeEnabled"
				case "rounding":
					row.OpBytes[feature] += " | evexRoundingEnabled"
				case "W1":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evexW0", "evexW1", 1)
				case "66":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evexF3", "evex66", 1)
				case "0F":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evex0F38", "evex0F", 1)
				case "load direction":
					row.ZCase = "Zevex_rm_k_r"
				case "zero mask":
					row.Classes[1] = "Yk"
				case "row stride":
					row.ZOffset = 1
				}
				if _, err := x86PackedAVXRowWitnesses(row); err == nil {
					t.Fatal("foreign narrowing transport was admitted", mutation, row)
				}
			}
			if found != 1 {
				t.Fatal("independent mutation row is absent", found)
			}
		})
	}
}
