package goasmrules

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const x86IntegerTestMaskTestMembers = `VPTESTMB VPTESTMW VPTESTMD VPTESTMQ
	VPTESTNMB VPTESTNMW VPTESTNMD VPTESTNMQ`

func TestX86IntegerTestMaskCompleteOfficialTransport(t *testing.T) {
	legacy, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	// Existing entry point: the initial RED must be an actual unsupported
	// format, not a test compiled against a future public family selector.
	rows, err := x86PackedBinaryRows(legacy, avx, x86IntegerTestMaskTestMembers)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 48 {
		t.Fatal("lost a VPTESTM/NM row or included VPSHUFBITQMB/legacy PTEST", len(rows))
	}
	for _, name := range strings.Fields(x86IntegerTestMaskTestMembers) {
		letter := name[len(name)-1]
		lane := map[byte]int{'B': 1, 'W': 2, 'D': 4, 'Q': 8}[letter]
		pp, w, opcode := "66", "W0", 0x26
		if strings.HasPrefix(name, "VPTESTNM") {
			pp = "F3"
		}
		if letter == 'W' || letter == 'Q' {
			w = "W1"
		}
		if lane >= 4 {
			opcode = 0x27
		}
		var payload []string
		for _, width := range []int{128, 256, 512} {
			feature := fmt.Sprintf("evexN%d", width/8)
			if lane >= 4 {
				feature += fmt.Sprintf(" | evexBcstN%d", lane)
			}
			payload = append(payload, fmt.Sprintf("avxEscape | evex%d | evex%s | evex0F38 | evex%s", width, pp, w),
				feature, fmt.Sprintf("0x%02X", opcode))
		}
		count := 0
		for _, rule := range avx {
			if rule.Opcode != name {
				continue
			}
			if count >= 6 {
				t.Fatal("extra original member row", name, rule)
			}
			classes := [][]string{{"YxmEvex", "YxrEvex"}, {"YymEvex", "YyrEvex"}, {"Yzm", "Yzr"}}[count/2]
			zcase := "Zevex_rm_v_r"
			if count%2 != 0 {
				classes, zcase = append(classes, "Yknot0"), "Zevex_rm_v_k_r"
			}
			classes = append(classes, "Yk") // K0 is a legal result; it is not a write mask.
			if rule.Ytab != "_yvpshufbitqmb" || rule.Prefix != "Pavx" || rule.RowIndex != count ||
				rule.ZCase != zcase || rule.ZOffset != count%2*3 || rule.EncodingOffset != count/2*3 ||
				!reflect.DeepEqual(rule.Classes, classes) || !reflect.DeepEqual(rule.OpBytes, payload) {
				t.Fatal("source width, memory tuple, polarity or K roles changed", name, rule)
			}
			count++
		}
		if count != 6 {
			t.Fatal("member lost its complete official table", name, count)
		}
	}
	widths, destinations := map[int]int{}, map[string]int{}
	memory, masked, broadcast, witnesses := 0, 0, 0, 0
	for _, row := range rows {
		for _, witness := range row.Witnesses {
			if witness.Generation != "evex" || !witness.MaskResult || witness.Zeroing ||
				witness.Destination != "K0" && witness.Destination != "K2" ||
				!strings.HasSuffix(witness.Second, "17") || witness.Memory != (witness.First == "(AX)") {
				t.Fatal("vector source, optional write mask and result K were conflated", row.ID, witness)
			}
			if witness.Memory {
				memory++
			}
			if witness.Masked {
				masked++
				if witness.Broadcast {
					// Input K1 and result K2 remain independent at every tuple.
					if !strings.Contains(witness.Instruction, ",K1,"+witness.Destination) {
						t.Fatal("a write mask acquired the destination role", witness)
					}
				}
			}
			if witness.Broadcast {
				broadcast++
			}
			widths[witness.Width]++
			destinations[witness.Destination]++
			witnesses++
		}
	}
	if witnesses != 240 || memory != 144 || masked != 120 || broadcast != 48 ||
		!reflect.DeepEqual(widths, map[int]int{128: 80, 256: 80, 512: 80}) ||
		!reflect.DeepEqual(destinations, map[string]int{"K0": 120, "K2": 120}) {
		t.Fatal("complete eight-member projection changed", witnesses, memory, masked, broadcast, widths, destinations)
	}
	x86CheckPackedEncodingAnchors(t, rows, []x86PackedEncodingAnchor{
		{"VPTESTMB X16,X17,K2", []byte{0x62, 0xb2, 0x75, 0x00, 0x26, 0xd0}},
		{"VPTESTNMW (AX),Y17,K1,K2", []byte{0x62, 0xf2, 0xf6, 0x21, 0x26, 0x10}},
		{"VPTESTMD.BCST (AX),Z17,K2", []byte{0x62, 0xf2, 0x75, 0x50, 0x27, 0x10}},
		{"VPTESTNMQ.BCST (AX),Z17,K1,K2", []byte{0x62, 0xf2, 0xf6, 0x51, 0x27, 0x10}},
		{"VPTESTMQ Y16,Y17,K0", []byte{0x62, 0xb2, 0xf5, 0x20, 0x27, 0xc0}},
		{"VPTESTNMD.BCST (AX),X17,K1,K0", []byte{0x62, 0xf2, 0x76, 0x11, 0x27, 0x00}},
	})
}

func TestX86IntegerTestMaskTransportRejectsForeignAxes(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"source width", "vector result", "K0 input mask", "exclude K0 result", "tuple", "BCST tuple", "W", "polarity", "zeroing", "SAE", "rounding", "opcode", "row stride", "byte broadcast"} {
		t.Run(mutation, func(t *testing.T) {
			name, rowIndex := "VPTESTNMQ", 5
			if mutation == "byte broadcast" {
				name, rowIndex = "VPTESTMB", 1
			}
			found := 0
			for _, original := range rules {
				if original.Opcode != name || original.RowIndex != rowIndex {
					continue
				}
				found++
				rule := original
				rule.Classes, rule.OpBytes = append([]string(nil), original.Classes...), append([]string(nil), original.OpBytes...)
				header, feature := rule.EncodingOffset, rule.EncodingOffset+1
				switch mutation {
				case "source width":
					rule.Classes[0] = "YxmEvex"
				case "vector result":
					rule.Classes[3] = "Yzr"
				case "K0 input mask":
					rule.Classes[2] = "Yk"
				case "exclude K0 result":
					rule.Classes[3] = "Yknot0"
				case "tuple":
					rule.OpBytes[feature] = strings.Replace(rule.OpBytes[feature], "evexN64", "evexN8", 1)
				case "BCST tuple":
					rule.OpBytes[feature] = strings.Replace(rule.OpBytes[feature], "evexBcstN8", "evexBcstN4", 1)
				case "W":
					rule.OpBytes[header] = strings.Replace(rule.OpBytes[header], "evexW1", "evexW0", 1)
				case "polarity":
					rule.OpBytes[header] = strings.Replace(rule.OpBytes[header], "evexF3", "evex66", 1)
				case "zeroing":
					rule.OpBytes[feature] += " | evexZeroingEnabled"
				case "SAE":
					rule.OpBytes[feature] += " | evexSaeEnabled"
				case "rounding":
					rule.OpBytes[feature] += " | evexRoundingEnabled"
				case "opcode":
					rule.OpBytes[header+2] = "0x8F"
				case "row stride":
					rule.ZOffset = 1
				case "byte broadcast":
					rule.OpBytes[feature] += " | evexBcstN4"
				}
				if witnesses, err := x86PackedAVXRowWitnesses(rule); err == nil || len(witnesses) != 0 {
					t.Fatal("foreign test-to-mask axis was admitted", mutation, witnesses, err)
				}
			}
			if found != 1 {
				t.Fatal("independent original mutation row missing", found)
			}
		})
	}
}
