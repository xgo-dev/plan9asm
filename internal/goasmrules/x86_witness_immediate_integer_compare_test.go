package goasmrules

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

const x86ImmediateIntegerCompareTestNames = "VPCMPB VPCMPUB VPCMPW VPCMPUW VPCMPD VPCMPUD VPCMPQ VPCMPUQ"

func TestX86ImmediateIntegerCompareCompleteOfficialRows(t *testing.T) {
	legacy, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, name := range strings.Fields(x86ImmediateIntegerCompareTestNames) {
		names[name] = true
	}
	originals := map[string]X86AVXRule{}
	for _, entry := range legacy.Optab {
		if names[entry.Opcode] {
			t.Fatal("immediate integer compare acquired a legacy row", entry)
		}
	}
	for index, row := range avx {
		if names[row.Opcode] {
			originals[fmt.Sprintf("avx/%d/%s/%s/%d", index, row.Opcode, row.Ytab, row.RowIndex)] = row
		}
	}
	if len(originals) != 48 {
		t.Fatal("complete eight-member six-row original source denominator changed", len(originals))
	}
	// Existing helper: RED must report a real unsupported table format.
	rows, err := x86PackedBinaryRows(legacy, avx, x86ImmediateIntegerCompareTestNames)
	if err != nil {
		t.Fatal(err)
	}
	seen, instructions, members := map[string]bool{}, map[string]bool{}, map[string]bool{}
	widths, destinations := map[int]int{}, map[string]int{}
	masked, broadcast, memory := 0, 0, 0
	for _, row := range rows {
		original, found := originals[row.ID]
		if !found || seen[row.ID] || original.Ytab != "_yvpcmpb" {
			t.Fatal("immediate compare lost original table identity", row)
		}
		seen[row.ID], members[row.Opcode] = true, true
		width := map[string]int{"YxmEvex": 128, "YymEvex": 256, "Yzm": 512}[original.Classes[1]]
		bank := map[int]string{128: "X", 256: "Y", 512: "Z"}[width]
		for _, w := range row.Witnesses {
			fields := strings.Fields(w.Instruction)
			if len(fields) != 2 {
				t.Fatal("lost immediate compare instruction", w)
			}
			args := strings.Split(fields[1], ",")
			if instructions[w.Instruction] || args[0] != "$7" || w.First != args[1] || w.Second != args[2] ||
				w.First != bank+"16" && w.First != "(AX)" || w.Second != bank+"17" ||
				w.Destination != args[len(args)-1] || w.Destination != "K0" && w.Destination != "K2" ||
				w.Generation != "evex" || w.Width != width || !w.MaskResult || w.Zeroing ||
				w.Masked != (original.ZCase == "Zevex_i_rm_v_k_r") || w.Masked && args[3] != "K1" ||
				w.Memory != (w.First == "(AX)") || w.Broadcast != strings.Contains(fields[0], ".BCST") ||
				w.Broadcast && (!w.Memory || !strings.HasSuffix(row.Opcode, "D") && !strings.HasSuffix(row.Opcode, "Q")) ||
				len(w.Encoding) != 7 || w.Encoding[0] != 0x62 || w.Encoding[1]&0x1f != 0x13 || w.Encoding[2]&0x7f != 0x75 ||
				w.Encoding[3]&0x88 != 0 || 128<<(w.Encoding[3]>>5&3) != width || w.Encoding[6] != 7 {
				t.Fatal("immediate/vector/K-result/nonzero-mask roles were conflated", row.ID, w)
			}
			instructions[w.Instruction] = true
			widths[width]++
			destinations[w.Destination]++
			if w.Masked {
				masked++
			}
			if w.Broadcast {
				broadcast++
			}
			if w.Memory {
				memory++
			}
		}
	}
	if len(rows) != 48 || len(seen) != len(originals) || len(members) != 8 || len(instructions) != 240 ||
		widths[128] != 80 || widths[256] != 80 || widths[512] != 80 ||
		destinations["K0"] != 120 || destinations["K2"] != 120 || masked != 120 || broadcast != 48 || memory != 144 {
		t.Fatal("complete immediate compare row/control denominator changed", len(rows), len(members), len(instructions), widths, destinations, masked, broadcast, memory)
	}
	x86CheckPackedEncodingAnchors(t, rows, []x86PackedEncodingAnchor{
		{"VPCMPB $7,X16,X17,K0", []byte{0x62, 0xb3, 0x75, 0x00, 0x3f, 0xc0, 0x07}},
		{"VPCMPUB $7,(AX),Z17,K1,K2", []byte{0x62, 0xf3, 0x75, 0x41, 0x3e, 0x10, 0x07}},
		{"VPCMPW $7,Y16,Y17,K2", []byte{0x62, 0xb3, 0xf5, 0x20, 0x3f, 0xd0, 0x07}},
		{"VPCMPUW $7,Z16,Z17,K1,K0", []byte{0x62, 0xb3, 0xf5, 0x41, 0x3e, 0xc0, 0x07}},
		{"VPCMPD.BCST $7,(AX),X17,K0", []byte{0x62, 0xf3, 0x75, 0x10, 0x1f, 0x00, 0x07}},
		{"VPCMPUD $7,Z16,Z17,K1,K2", []byte{0x62, 0xb3, 0x75, 0x41, 0x1e, 0xd0, 0x07}},
		{"VPCMPQ $7,X16,X17,K1,K2", []byte{0x62, 0xb3, 0xf5, 0x01, 0x1f, 0xd0, 0x07}},
		{"VPCMPUQ.BCST $7,(AX),Y17,K1,K0", []byte{0x62, 0xf3, 0xf5, 0x31, 0x1e, 0x00, 0x07}},
	})
}

func TestX86ImmediateIntegerCompareRejectsForeignFormatAxes(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"signed immediate", "source carrier", "second carrier", "vector result", "nonzero-only result", "K0 writemask", "tuple", "byte BCST", "wrong BCST element", "zeroing", "rounding", "SAE", "map", "PP", "W", "VEX", "offset", "row index", "opcode extent"} {
		t.Run(mutation, func(t *testing.T) {
			name, index := "VPCMPD", 0
			if mutation == "byte BCST" {
				name = "VPCMPB"
			}
			if mutation == "K0 writemask" {
				index = 1
			}
			found := 0
			for _, original := range rules {
				if original.Opcode != name || original.RowIndex != index {
					continue
				}
				found++
				if _, err := x86PackedAVXRowWitnesses(original); err != nil {
					t.Fatal("negative requires its valid original row", original, err)
				}
				row := original
				row.Classes, row.OpBytes = append([]string(nil), original.Classes...), append([]string(nil), original.OpBytes...)
				header, feature := row.EncodingOffset, row.EncodingOffset+1
				switch mutation {
				case "signed immediate":
					row.Classes[0] = "Yi8"
				case "source carrier":
					row.Classes[1] = "YymEvex"
				case "second carrier":
					row.Classes[2] = "YyrEvex"
				case "vector result":
					row.Classes[len(row.Classes)-1] = "YxrEvex"
				case "nonzero-only result":
					row.Classes[len(row.Classes)-1] = "Yknot0"
				case "K0 writemask":
					row.Classes[3] = "Yk"
				case "tuple":
					row.OpBytes[feature] = strings.Replace(row.OpBytes[feature], "evexN16", "evexN8", 1)
				case "byte BCST":
					row.OpBytes[feature] += "|evexBcstN4"
				case "wrong BCST element":
					row.OpBytes[feature] = strings.Replace(row.OpBytes[feature], "evexBcstN4", "evexBcstN8", 1)
				case "zeroing":
					row.OpBytes[feature] += "|evexZeroingEnabled"
				case "rounding":
					row.OpBytes[feature] += "|evexRoundingEnabled"
				case "SAE":
					row.OpBytes[feature] += "|evexSaeEnabled"
				case "map":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evex0F3A", "evex0F38", 1)
				case "PP":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evex66", "evexF3", 1)
				case "W":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evexW0", "evexW1", 1)
				case "VEX":
					row.ZCase = "Zvex_i_rm_v_r"
				case "offset":
					row.EncodingOffset++
				case "row index":
					row.RowIndex++
				case "opcode extent":
					row.OpBytes[header+2] = "256"
				}
				if fmt.Sprint(row) == fmt.Sprint(original) {
					t.Fatal("negative did not change its original row", mutation)
				}
				if _, err := x86PackedAVXRowWitnesses(row); err == nil {
					t.Fatal("immediate integer compare borrowed a foreign format axis", mutation, row)
				}
			}
			if found != 1 {
				t.Fatal("negative lost its original row", name, index, found)
			}
		})
	}
}
