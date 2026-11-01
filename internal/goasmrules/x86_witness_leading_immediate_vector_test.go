package goasmrules

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const x86LeadingImmediateVectorTestNames = `VALIGND VALIGNQ
	VPSHLDW VPSHLDD VPSHLDQ VPSHRDW VPSHRDD VPSHRDQ VPTERNLOGD VPTERNLOGQ VDBPSADBW`

func TestX86LeadingImmediateVectorCompleteOfficialRows(t *testing.T) {
	legacy, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	names, originals := map[string]bool{}, map[string]X86AVXRule{}
	for _, name := range strings.Fields(x86LeadingImmediateVectorTestNames) {
		names[name] = true
	}
	for _, entry := range legacy.Optab {
		if names[entry.Opcode] {
			t.Fatal("leading-immediate vector family acquired a legacy row", entry)
		}
	}
	for index, row := range avx {
		if names[row.Opcode] {
			originals[fmt.Sprintf("avx/%d/%s/%s/%d", index, row.Opcode, row.Ytab, row.RowIndex)] = row
		}
	}
	if len(names) != 11 || len(originals) != 66 {
		t.Fatal("four complete families lost an original official row", len(names), len(originals))
	}
	// Existing helper: the initial RED must be an actual unsupported format,
	// not a missing future API. This join grants no numerical or memory rights.
	rows, err := x86PackedBinaryRows(legacy, avx, x86LeadingImmediateVectorTestNames)
	if err != nil {
		t.Fatal(err)
	}
	seen, instructions, members := map[string]bool{}, map[string]bool{}, map[string]int{}
	widths := map[int]int{}
	masked, zeroing, broadcast, memory := 0, 0, 0, 0
	for _, row := range rows {
		original, found := originals[row.ID]
		if !found || seen[row.ID] || original.Ytab != "_yvalignd" {
			t.Fatal("leading-immediate vector join lost its original identity", row)
		}
		seen[row.ID], members[row.Opcode] = true, members[row.Opcode]+1
		widthIndex, maskIndex := original.RowIndex/2, original.RowIndex%2
		width, hasMask := 128<<widthIndex, maskIndex != 0
		bank := map[int]string{128: "X", 256: "Y", 512: "Z"}[width]
		registerClass := map[int]string{128: "YxrEvex", 256: "YyrEvex", 512: "Yzr"}[width]
		classes := []string{"Yu8", map[int]string{128: "YxmEvex", 256: "YymEvex", 512: "Yzm"}[width], registerClass}
		if hasMask {
			classes = append(classes, "Yknot0")
		}
		classes = append(classes, registerClass)
		zcase := "Zevex_i_rm_v_r"
		if hasMask {
			zcase = "Zevex_i_rm_v_k_r"
		}
		if original.Prefix != "Pavx" || original.ZCase != zcase || original.ZOffset != maskIndex*3 ||
			original.EncodingOffset != widthIndex*3 || len(original.OpBytes) != 9 ||
			strings.Join(original.Classes, ",") != strings.Join(classes, ",") {
			t.Fatal("leading immediate, two sources, mask and result were conflated", original)
		}
		w, bcst := "W0", 0
		if strings.HasSuffix(row.Opcode, "Q") || strings.HasSuffix(row.Opcode, "W") && row.Opcode != "VDBPSADBW" {
			w = "W1"
		}
		if strings.HasSuffix(row.Opcode, "D") {
			bcst = 4
		} else if strings.HasSuffix(row.Opcode, "Q") {
			bcst = 8
		}
		if _, err := x86PackedEncodingAtoms(original.OpBytes[original.EncodingOffset], []string{
			"avxEscape", "evex" + strconv.Itoa(width), "evex66", "evex0F3A", "evex" + w,
		}, nil); err != nil {
			t.Fatal("leading-immediate header changed", original, err)
		}
		features := []string{"evexN" + strconv.Itoa(width/8), "evexZeroingEnabled"}
		if bcst != 0 {
			features = append(features, "evexBcstN"+strconv.Itoa(bcst))
		}
		if _, err := x86PackedEncodingAtoms(original.OpBytes[original.EncodingOffset+1], features, nil); err != nil {
			t.Fatal("full tuple/broadcast/zeroing axis changed", original, err)
		}
		payload, err := strconv.ParseUint(original.OpBytes[original.EncodingOffset+2], 0, 8)
		if err != nil {
			t.Fatal("official immediate payload has no byte opcode", original, err)
		}
		for _, witness := range row.Witnesses {
			fields := strings.Fields(witness.Instruction)
			if len(fields) != 2 {
				t.Fatal("lost leading-immediate instruction", witness)
			}
			args := strings.Split(fields[1], ",")
			if len(args) != len(classes) || instructions[witness.Instruction] || args[0] != "$7" ||
				witness.First != args[1] || witness.First != bank+"16" && witness.First != "(AX)" ||
				witness.Second != args[2] || witness.Second != bank+"17" ||
				witness.Destination != args[len(args)-1] || witness.Destination != bank+"18" ||
				witness.Width != width || witness.Generation != "evex" || witness.MaskResult ||
				witness.Masked != hasMask || hasMask && args[3] != "K1" ||
				witness.Zeroing != strings.Contains(fields[0], ".Z") || witness.Zeroing && !hasMask ||
				witness.Memory != (witness.First == "(AX)") || witness.Broadcast != strings.Contains(fields[0], ".BCST") ||
				witness.Broadcast && (!witness.Memory || bcst == 0) || len(witness.Encoding) != 7 ||
				witness.Encoding[0] != 0x62 || witness.Encoding[1]&0xf != 3 || witness.Encoding[2]&0x7f != 0x75 ||
				(witness.Encoding[2]&0x80 != 0) != (w == "W1") ||
				(witness.Encoding[3]&0x80 != 0) != witness.Zeroing ||
				(witness.Encoding[3]&0x10 != 0) != witness.Broadcast ||
				witness.Encoding[3]&7 != byte(maskIndex) || 128<<(witness.Encoding[3]>>5&3) != width ||
				witness.Encoding[4] != byte(payload) || witness.Encoding[6] != 7 {
				t.Fatal("leading immediate/two-vector/vector-result witness borrowed a foreign role", row.ID, witness)
			}
			instructions[witness.Instruction], widths[width] = true, widths[width]+1
			if witness.Masked {
				masked++
			}
			if witness.Zeroing {
				zeroing++
			}
			if witness.Broadcast {
				broadcast++
			}
			if witness.Memory {
				memory++
			}
		}
	}
	if len(rows) != 66 || len(seen) != len(originals) || len(members) != 11 || len(instructions) != 270 ||
		widths[128] != 90 || widths[256] != 90 || widths[512] != 90 ||
		masked != 180 || zeroing != 90 || broadcast != 72 || memory != 171 {
		t.Fatal("complete leading-immediate source/control denominator changed", len(rows), members, len(instructions), widths, masked, zeroing, broadcast, memory)
	}
	for member, count := range members {
		if count != 6 {
			t.Fatal("member lost an original width/mask row", member, count)
		}
	}
	x86CheckPackedEncodingAnchors(t, rows, []x86PackedEncodingAnchor{
		{"VALIGND $7,X16,X17,X18", []byte{0x62, 0xa3, 0x75, 0x00, 0x03, 0xd0, 0x07}},
		{"VALIGNQ.BCST.Z $7,(AX),Z17,K1,Z18", []byte{0x62, 0xe3, 0xf5, 0xd1, 0x03, 0x10, 0x07}},
		{"VPSHLDW $7,X16,X17,X18", []byte{0x62, 0xa3, 0xf5, 0x00, 0x70, 0xd0, 0x07}},
		{"VPTERNLOGQ.BCST $7,(AX),Y17,Y18", []byte{0x62, 0xe3, 0xf5, 0x30, 0x25, 0x10, 0x07}},
		{"VDBPSADBW.Z $7,Y16,Y17,K1,Y18", []byte{0x62, 0xa3, 0x75, 0xa1, 0x42, 0xd0, 0x07}},
	})
}

func TestX86LeadingImmediateVectorRejectsForeignAxes(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"signed immediate", "source carrier", "second carrier", "K result", "K0 mask",
		"tuple", "word BCST", "SAD BCST", "both BCST sizes", "no zeroing", "SAE", "rounding", "W", "map", "PP",
		"VEX", "offset", "row index", "opcode extent"} {
		t.Run(mutation, func(t *testing.T) {
			name := "VALIGND"
			if mutation == "word BCST" {
				name = "VPSHLDW"
			} else if mutation == "SAD BCST" {
				name = "VDBPSADBW"
			}
			found := 0
			for _, original := range rules {
				if original.Opcode != name || original.RowIndex != 1 {
					continue
				}
				found++
				if _, err := x86PackedAVXRowWitnesses(original); err != nil {
					t.Fatal("negative requires its valid original source row", original, err)
				}
				row := original
				row.Classes, row.OpBytes = append([]string(nil), original.Classes...), append([]string(nil), original.OpBytes...)
				header, features := row.EncodingOffset, row.EncodingOffset+1
				switch mutation {
				case "signed immediate":
					row.Classes[0] = "Yi8"
				case "source carrier":
					row.Classes[1] = "YymEvex"
				case "second carrier":
					row.Classes[2] = "YyrEvex"
				case "K result":
					row.Classes[4] = "Yk"
				case "K0 mask":
					row.Classes[3] = "Yk"
				case "tuple":
					row.OpBytes[features] = strings.Replace(row.OpBytes[features], "evexN16", "evexN8", 1)
				case "word BCST":
					row.OpBytes[features] += "|evexBcstN8"
				case "SAD BCST":
					row.OpBytes[features] += "|evexBcstN4"
				case "both BCST sizes":
					row.OpBytes[features] += "|evexBcstN8"
				case "no zeroing":
					row.OpBytes[features] = strings.ReplaceAll(row.OpBytes[features], "evexZeroingEnabled", "")
				case "SAE":
					row.OpBytes[features] += "|evexSaeEnabled"
				case "rounding":
					row.OpBytes[features] += "|evexRoundingEnabled"
				case "W":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evexW0", "evexW1", 1)
				case "map":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evex0F3A", "evex0F38", 1)
				case "PP":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evex66", "evexF3", 1)
				case "VEX":
					row.ZCase = "Zvex_i_rm_v_r"
				case "offset":
					row.EncodingOffset++
				case "row index":
					row.RowIndex++
				case "opcode extent":
					row.OpBytes[header+2] = "256"
				}
				if _, err := x86PackedAVXRowWitnesses(row); err == nil {
					t.Fatal("leading-immediate vector row borrowed a foreign format axis", mutation, row)
				}
			}
			if found != 1 {
				t.Fatal("negative lost its original row", name, found)
			}
		})
	}
}
