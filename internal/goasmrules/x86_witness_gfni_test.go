package goasmrules

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

const x86GFNITestNames = "VGF2P8MULB VGF2P8AFFINEQB VGF2P8AFFINEINVQB"

func TestX86GFNICompleteOriginalRowTransport(t *testing.T) {
	legacy, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, name := range strings.Fields(x86GFNITestNames) {
		names[name] = true
	}
	for _, entry := range legacy.Optab {
		if names[entry.Opcode] {
			t.Fatal("GFNI acquired a legacy Go row", entry)
		}
	}
	originals := map[string]X86AVXRule{}
	for index, row := range avx {
		if names[row.Opcode] {
			originals[fmt.Sprintf("avx/%d/%s/%s/%d", index, row.Opcode, row.Ytab, row.RowIndex)] = row
		}
	}
	if len(originals) != 24 {
		t.Fatal("complete GFNI original source denominator changed", len(originals))
	}
	// Existing helper only: a future selector's missing symbol is not RED.
	rows, err := x86PackedBinaryRows(legacy, avx, x86GFNITestNames)
	if err != nil {
		t.Fatal(err)
	}
	seen, instructions := map[string]bool{}, map[string]bool{}
	rowCounts, formats, generations, widths := map[string]int{}, map[string]int{}, map[string]int{}, map[int]int{}
	masked, zeroing, broadcast, memory := 0, 0, 0, 0
	for _, row := range rows {
		original, found := originals[row.ID]
		if !found || seen[row.ID] {
			t.Fatal("GFNI lost original row identity", row)
		}
		seen[row.ID], rowCounts[row.Opcode] = true, rowCounts[row.Opcode]+1
		affine := row.Opcode != "VGF2P8MULB"
		offset, table := 0, "_yvandnpd"
		if affine {
			offset, table = 1, "_yvgf2p8affineinvqb"
		}
		if original.Ytab != table {
			t.Fatal("GFNI lost its distinct binary/immediate source grammar", original)
		}
		width := map[string]int{"Yxm": 128, "Yym": 256, "YxmEvex": 128, "YymEvex": 256, "Yzm": 512}[original.Classes[offset]]
		bank, kind, first, second, destination := map[int]string{128: "X", 256: "Y", 512: "Z"}[width], "vex", "0", "1", "2"
		if strings.HasPrefix(original.ZCase, "Zevex_") {
			kind, first, second, destination = "evex", "16", "17", "18"
		}
		for _, w := range row.Witnesses {
			fields := strings.Fields(w.Instruction)
			if len(fields) != 2 {
				t.Fatal("GFNI lost source syntax", w)
			}
			args := strings.Split(fields[1], ",")
			wantMasked := original.ZCase == "Zevex_rm_v_k_r" || original.ZCase == "Zevex_i_rm_v_k_r"
			if instructions[w.Instruction] || strings.Split(fields[0], ".")[0] != row.Opcode || affine && args[0] != "$7" ||
				w.First != args[offset] || w.First != bank+first && w.First != "(AX)" || w.Second != args[offset+1] || w.Second != bank+second ||
				w.Destination != bank+destination || args[len(args)-1] != w.Destination || w.Width != width || w.Generation != kind || w.MaskResult ||
				w.Masked != wantMasked || w.Masked && args[len(args)-2] != "K1" || w.Zeroing != strings.HasSuffix(fields[0], ".Z") || w.Zeroing && !w.Masked ||
				w.Memory != (w.First == "(AX)") || w.Broadcast != strings.Contains(fields[0], ".BCST") || w.Broadcast && (!affine || !w.Memory || kind != "evex") {
				t.Fatal("GFNI conflated matrix/data/immediate/byte-mask roles", row.ID, w)
			}
			wantLength := 5
			if kind == "evex" {
				wantLength++
			}
			if affine {
				wantLength++
			}
			if len(w.Encoding) != wantLength || affine && w.Encoding[len(w.Encoding)-1] != 7 {
				t.Fatal("GFNI lost its exact immediate transport", row.ID, w)
			}
			instructions[w.Instruction] = true
			formats[row.Opcode]++
			generations[kind]++
			widths[width]++
			if w.Masked {
				masked++
			}
			if w.Zeroing {
				zeroing++
			}
			if w.Broadcast {
				broadcast++
			}
			if w.Memory {
				memory++
			}
		}
	}
	if len(rows) != 24 || len(seen) != 24 || len(instructions) != 84 || rowCounts["VGF2P8MULB"] != 8 || rowCounts["VGF2P8AFFINEQB"] != 8 || rowCounts["VGF2P8AFFINEINVQB"] != 8 ||
		formats["VGF2P8MULB"] != 22 || formats["VGF2P8AFFINEQB"] != 31 || formats["VGF2P8AFFINEINVQB"] != 31 || generations["vex"] != 12 || generations["evex"] != 72 ||
		widths[128] != 30 || widths[256] != 30 || widths[512] != 24 || masked != 48 || zeroing != 24 || broadcast != 18 || memory != 51 {
		t.Fatal("complete GFNI row/control denominator changed", len(rows), len(instructions), rowCounts, formats, generations, widths, masked, zeroing, broadcast, memory)
	}
	x86CheckPackedEncodingAnchors(t, rows, []x86PackedEncodingAnchor{
		{"VGF2P8MULB X0,X1,X2", []byte{0xc4, 0xe2, 0x71, 0xcf, 0xd0}},
		{"VGF2P8MULB.Z (AX),Z17,K1,Z18", []byte{0x62, 0xe2, 0x75, 0xc1, 0xcf, 0x10}},
		{"VGF2P8AFFINEQB $7,Y0,Y1,Y2", []byte{0xc4, 0xe3, 0xf5, 0xce, 0xd0, 0x07}},
		{"VGF2P8AFFINEINVQB $7,X16,X17,X18", []byte{0x62, 0xa3, 0xf5, 0x00, 0xcf, 0xd0, 0x07}},
		{"VGF2P8AFFINEQB.BCST $7,(AX),Z17,Z18", []byte{0x62, 0xe3, 0xf5, 0x50, 0xce, 0x10, 0x07}},
		{"VGF2P8AFFINEINVQB.BCST.Z $7,(AX),Y17,K1,Y18", []byte{0x62, 0xe3, 0xf5, 0xb1, 0xcf, 0x10, 0x07}},
	})
}

func TestX86GFNIMultiplyRetainsExistingBinaryTransport(t *testing.T) {
	legacy, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := x86PackedBinaryRows(legacy, avx, "VGF2P8MULB")
	if err != nil {
		t.Fatal(err)
	}
	formats := 0
	for _, row := range rows {
		for _, w := range row.Witnesses {
			formats++
			if w.Broadcast || strings.Contains(w.Instruction, "$") || w.MaskResult {
				t.Fatal("MUL borrowed affine or K-result transport", row.ID, w)
			}
		}
	}
	if len(rows) != 8 || formats != 22 {
		t.Fatal("complete existing MUL source rows changed", len(rows), formats)
	}
}

func TestX86GFNIRejectsForeignFormatAxes(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"MUL BCST", "MUL W1", "MUL no66", "MUL map", "signed immediate", "matrix carrier", "data carrier", "K result", "K0 writemask", "matrix tuple", "BCST element", "rounding", "SAE", "affine map", "affine W0", "affine prefix", "VEX Z", "offset", "row index", "opcode extent"} {
		t.Run(mutation, func(t *testing.T) {
			name, index := "VGF2P8AFFINEQB", 2
			if strings.HasPrefix(mutation, "MUL ") {
				name = "VGF2P8MULB"
			}
			if mutation == "K0 writemask" {
				index = 3
			}
			if mutation == "VEX Z" {
				index = 0
			}
			found := 0
			for _, original := range rules {
				if original.Opcode != name || original.RowIndex != index {
					continue
				}
				found++
				if _, err := x86PackedAVXRowWitnesses(original); err != nil {
					t.Fatal("negative requires a valid complete original row", original, err)
				}
				row := original
				row.Classes = append([]string(nil), row.Classes...)
				row.OpBytes = append([]string(nil), row.OpBytes...)
				header, feature := row.EncodingOffset, row.EncodingOffset+1
				switch mutation {
				case "MUL BCST":
					row.OpBytes[feature] += "|evexBcstN8"
				case "MUL W1":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evexW0", "evexW1", 1)
				case "MUL no66":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evex66", "", 1)
				case "MUL map":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evex0F38", "evex0F", 1)
				case "signed immediate":
					row.Classes[0] = "Yi8"
				case "matrix carrier":
					row.Classes[1] = "YymEvex"
				case "data carrier":
					row.Classes[2] = "YyrEvex"
				case "K result":
					row.Classes[len(row.Classes)-1] = "Yk"
				case "K0 writemask":
					row.Classes[3] = "Yk"
				case "matrix tuple":
					row.OpBytes[feature] = strings.Replace(row.OpBytes[feature], "evexN16", "evexN8", 1)
				case "BCST element":
					row.OpBytes[feature] = strings.Replace(row.OpBytes[feature], "evexBcstN8", "evexBcstN4", 1)
				case "rounding":
					row.OpBytes[feature] += "|evexRoundingEnabled"
				case "SAE":
					row.OpBytes[feature] += "|evexSaeEnabled"
				case "affine map":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evex0F3A", "evex0F38", 1)
				case "affine W0":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evexW1", "evexW0", 1)
				case "affine prefix":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evex66", "evexF3", 1)
				case "VEX Z":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "vex128", "vex512", 1)
				case "offset":
					row.EncodingOffset++
				case "row index":
					row.RowIndex++
				case "opcode extent":
					row.OpBytes[header+2] = "256"
				}
				if fmt.Sprint(row) == fmt.Sprint(original) {
					t.Fatal("negative did not change its source row", mutation)
				}
				if _, err := x86PackedAVXRowWitnesses(row); err == nil {
					t.Fatal("GFNI borrowed a foreign source/control capability", mutation, row)
				}
			}
			if found != 1 {
				t.Fatal("negative lost its exact Go row", name, index, found)
			}
		})
	}
}
