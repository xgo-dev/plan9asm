package goasmrules

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

const x86PackedBroadcastTestNames = `
	VPBROADCASTB VPBROADCASTW VPBROADCASTD VPBROADCASTQ
	VBROADCASTSS VBROADCASTSD VBROADCASTI32X2 VBROADCASTF32X2
	VBROADCASTF32X4 VBROADCASTF64X2 VBROADCASTI32X4 VBROADCASTI64X2
	VBROADCASTF32X8 VBROADCASTF64X4 VBROADCASTI32X8 VBROADCASTI64X4
	VPBROADCASTMB2Q VPBROADCASTMW2D VBROADCASTF128 VBROADCASTI128`

func TestX86PackedBroadcastCompleteOfficialTransport(t *testing.T) {
	legacy, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	// Existing row reader gives a real format RED, without a future selector.
	rows, err := x86PackedBinaryRows(legacy, avx, x86PackedBroadcastTestNames)
	if err != nil {
		t.Fatal(err)
	}
	originals := map[string]X86AVXRule{}
	for index, row := range avx {
		if strings.HasPrefix(row.Opcode, "VBROADCAST") || strings.HasPrefix(row.Opcode, "VPBROADCAST") {
			originals[fmt.Sprintf("avx/%d/%s/%s/%d", index, row.Opcode, row.Ytab, row.RowIndex)] = row
		}
	}
	names, ids, instructions := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var rowKinds, formats [2]int
	widthCounts := map[int]int{}
	memory, masked, zeroing, kdata, single := 0, 0, 0, 0, 0
	for _, row := range rows {
		original, valid := originals[row.ID]
		if !valid || ids[row.ID] || row.Opcode != original.Opcode || len(row.Witnesses) == 0 {
			t.Fatal("broadcast lost its exact official row or source-only witness", row)
		}
		ids[row.ID], names[row.Opcode] = true, true
		evex := strings.HasPrefix(original.ZCase, "Zevex_")
		generation, index := "vex", 0
		if evex {
			generation, index = "evex", 1
		}
		rowKinds[index]++
		width := map[string]int{"Yxr": 128, "Yyr": 256, "YxrEvex": 128, "YyrEvex": 256, "Yzr": 512}[original.Classes[len(original.Classes)-1]]
		register := "X0"
		if evex {
			register = "X16"
		}
		sources := []string{register, "(AX)"}
		switch original.Classes[0] {
		case "Yrl":
			sources = []string{"AX"}
		case "Yk":
			sources = []string{"K0"} // K0 is data here, never a writemask.
		case "Ym":
			sources = []string{"(AX)"}
		case "Yxm", "YxmEvex":
		default:
			t.Fatal("broadcast source class escaped the complete official family", original)
		}
		wantMasked := original.ZCase == "Zevex_rm_k_r"
		want := len(sources)
		if wantMasked {
			want *= 2
		}
		if len(row.Witnesses) != want {
			t.Fatal("broadcast invented a register/memory alternative or omitted mask/zero controls", row.ID, len(row.Witnesses), want)
		}
		if want == 1 {
			single++
		}
		for _, witness := range row.Witnesses {
			if len(witness.Encoding) != 5 && !evex || len(witness.Encoding) != 6 && evex {
				t.Fatal("broadcast has no complete VEX/EVEX bytes", row.ID, witness)
			}
			fields := strings.Fields(witness.Instruction)
			if len(fields) != 2 {
				t.Fatal("broadcast has no complete source spelling", row.ID, witness)
			}
			operands := strings.Split(fields[1], ",")
			allowed := false
			for _, source := range sources {
				allowed = allowed || witness.First == source
			}
			if !allowed || instructions[witness.Instruction] || witness.First != operands[0] ||
				strings.TrimSuffix(fields[0], ".Z") != row.Opcode || witness.Zeroing != strings.HasSuffix(fields[0], ".Z") ||
				witness.Destination != operands[len(operands)-1] ||
				witness.Second != "" || witness.Width != width || witness.Generation != generation ||
				witness.Memory != (witness.First == "(AX)") || witness.Masked != wantMasked ||
				witness.MaskResult || witness.Broadcast || witness.Zeroing && !wantMasked ||
				wantMasked && operands[1] != "K1" || !wantMasked && len(operands) != 2 {
				t.Fatal("broadcast confused source data, destination or writemask roles", row.ID, witness)
			}
			instructions[witness.Instruction] = true
			if witness.Encoding[2]&0x78 != 0x78 || !evex && witness.Encoding[0] != 0xc4 ||
				evex && (!strings.HasSuffix(witness.Destination, "18") || witness.Encoding[0] != 0x62 || witness.Encoding[3]&8 == 0) {
				t.Fatal("broadcast lost reserved vvvv/V' or physical EVEX identity", row.ID, witness)
			}
			formats[index]++
			widthCounts[width]++
			if witness.Memory {
				memory++
			}
			if witness.Masked {
				masked++
			}
			if witness.Zeroing {
				zeroing++
			}
			if witness.First == "K0" {
				kdata++
			}
		}
	}
	if len(names) != 20 || len(rows) != 111 || len(ids) != len(originals) || rowKinds != [2]int{13, 98} ||
		formats != [2]int{24, 210} || widthCounts[128] != 60 || widthCounts[256] != 88 || widthCounts[512] != 86 ||
		memory != 115 || masked != 136 || zeroing != 68 || kdata != 6 || single != 32 {
		t.Fatal("complete scalar/block/GP/K-data broadcast denominator changed", len(names), len(rows), rowKinds, formats, widthCounts, memory, masked, zeroing, kdata, single)
	}
	x86CheckPackedEncodingAnchors(t, rows, []x86PackedEncodingAnchor{
		{"VBROADCASTF128 (AX),Y2", []byte{0xc4, 0xe2, 0x7d, 0x1a, 0x10}},
		{"VBROADCASTSS X0,X2", []byte{0xc4, 0xe2, 0x79, 0x18, 0xd0}},
		{"VPBROADCASTB AX,X18", []byte{0x62, 0xe2, 0x7d, 0x08, 0x7a, 0xd0}},
		{"VPBROADCASTQ AX,Z18", []byte{0x62, 0xe2, 0xfd, 0x48, 0x7c, 0xd0}},
		{"VPBROADCASTMB2Q K0,Z18", []byte{0x62, 0xe2, 0xfe, 0x48, 0x2a, 0xd0}},
		{"VPBROADCASTMW2D K0,X18", []byte{0x62, 0xe2, 0x7e, 0x08, 0x3a, 0xd0}},
		{"VBROADCASTF32X4.Z (AX),K1,Z18", []byte{0x62, 0xe2, 0x7d, 0xc9, 0x1a, 0x10}},
		{"VBROADCASTF64X4 (AX),Z18", []byte{0x62, 0xe2, 0xfd, 0x48, 0x1b, 0x10}},
		{"VBROADCASTI32X2 X16,Z18", []byte{0x62, 0xa2, 0x7d, 0x48, 0x59, 0xd0}},
	})
}

func TestX86PackedBroadcastOfficialSourceContracts(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	selected := map[string]bool{}
	for _, name := range strings.Fields(x86PackedBroadcastTestNames) {
		selected[name] = true
	}
	seen := 0
	for _, row := range rules {
		if !selected[row.Opcode] {
			continue
		}
		seen++
		kind, width := "vex", map[string]int{"Yxr": 128, "Yyr": 256, "YxrEvex": 128, "YyrEvex": 256, "Yzr": 512}[row.Classes[len(row.Classes)-1]]
		if strings.HasPrefix(row.ZCase, "Zevex_") {
			kind = "evex"
		}
		pp, w := "66", 0
		if row.Classes[0] == "Yk" {
			pp = "F3"
		}
		if kind == "evex" && (row.Opcode == "VBROADCASTSD" || strings.Contains(row.Opcode, "64X") || strings.HasSuffix(row.Opcode, "Q")) {
			w = 1
		}
		want := fmt.Sprintf("avxEscape|%s%d|%s%s|%s0F38|%sW%d", kind, width, kind, pp, kind, kind, w)
		if strings.Join(strings.Fields(row.OpBytes[row.EncodingOffset]), "") != want {
			t.Fatal("broadcast PP/W/map/width changed", row)
		}
		if kind != "evex" {
			continue
		}
		feature := "0"
		if row.Classes[0] == "Yrl" {
			feature = "evexZeroingEnabled"
		} else if row.Classes[0] != "Yk" {
			bytes := 0
			switch row.Ytab {
			case "_yvpbroadcastb":
				bytes = map[byte]int{'B': 1, 'W': 2, 'D': 4, 'Q': 8}[row.Opcode[len(row.Opcode)-1]]
			case "_yvbroadcastss":
				bytes = 4
			case "_yvbroadcastsd", "_yvbroadcasti32x2", "_yvbroadcastf32x2":
				bytes = 8
			case "_yvbroadcastf32x4":
				bytes = 16
			case "_yvbroadcastf32x8":
				bytes = 32
			}
			feature = fmt.Sprintf("evexN%d|evexZeroingEnabled", bytes)
		}
		if strings.Join(strings.Fields(row.OpBytes[row.EncodingOffset+1]), "") != feature {
			t.Fatal("broadcast borrowed a full vector tuple or foreign access control", row)
		}
	}
	if seen != 111 {
		t.Fatal("broadcast source contract lost an official row", seen)
	}
}

func TestX86PackedBroadcastTransportRejectsForeignAxes(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"GP memory", "vector GP", "memory-only register", "vector Y carrier", "scalar tuple", "block tuple", "GP tuple", "K-data tuple", "K-data zeroing", "K-data writemask", "K-data nonzero-only", "K-data memory", "K0 writemask class", "SD X width", "small block X width", "large block Y width", "VEX block EVEX", "K-data F2", "GP Q W0", "map", "BCST", "SAE", "rounding", "widening GP", "binary shrinking tuple"} {
		t.Run(mutation, func(t *testing.T) {
			name, index := "VBROADCASTSS", 2
			switch mutation {
			case "GP memory", "GP tuple":
				name, index = "VPBROADCASTB", 2
			case "vector GP":
				name, index = "VPBROADCASTB", 8
			case "memory-only register", "block tuple":
				name, index = "VBROADCASTF32X4", 0
			case "K-data tuple", "K-data zeroing", "K-data writemask", "K-data nonzero-only", "K-data memory", "K-data F2":
				name, index = "VPBROADCASTMB2Q", 0
			case "K0 writemask class":
				index = 3
			case "SD X width":
				name, index = "VBROADCASTSD", 1
			case "small block X width":
				name, index = "VBROADCASTF32X2", 0
			case "large block Y width":
				name, index = "VBROADCASTF32X8", 0
			case "VEX block EVEX":
				name, index = "VBROADCASTF128", 0
			case "GP Q W0":
				name, index = "VPBROADCASTQ", 2
			case "widening GP":
				name, index = "VPMOVSXBW", 2
			case "binary shrinking tuple":
				name, index = "VPMULLD", 2
			}
			found := 0
			for _, original := range rules {
				if original.Opcode != name || original.RowIndex != index {
					continue
				}
				found++
				row := original
				row.Classes = append([]string(nil), row.Classes...)
				row.OpBytes = append([]string(nil), row.OpBytes...)
				header, feature := row.EncodingOffset, row.EncodingOffset+1
				switch mutation {
				case "GP memory", "K-data memory":
					row.Classes[0] = "Ym"
				case "vector GP", "widening GP":
					row.Classes[0] = "Yrl"
				case "memory-only register":
					row.Classes[0] = "YxmEvex"
				case "vector Y carrier":
					row.Classes[0] = "YymEvex"
				case "scalar tuple":
					row.OpBytes[feature] = strings.Replace(row.OpBytes[feature], "evexN4", "evexN8", 1)
				case "block tuple":
					row.OpBytes[feature] = strings.Replace(row.OpBytes[feature], "evexN16", "evexN32", 1)
				case "GP tuple":
					row.OpBytes[feature] += "|evexN1"
				case "K-data tuple":
					row.OpBytes[feature] = "evexN8"
				case "K-data zeroing":
					row.OpBytes[feature] = "evexZeroingEnabled"
				case "K-data writemask":
					row.ZCase, row.Classes = "Zevex_rm_k_r", []string{"Yk", "Yknot0", row.Classes[1]}
				case "K-data nonzero-only":
					row.Classes[0] = "Yknot0"
				case "K0 writemask class":
					row.Classes[1] = "Yk"
				case "SD X width", "small block X width":
					row.Classes[len(row.Classes)-1] = "YxrEvex"
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evex256", "evex128", 1)
				case "large block Y width":
					row.Classes[len(row.Classes)-1] = "YyrEvex"
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evex512", "evex256", 1)
				case "VEX block EVEX":
					row.Classes[1], row.ZCase, row.ZOffset = "YyrEvex", "Zevex_rm_v_r", 3
					row.OpBytes = []string{strings.ReplaceAll(row.OpBytes[0], "vex", "evex"), "evexN16|evexZeroingEnabled", row.OpBytes[1]}
				case "K-data F2":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evexF3", "evexF2", 1)
				case "GP Q W0":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evexW1", "evexW0", 1)
				case "map":
					row.OpBytes[header] = strings.Replace(row.OpBytes[header], "evex0F38", "evex0F", 1)
				case "BCST":
					row.OpBytes[feature] += "|evexBcstN4"
				case "SAE":
					row.OpBytes[feature] += "|evexSaeEnabled"
				case "rounding":
					row.OpBytes[feature] += "|evexRoundingEnabled"
				case "binary shrinking tuple":
					row.OpBytes[feature] = strings.Replace(row.OpBytes[feature], "evexN16", "evexN4", 1)
				}
				if _, err := x86PackedAVXRowWitnesses(row); err == nil {
					t.Fatal("broadcast borrowed a foreign source role, tuple, prefix or masking capability", mutation, row)
				}
			}
			if found != 1 {
				t.Fatal("broadcast negative lost its exact original row", name, index, found)
			}
		})
	}
}
