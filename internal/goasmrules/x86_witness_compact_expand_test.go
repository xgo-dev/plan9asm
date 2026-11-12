package goasmrules

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const x86CompactExpandTestMembers = `VCOMPRESSPS VCOMPRESSPD VPCOMPRESSB VPCOMPRESSW VPCOMPRESSD VPCOMPRESSQ
	VEXPANDPS VEXPANDPD VPEXPANDB VPEXPANDW VPEXPANDD VPEXPANDQ`

func TestX86CompactExpandCompleteOfficialRows(t *testing.T) {
	legacy, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	names, originals := map[string]bool{}, map[string]X86AVXRule{}
	for _, name := range strings.Fields(x86CompactExpandTestMembers) {
		names[name] = true
	}
	for index, rule := range avx {
		if names[rule.Opcode] {
			originals[fmt.Sprintf("avx/%d/%s/%s/%d", index, rule.Opcode, rule.Ytab, rule.RowIndex)] = rule
		}
	}
	if len(originals) != 72 {
		t.Fatal("complete twelve-member original row inventory changed", len(originals))
	}
	// Existing helper: expected initial RED is the unjoined store direction or
	// element-sized tuple. No future helper or production capability is assumed.
	rows, err := x86PackedBinaryRows(legacy, avx, x86CompactExpandTestMembers)
	if err != nil {
		t.Fatal(err)
	}
	seen, instructions, members := map[string]bool{}, map[string]bool{}, map[string]int{}
	widths := map[int]int{}
	sourceMemory, destinationMemory, masked, zeroing, terminal := 0, 0, 0, 0, 0
	for _, row := range rows {
		original, found := originals[row.ID]
		if !found || seen[row.ID] {
			t.Fatal("compact/expand lost its original ordinal or duplicated a row", row)
		}
		seen[row.ID], members[row.Opcode] = true, members[row.Opcode]+1
		expand := strings.Contains(row.Opcode, "EXPAND")
		widthIndex, maskIndex := original.RowIndex/2, original.RowIndex%2
		width, hasMask := 128<<widthIndex, maskIndex != 0
		bank := map[int]string{128: "X", 256: "Y", 512: "Z"}[width]
		reg := map[int]string{128: "YxrEvex", 256: "YyrEvex", 512: "Yzr"}[width]
		mem := map[int]string{128: "YxmEvex", 256: "YymEvex", 512: "Yzm"}[width]
		first, last, ytab, zcase := reg, mem, "_yvcompresspd", "Zevex_r_v_rm"
		if expand {
			first, last, ytab, zcase = mem, reg, "_yvexpandpd", "Zevex_rm_v_r"
		}
		classes := []string{first}
		if hasMask {
			classes = append(classes, "Yknot0")
			zcase = strings.Replace(zcase, "_v_", "_k_", 1)
			if expand {
				zcase = "Zevex_rm_k_r"
			}
		}
		classes = append(classes, last)
		if original.Ytab != ytab || original.Prefix != "Pavx" || original.ZCase != zcase ||
			original.ZOffset != maskIndex*3 || original.EncodingOffset != widthIndex*3 || len(original.OpBytes) != 9 ||
			strings.Join(original.Classes, ",") != strings.Join(classes, ",") {
			t.Fatal("direction, carrier or nonzero mask differs from original row", original)
		}
		bytes, w := 4, "evexW0"
		if strings.HasSuffix(row.Opcode, "B") {
			bytes = 1
		} else if strings.HasSuffix(row.Opcode, "W") {
			bytes, w = 2, "evexW1"
		} else if strings.HasSuffix(row.Opcode, "Q") || strings.HasSuffix(row.Opcode, "PD") {
			bytes, w = 8, "evexW1"
		}
		if _, err := x86PackedEncodingAtoms(original.OpBytes[original.EncodingOffset], []string{
			"avxEscape", "evex" + strconv.Itoa(width), "evex66", "evex0F38", w,
		}, nil); err != nil {
			t.Fatal("compact/expand header changed", original, err)
		}
		if _, err := x86PackedEncodingAtoms(original.OpBytes[original.EncodingOffset+1], []string{
			"evexN" + strconv.Itoa(bytes), "evexZeroingEnabled",
		}, nil); err != nil {
			t.Fatal("disp8 element scale was replaced by vector or dynamic compact extent", original, err)
		}
		for _, witness := range row.Witnesses {
			fields := strings.Fields(witness.Instruction)
			if len(fields) != 2 {
				t.Fatal("lost compact/expand instruction", witness)
			}
			args := strings.Split(fields[1], ",")
			memorySource, memoryDestination := witness.First == "(AX)", witness.Destination == "(AX)"
			if len(args) != len(classes) || instructions[witness.Instruction] || witness.First != args[0] ||
				witness.Destination != args[len(args)-1] || witness.Second != "" || witness.MaskResult ||
				witness.First != bank+"16" && !memorySource || witness.Destination != bank+"18" && !memoryDestination ||
				memorySource && !expand || memoryDestination && expand ||
				witness.Memory != memorySource || witness.Generation != "evex" || witness.Width != width ||
				witness.Masked != hasMask || hasMask && args[1] != "K1" || witness.Broadcast ||
				witness.Zeroing != strings.HasSuffix(fields[0], ".Z") || witness.Zeroing && !hasMask ||
				len(witness.Encoding) != 6 || witness.Encoding[0] != 0x62 || witness.Encoding[2]&0x7f != 0x7d ||
				witness.Encoding[3]&8 == 0 || witness.Encoding[3]&0x10 != 0 {
				t.Fatal("compact store, source Memory, reserved vvvv or register result was conflated", row.ID, witness)
			}
			instructions[witness.Instruction], widths[width] = true, widths[width]+1
			if memorySource {
				sourceMemory++
			}
			if memoryDestination {
				destinationMemory++
			}
			if witness.Masked {
				masked++
			}
			if witness.Zeroing {
				zeroing++
			}
			if memoryDestination && witness.Zeroing {
				terminal++
			}
		}
	}
	if len(rows) != 72 || len(seen) != len(originals) || len(instructions) != 216 || len(members) != 12 ||
		widths[128] != 72 || widths[256] != 72 || widths[512] != 72 || sourceMemory != 54 || destinationMemory != 54 ||
		masked != 144 || zeroing != 72 || terminal != 18 {
		t.Fatal("complete compact/expand denominator changed", len(rows), len(instructions), widths, sourceMemory, destinationMemory, masked, zeroing, terminal)
	}
	for member, count := range members {
		if count != 6 {
			t.Fatal("member lost a complete width/mask row", member, count)
		}
	}
	x86CheckPackedEncodingAnchors(t, rows, []x86PackedEncodingAnchor{
		{"VCOMPRESSPD X16,X18", []byte{0x62, 0xa2, 0xfd, 0x08, 0x8a, 0xc2}},
		{"VPCOMPRESSB.Z Z16,K1,(AX)", []byte{0x62, 0xe2, 0x7d, 0xc9, 0x63, 0x00}},
		{"VEXPANDPS (AX),Y18", []byte{0x62, 0xe2, 0x7d, 0x28, 0x88, 0x10}},
		{"VPEXPANDW.Z X16,K1,X18", []byte{0x62, 0xa2, 0xfd, 0x89, 0x62, 0xd0}},
	})
}

func TestX86CompactExpandRejectsForeignAxes(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range strings.Fields(x86CompactExpandTestMembers) {
		for _, mutation := range []string{"source width", "result width", "direction", "immediate", "K result", "K0 mask", "arity",
			"full tuple", "BCST", "SAE", "rounding", "no zeroing", "W", "PP", "map", "VEX", "offset", "row index", "short payload", "opcode extent"} {
			t.Run(member+"/"+mutation, func(t *testing.T) {
				found := 0
				for _, original := range rules {
					if original.Opcode != member || original.RowIndex != 1 {
						continue
					}
					found++
					if _, err := x86PackedAVXRowWitnesses(original); err != nil {
						t.Fatal("negative requires its valid original", original, err)
					}
					row := original
					row.Classes, row.OpBytes = append([]string(nil), original.Classes...), append([]string(nil), original.OpBytes...)
					header, feature := row.EncodingOffset, row.EncodingOffset+1
					switch mutation {
					case "source width":
						row.Classes[0] = strings.Replace(row.Classes[0], "x", "y", 1)
					case "result width":
						row.Classes[2] = strings.Replace(row.Classes[2], "x", "y", 1)
					case "direction":
						row.Classes[0], row.Classes[2] = row.Classes[2], row.Classes[0]
					case "immediate":
						row.Classes[0] = "Yu8"
					case "K result":
						row.Classes[2] = "Yk"
					case "K0 mask":
						row.Classes[1] = "Yk"
					case "arity":
						row.Classes = append(row.Classes, "Yk")
					case "full tuple":
						row.OpBytes[feature] = "evexN16|evexZeroingEnabled"
					case "BCST":
						row.OpBytes[feature] += "|evexBcstN4"
					case "SAE":
						row.OpBytes[feature] += "|evexSaeEnabled"
					case "rounding":
						row.OpBytes[feature] += "|evexRoundingEnabled"
					case "no zeroing":
						row.OpBytes[feature] = strings.ReplaceAll(row.OpBytes[feature], "evexZeroingEnabled", "")
					case "W":
						if strings.Contains(row.OpBytes[header], "evexW0") {
							row.OpBytes[header] = strings.ReplaceAll(row.OpBytes[header], "evexW0", "evexW1")
						} else {
							row.OpBytes[header] = strings.ReplaceAll(row.OpBytes[header], "evexW1", "evexW0")
						}
					case "PP":
						row.OpBytes[header] = strings.ReplaceAll(row.OpBytes[header], "evex66", "evexF3")
					case "map":
						row.OpBytes[header] = strings.ReplaceAll(row.OpBytes[header], "evex0F38", "evex0F3A")
					case "VEX":
						row.ZCase = "Zvex_rm_v_r"
					case "offset":
						row.EncodingOffset++
					case "row index":
						row.RowIndex++
					case "short payload":
						row.OpBytes = row.OpBytes[:8]
					case "opcode extent":
						row.OpBytes[header+2] = "256"
					}
					if _, err := x86PackedAVXRowWitnesses(row); err == nil {
						t.Fatal("foreign compact/expand axis accepted", mutation, row)
					}
				}
				if found != 1 {
					t.Fatal("negative lost its complete official member", member, found)
				}
			})
		}
	}
}
