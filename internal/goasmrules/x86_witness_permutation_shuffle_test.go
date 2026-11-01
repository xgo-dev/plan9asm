package goasmrules

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

const x86PermutationShuffleTestNames = `VPERMILPD VPERMILPS VPERMPD VPERMQ
	VPERMD VPERMPS VPERM2F128 VPERM2I128
	VSHUFF32X4 VSHUFF64X2 VSHUFI32X4 VSHUFI64X2`

func TestX86PermutationShuffleCompleteOriginalRows(t *testing.T) {
	legacy, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string][2]int{
		"VPERMILPD": {18, 66}, "VPERMILPS": {18, 66},
		"VPERMPD": {10, 40}, "VPERMQ": {10, 40},
		"VPERMD": {5, 20}, "VPERMPS": {5, 20},
		"VPERM2F128": {1, 2}, "VPERM2I128": {1, 2},
		"VSHUFF32X4": {4, 18}, "VSHUFF64X2": {4, 18},
		"VSHUFI32X4": {4, 18}, "VSHUFI64X2": {4, 18},
	}
	originals := map[string]X86AVXRule{}
	for index, rule := range avx {
		if _, found := expected[rule.Opcode]; found {
			originals[fmt.Sprintf("avx/%d/%s/%s/%d", index, rule.Opcode, rule.Ytab, rule.RowIndex)] = rule
		}
	}
	if len(originals) != 84 || len(strings.Fields(x86PermutationShuffleTestNames)) != 12 {
		t.Fatal("complete source closure changed", len(originals))
	}
	for _, entry := range legacy.Optab {
		if _, found := expected[entry.Opcode]; found {
			t.Fatal("AVX permutation closure acquired a legacy source row", entry)
		}
	}
	// Current helper: the first real RED must be a genuine format limitation,
	// not a missing future join API or an uninitialized synthetic program.
	rows, err := x86PackedBinaryRows(legacy, avx, x86PermutationShuffleTestNames)
	if err != nil {
		t.Fatal(err)
	}
	seen, spellings, members := map[string]bool{}, map[string]bool{}, map[string][2]int{}
	for _, row := range rows {
		rule, found := originals[row.ID]
		if !found || seen[row.ID] || rule.Opcode != row.Opcode {
			t.Fatal("lost original source row identity", row)
		}
		seen[row.ID] = true
		count := members[row.Opcode]
		count[0]++
		for _, witness := range row.Witnesses {
			fields := strings.Fields(witness.Instruction)
			if len(fields) != 2 || spellings[witness.Instruction] || witness.MaskResult {
				t.Fatal("duplicate or foreign permutation result", row.ID, witness)
			}
			args := strings.Split(fields[1], ",")
			if len(args) != len(rule.Classes) || len(witness.Encoding) == 0 {
				t.Fatal("incomplete original operand/encoding witness", row.ID, witness)
			}
			immediate := rule.Classes[0] == "Yu8" || rule.Classes[0] == "Yi8"
			first := 0
			if immediate {
				first = 1
				literal := "$7"
				if rule.Classes[0] == "Yi8" {
					literal = "$-1"
				}
				encoded := byte(7)
				if rule.Classes[0] == "Yi8" {
					encoded = 255
				}
				if args[0] != literal || witness.Encoding[len(witness.Encoding)-1] != encoded {
					t.Fatal("signed/unsigned source rows or imm8 transport merged", row.ID, witness)
				}
			}
			masked := strings.Contains(strings.Join(rule.Classes, ","), "Yknot0")
			unary := immediate && len(rule.Classes) == 3 || immediate && masked && len(rule.Classes) == 4
			width := map[string]int{"Yxm": 128, "YxmEvex": 128, "Yym": 256, "YymEvex": 256, "Yzm": 512}[rule.Classes[first]]
			if len(args) != len(rule.Classes) || witness.Width != width || witness.Masked != masked || masked && args[len(args)-2] != "K1" ||
				witness.First != args[first] || witness.Destination != args[len(args)-1] ||
				witness.Memory != (witness.First == "(AX)") ||
				witness.Zeroing != strings.Contains(fields[0], ".Z") || witness.Zeroing && !masked ||
				witness.Broadcast != strings.Contains(fields[0], ".BCST") || witness.Broadcast && !witness.Memory ||
				unary && witness.Second != "" || !unary && witness.Second != args[first+1] {
				t.Fatal("source/control/result roles or width/tuple/mask were confused", row.ID, witness)
			}
			spellings[witness.Instruction] = true
			count[1]++
		}
		members[row.Opcode] = count
	}
	if len(seen) != 84 || len(spellings) != 328 || len(members) != 12 {
		t.Fatal("complete row/witness closure changed", len(seen), len(spellings), len(members))
	}
	for name, want := range expected {
		if members[name] != want {
			t.Fatal("member lost original rows or controls", name, members[name], want)
		}
	}
}

func TestX86PermutationShuffleRejectsForeignPhysicalAxes(t *testing.T) {
	avx, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	names := " " + strings.Join(strings.Fields(x86PermutationShuffleTestNames), " ") + " "
	count := 0
	for _, original := range avx {
		if !strings.Contains(names, " "+original.Opcode+" ") {
			continue
		}
		if _, err := x86PackedAVXRowWitnesses(original); err != nil {
			t.Fatal("negative control has no valid original", original, err)
		}
		for _, axis := range []string{"prefix", "table", "ordinal", "offset", "stride", "source", "destination", "header", "payload", "mask", "W", "tuple", "broadcast"} {
			t.Run(fmt.Sprintf("%s/%d/%s", original.Opcode, original.RowIndex, axis), func(t *testing.T) {
				changed := original
				changed.Classes = append([]string(nil), original.Classes...)
				changed.OpBytes = append([]string(nil), original.OpBytes...)
				switch axis {
				case "prefix":
					changed.Prefix = "Pm"
				case "table":
					changed.Ytab = "_foreign_permutation"
				case "ordinal":
					changed.RowIndex += 1000
				case "offset":
					changed.EncodingOffset++
				case "stride":
					changed.ZOffset++
				case "source":
					changed.Classes[0] = "Yrl"
				case "destination":
					changed.Classes[len(changed.Classes)-1] = "Yk"
				case "header":
					changed.OpBytes[changed.EncodingOffset] += "|foreignPermutationAxis"
				case "payload":
					index := changed.EncodingOffset + 1
					if strings.HasPrefix(changed.ZCase, "Zevex_") {
						index++
					}
					changed.OpBytes[index] = "0x100"
				case "mask":
					changed.Classes = append(changed.Classes, "Yknot0")
				case "W":
					header := changed.OpBytes[changed.EncodingOffset]
					if strings.Contains(header, "W0") {
						header = strings.Replace(header, "W0", "W1", 1)
					} else {
						header = strings.Replace(header, "W1", "W0", 1)
					}
					changed.OpBytes[changed.EncodingOffset] = header
				case "tuple", "broadcast":
					if strings.HasPrefix(changed.ZCase, "Zevex_") {
						index := changed.EncodingOffset + 1
						if axis == "tuple" {
							changed.OpBytes[index] = strings.ReplaceAll(changed.OpBytes[index], "evexN", "foreignN")
						} else {
							changed.OpBytes[index] = strings.ReplaceAll(changed.OpBytes[index], "evexBcstN", "foreignBcstN")
						}
					} else {
						changed.OpBytes[changed.EncodingOffset] += "|evexN16"
					}
				}
				if witnesses, err := x86PackedAVXRowWitnesses(changed); err == nil {
					t.Fatal("foreign physical axis silently accepted", axis, changed, witnesses)
				}
			})
		}
		count++
	}
	if count != 84 {
		t.Fatal("foreign-axis controls lost original source rows", count)
	}
}
