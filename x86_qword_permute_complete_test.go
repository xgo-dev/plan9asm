package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Independent inventory: Go's complete _yvpermq, not the translator's table.
// Intel SDM Vol.2C 5-522..525 and 5-529..532 specify five encodings per
// member, no X form or FP exception, and E4NF for every EVEX memory form.
func TestX86QwordPermuteCompleteOfficialRowsAndAttributes(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	classes := []string{
		"Yu8,Yym,Yyr", "Yi8,Yym,Yyr", "Yu8,YymEvex,YyrEvex",
		"Yu8,YymEvex,Yknot0,YyrEvex", "Yu8,Yzm,Yzr", "Yu8,Yzm,Yknot0,Yzr",
		"YymEvex,YyrEvex,YyrEvex", "YymEvex,YyrEvex,Yknot0,YyrEvex",
		"Yzm,Yzr,Yzr", "Yzm,Yzr,Yknot0,Yzr",
	}
	zcases := []string{"Zvex_i_rm_r", "Zvex_i_rm_r", "Zevex_i_rm_r", "Zevex_i_rm_k_r",
		"Zevex_i_rm_r", "Zevex_i_rm_k_r", "Zevex_rm_v_r", "Zevex_rm_v_k_r", "Zevex_rm_v_r", "Zevex_rm_v_k_r"}
	offsets := []int{0, 0, 2, 2, 5, 5, 8, 8, 11, 11}
	advances := []int{0, 2, 0, 3, 0, 3, 0, 3, 0, 3}
	for _, member := range []struct{ name, immediate, variable string }{
		{"VPERMQ", "0x00", "0x36"}, {"VPERMPD", "0x01", "0x16"},
	} {
		want := []string{
			"avxEscape | vex256 | vex66 | vex0F3A | vexW1", member.immediate,
			"avxEscape | evex256 | evex66 | evex0F3A | evexW1", "evexN32 | evexBcstN8 | evexZeroingEnabled", member.immediate,
			"avxEscape | evex512 | evex66 | evex0F3A | evexW1", "evexN64 | evexBcstN8 | evexZeroingEnabled", member.immediate,
			"avxEscape | evex256 | evex66 | evex0F38 | evexW1", "evexN32 | evexBcstN8 | evexZeroingEnabled", member.variable,
			"avxEscape | evex512 | evex66 | evex0F38 | evexW1", "evexN64 | evexBcstN8 | evexZeroingEnabled", member.variable,
		}
		count := 0
		for _, rule := range rules {
			if rule.Opcode != member.name {
				continue
			}
			if count >= len(classes) || rule.RowIndex != count || rule.Ytab != "_yvpermq" || rule.Prefix != "Pavx" ||
				strings.Join(rule.Classes, ",") != classes[count] || rule.ZCase != zcases[count] ||
				rule.EncodingOffset != offsets[count] || rule.ZOffset != advances[count] || !reflect.DeepEqual(rule.OpBytes, want) {
				t.Fatal("complete official qword-permute row/attribute changed", member.name, rule)
			}
			count++
		}
		if count != 10 {
			t.Fatal("official qword-permute denominator changed", member.name, count)
		}
	}
}

type x86QwordPermuteOracleRow struct {
	op, bank, mode, input string
	immediate             bool
}

func x86QwordPermuteOracleRows(arch string) []x86QwordPermuteOracleRow {
	var rows []x86QwordPermuteOracleRow
	for _, op := range []string{"VPERMQ", "VPERMPD"} {
		for _, bank := range []string{"Y", "Z"} {
			for _, immediate := range []bool{true, false} {
				for _, mode := range []string{"plain", "merge", "zero"} {
					if arch == "386" && mode != "plain" {
						continue // Go's named frontend rejects four operands; physical EVEX is separate.
					}
					for _, input := range []string{"register", "memory", "broadcast"} {
						rows = append(rows, x86QwordPermuteOracleRow{op, bank, mode, input, immediate})
					}
				}
			}
		}
	}
	return rows
}

func (row x86QwordPermuteOracleRow) width() int {
	if row.bank == "Z" {
		return 64
	}
	return 32
}

func (row x86QwordPermuteOracleRow) instruction() string {
	input, suffix, mask := row.bank+"0", "", ""
	if row.input != "register" {
		input = "(BX)"
	}
	if row.input == "broadcast" {
		suffix = ".BCST"
	}
	if row.mode != "plain" {
		mask = ",K1"
	}
	if row.mode == "zero" {
		suffix += ".Z"
	}
	operands := input + "," + row.bank + "1"
	if row.immediate {
		operands = "$216," + input
	}
	return row.op + suffix + " " + operands + mask + "," + row.bank + "2"
}

func TestX86QwordPermuteCompleteTypedByteEffects(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		rows := x86QwordPermuteOracleRows(arch)
		var source strings.Builder
		source.WriteString("TEXT effectrows(SB),4,$0-0\n")
		for _, row := range rows {
			fmt.Fprintln(&source, row.instruction())
		}
		source.WriteString("RET\n")
		x86LEAActualTargetGoObject(t, arch, x86AddressMemoryTargets(arch)[0], source.String())
		want := 72
		if arch == "386" {
			want = 24
		}
		if len(rows) != want {
			t.Fatal("complete independent shape denominator changed", arch, len(rows), want)
		}
		for _, row := range rows {
			t.Run(arch+"/"+row.instruction(), func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction())
				effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
				if !known || err != nil || !effect.requiresResultProof || effect.dynamicMemory ||
					effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 {
					t.Fatal("complete qword-permute shape lacks a mandatory typed/FLAGS owner", known, err)
				}
				sourceIndex, destination := 0, len(ins.Args)-1
				if row.immediate {
					sourceIndex = 1
				}
				seen := make(map[int]bool)
				for _, operand := range effect.operands {
					index := operand.index
					if index < 0 || index >= len(ins.Args) || seen[index] || !reflect.DeepEqual(operand.operand, ins.Args[index]) {
						t.Fatal("typed byte descriptor changed or duplicated an original operand", operand)
					}
					seen[index] = true
					width := row.width()
					if index == sourceIndex && row.input == "broadcast" || row.mode != "plain" && index == 2 {
						width = 8
					}
					read := index != destination || row.mode == "merge"
					if operand.width != int64(width) || operand.read != read || operand.write != (index == destination) {
						t.Fatal("data/control/mask/old-destination byte roles changed", operand)
					}
				}
				wantOperands := len(ins.Args)
				if row.immediate {
					wantOperands--
				}
				if len(seen) != wantOperands || row.immediate && seen[0] ||
					!x86TypedFPResultNeedsProof(Func{Instrs: []Instr{ins}}, FuncSig{Ret: Void}, arch) {
					t.Fatal("Void or immediate classification bypassed actual input obligations", seen)
				}
			})
		}
	}
}

// Immediate control is repeated per 256-bit block, not VPERMIL's 128-bit
// block. The oracle below is independent of the emitter's lane selector.
func x86QwordPermuteDefinedBytes(source uint64, width, selector int) uint64 {
	var defined uint64
	for output := 0; output < width; output++ {
		lane := output / 8
		selected := lane/4*4 + ((selector >> uint(2*(lane%4))) & 3)
		if source>>uint(selected*8+output%8)&1 != 0 {
			defined |= uint64(1) << uint(output)
		}
	}
	return defined
}

func TestX86QwordPermuteAllImmediateSelectorsAndEveryByte(t *testing.T) {
	for _, op := range []string{"VPERMQ", "VPERMPD"} {
		for _, bank := range []string{"Y", "Z"} {
			t.Run(op+"/"+bank, func(t *testing.T) {
				width := 32
				if bank == "Z" {
					width = 64
				}
				for selector := 0; selector < 256; selector++ {
					// Alternate a separate destination and a destructive data alias.
					destination := 2
					if selector&1 != 0 {
						destination = 0
					}
					ins := x86ScalarLaneInstruction(t, fmt.Sprintf("%s $%d,%s0,%s%d", op, selector, bank, bank, destination))
					for missing := -1; missing < width; missing++ {
						state := x86FMA3ResultInputState()
						if missing >= 0 {
							state.writeVector(0, 64, state.vectorBytes(0)&^(uint64(1)<<uint(missing)), false)
						}
						before := state.clone()
						defined := x86QwordPermuteDefinedBytes(state.vectorBytes(0), width, selector)
						want := before.clone()
						want.writeVector(destination, width, defined, false)
						if !x86ScalarFPResultTransfer(ins, &state, nil, 0, "amd64") || !reflect.DeepEqual(state, want) {
							t.Fatal("immediate selector invented bytes or lost upper aliases/FLAGS/DF/private state", selector, missing, destination)
						}
					}
				}
			})
		}
	}
}

func TestX86QwordPermuteVariableMaskAndMergeActualInputs(t *testing.T) {
	for _, row := range x86QwordPermuteOracleRows("amd64") {
		if row.input != "register" {
			continue
		}
		for destination := 0; destination < 3; destination++ {
			instruction := strings.TrimSuffix(row.instruction(), row.bank+"2") + fmt.Sprint(row.bank, destination)
			t.Run(instruction, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, instruction)
				for source := -1; source < 3; source++ {
					for missing := 0; missing < row.width(); missing++ {
						if source == -1 && (row.mode == "plain" || missing != 0) {
							continue
						}
						state := x86FMA3ResultInputState()
						if source == -1 {
							state.masks[1] = false
						} else {
							state.writeVector(source, 64, state.vectorBytes(source)&^(uint64(1)<<uint(missing)), false)
						}
						before := state.clone()
						accepted := x86ScalarFPResultTransfer(ins, &state, nil, 0, "amd64")
						if source == -1 || !row.immediate && (source == 0 || source == 1 && missing%8 == 0) {
							if accepted || !reflect.DeepEqual(state, before) {
								t.Fatal("missing actual mask/data/low control byte was invented or partly wrote state", source, missing)
							}
							continue
						}
						defined := x86CallerVectorByteMask(int64(row.width()))
						if row.immediate {
							defined = x86QwordPermuteDefinedBytes(before.vectorBytes(0), row.width(), 216)
						}
						if row.mode == "merge" {
							defined &= before.vectorBytes(destination)
						}
						want := before.clone()
						want.writeVector(destination, row.width(), defined, false)
						if !accepted || !reflect.DeepEqual(state, want) {
							t.Fatal("unused high control bits/zero old destination or selected data changed state", source, missing)
						}
					}
				}
			})
		}
	}
}
