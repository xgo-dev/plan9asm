package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Independent Go and ISA directory. The signed legacy/VEX family and raw FP16
// conversions retain their own owners. EVEX.W1 is WIG in non-64-bit mode.
var x86UnsignedScalarIntegerFloatOracle = []struct {
	op            string
	input, output int
	rounding      bool
}{
	{"VCVTUSI2SDL", 4, 8, false}, {"VCVTUSI2SDQ", 8, 8, true},
	{"VCVTUSI2SSL", 4, 4, true}, {"VCVTUSI2SSQ", 8, 4, true},
}

type x86UnsignedScalarIntegerFloatRow struct {
	op, control, source string
	input, output       int
	upper, destination  int
}

func x86UnsignedScalarIntegerFloatRows(arch string) []x86UnsignedScalarIntegerFloatRow {
	var rows []x86UnsignedScalarIntegerFloatRow
	for _, member := range x86UnsignedScalarIntegerFloatOracle {
		input := member.input
		if arch == "386" {
			input = 4
		}
		base := x86UnsignedScalarIntegerFloatRow{op: member.op, input: input, output: member.output, upper: 0, destination: 1}
		for _, source := range []string{"GP", "FP", "native"} {
			row := base
			row.source = source
			rows = append(rows, row)
		}
		if member.rounding {
			for _, control := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
				row := base
				row.source, row.control = "GP", control
				rows = append(rows, row)
			}
		}
		alias := base
		alias.source, alias.upper = "GP", alias.destination
		rows = append(rows, alias)
		if arch == "amd64" {
			high := base
			high.source, high.upper, high.destination = "GP", 29, 30
			rows = append(rows, high)
		}
	}
	return rows
}

func (row x86UnsignedScalarIntegerFloatRow) instruction() string {
	source := "CX"
	if row.source == "FP" {
		source = "value+0(FP)"
	} else if row.source == "native" {
		source = "(BX)"
	}
	op := row.op
	if row.control != "" {
		op += "." + row.control
	}
	return fmt.Sprintf("%s %s,X%d,X%d", op, source, row.upper, row.destination)
}

func TestX86UnsignedScalarIntegerFloatCompleteIndependentGoRows(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]int)
	for _, rule := range rules {
		if !strings.HasPrefix(rule.Opcode, "VCVTUSI2S") {
			continue
		}
		counts[rule.Opcode]++
		var input, output int
		var rounding bool
		for _, member := range x86UnsignedScalarIntegerFloatOracle {
			if rule.Opcode == member.op {
				input, output, rounding = member.input, member.output, member.rounding
			}
		}
		if input == 0 {
			t.Fatal("new official unsigned scalar member is absent from the independent directory", rule)
		}
		prefix, width := "evexF3", "evexW0"
		if output == 8 {
			prefix = "evexF2"
		}
		if input == 8 {
			width = "evexW1"
		}
		attributes := fmt.Sprintf("evexN%d", input)
		if rounding {
			attributes += " | evexRoundingEnabled"
		}
		if rule.RowIndex != 0 || rule.Ytab != "_yvcvtusi2sdl" || rule.Prefix != "Pavx" ||
			rule.ZCase != "Zevex_rm_v_r" || rule.ZOffset != 3 || rule.EncodingOffset != 0 ||
			strings.Join(rule.Classes, ",") != "Yml,YxrEvex,YxrEvex" ||
			!reflect.DeepEqual(rule.OpBytes, []string{"avxEscape | evex128 | " + prefix + " | evex0F | " + width, attributes, "0x7B"}) {
			t.Fatal("complete unsigned scalar Go row or opcode controls changed", rule)
		}
	}
	if !reflect.DeepEqual(counts, map[string]int{"VCVTUSI2SDL": 1, "VCVTUSI2SDQ": 1, "VCVTUSI2SSL": 1, "VCVTUSI2SSQ": 1}) {
		t.Fatal("complete unsigned scalar Go family changed", counts)
	}
}

func TestX86UnsignedScalarIntegerFloatExactFPWidthsAndControls(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86UnsignedScalarIntegerFloatRows(arch) {
			if row.source != "FP" {
				continue
			}
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.instruction())
				for index := range ins.Args {
					width, write, known := X86FPAccessBytes(ins, index, arch)
					if index == 0 {
						if !known || write || width != int64(row.input) {
							t.Fatal("unsigned source lost its actual scalar width or acquired a write", width, write, known)
						}
					} else if known || width != 0 || write {
						t.Fatal("upper/destination acquired an FP memory access", index)
					}
				}
			})
		}
	}
}

func TestX86UnsignedScalarIntegerFloatEveryByteAndIndependentState(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, member := range x86UnsignedScalarIntegerFloatOracle {
			input := member.input
			if arch == "386" {
				input = 4
			}
			for _, source := range []string{"GP", "FP"} {
				for missing := -1; missing < input; missing++ {
					t.Run(fmt.Sprintf("%s/%s/%s/missing%d", arch, member.op, source, missing), func(t *testing.T) {
						row := x86UnsignedScalarIntegerFloatRow{op: member.op, source: source, upper: 0, destination: 1}
						ins := x86ScalarLaneInstruction(t, row.instruction())
						state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward,
							fp: make([]bool, 16), auto: make([]bool, 8)}
						owned := make([]bool, 16)
						for index := range owned {
							state.fp[index], owned[index] = true, true
							if index < len(state.auto) {
								state.auto[index] = true
							}
						}
						state.gp[1], state.xmm[0], state.xmm[1] = 0xff, 0xa5c3, 0xffff
						state.vectorUpper[1], state.pointerGP[7], state.masks[2] = 0x123456780000, true, true
						if missing >= 0 {
							if source == "FP" {
								state.fp[missing] = false
							} else {
								state.gp[1] &^= 1 << uint(missing)
							}
						}
						before, expected := state.clone(), state.clone()
						low := x86CallerVectorByteMask(int64(member.output))
						expected.writeVector(1, 16, low|state.vectorBytes(0)&(0xffff&^low), false)
						accepted := x86ResultTransfer(ins, &state, owned, 0, arch)
						if accepted != (missing < 0) || accepted && !reflect.DeepEqual(state, expected) ||
							!accepted && !reflect.DeepEqual(state, before) {
							t.Fatal("unsigned conversion lost an actual input, sparse upper bytes, alias clearing or unrelated state", accepted, missing)
						}
					})
				}
			}
		}
	}
}
