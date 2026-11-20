package plan9asm

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86IFMACompleteIndependentGoRows(t *testing.T) {
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	opcodes := map[string]string{"VPMADD52HUQ": "0xB5", "VPMADD52LUQ": "0xB4"}
	counts := map[string]int{}
	for _, rule := range rules {
		opcode, wanted := opcodes[rule.Opcode]
		if !wanted {
			continue
		}
		index := counts[rule.Opcode]
		counts[rule.Opcode]++
		classes := []string{
			"YxmEvex,YxrEvex,YxrEvex", "YxmEvex,YxrEvex,Yknot0,YxrEvex",
			"YymEvex,YyrEvex,YyrEvex", "YymEvex,YyrEvex,Yknot0,YyrEvex",
			"Yzm,Yzr,Yzr", "Yzm,Yzr,Yknot0,Yzr",
		}
		var bytes []string
		for _, width := range []int{128, 256, 512} {
			bytes = append(bytes, fmt.Sprintf("avxEscape | evex%d | evex66 | evex0F38 | evexW1", width),
				fmt.Sprintf("evexN%d | evexBcstN8 | evexZeroingEnabled", width/8), opcode)
		}
		zcase, offset := "Zevex_rm_v_r", 0
		if index%2 != 0 {
			zcase, offset = "Zevex_rm_v_k_r", 3
		}
		if index >= 6 || rule.RowIndex != index || rule.Ytab != "_yvblendmpd" || rule.Prefix != "Pavx" ||
			rule.ZCase != zcase || rule.ZOffset != offset || rule.EncodingOffset != index/2*3 ||
			strings.Join(rule.Classes, ",") != classes[index] || !reflect.DeepEqual(rule.OpBytes, bytes) {
			t.Fatal("independent complete IFMA row/tuple attributes changed", rule)
		}
	}
	for name := range opcodes {
		if counts[name] != 6 {
			t.Fatal("complete IFMA family row denominator changed", counts)
		}
	}
	if len(amd64IFMASpecs) != 2 {
		t.Fatal("unaccounted IFMA operation")
	}
}

func TestX86IFMAEveryNumericalSourceAndAccumulatorByte(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, name := range []string{"VPMADD52HUQ", "VPMADD52LUQ"} {
			for _, bank := range []string{"X", "Y", "Z"} {
				ins := x86ScalarLaneInstruction(t, name+" "+bank+"0,"+bank+"1,"+bank+"2")
				width := amd64VectorByteWidth(ins.Args[2].Reg)
				for input := 0; input < 3; input++ {
					for missing := -1; missing < width; missing++ {
						state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionEither}
						for register := 0; register < 3; register++ {
							state.writeVector(register, 64, ^uint64(0), false)
						}
						state.pointerGP[6], state.gp[3], state.masks[1] = true, 0x55, true
						if missing >= 0 {
							state.writeVector(input, 64, state.vectorBytes(input)&^(uint64(1)<<uint(missing)), false)
						}
						want := state.clone()
						defined := x86CallerVectorByteMask(int64(width))
						if missing >= 0 && (input == 2 || missing%8 != 7) {
							defined &^= uint64(0xff) << uint(missing/8*8)
						}
						want.writeVector(2, width, defined, false)
						accepted, known := x86ResultIFMAStep(ins, &state, nil, arch)
						if !known || !accepted || !reflect.DeepEqual(state, want) {
							t.Fatal("IFMA invented numerical bytes, lost meaningful subwords or changed independent state",
								arch, name, bank, input, missing)
						}
					}
				}
			}
		}
	}
}

func TestX86IFMAZeroingStillReadsTheActualAccumulator(t *testing.T) {
	for _, name := range []string{"VPMADD52HUQ", "VPMADD52LUQ"} {
		for _, bank := range []string{"X", "Y", "Z"} {
			ins := x86ScalarLaneInstruction(t, name+".Z "+bank+"0,"+bank+"1,K1,"+bank+"2")
			state := x86ResultState{flags: x86ByteFlagsAll}
			state.writeVector(0, 64, ^uint64(0), false)
			state.writeVector(1, 64, ^uint64(0), false)
			state.masks[1] = true
			accepted, known := x86ResultIFMAStep(ins, &state, nil, "amd64")
			width := amd64VectorByteWidth(ins.Args[3].Reg)
			if !known || !accepted || state.vectorBytes(2)&x86CallerVectorByteMask(int64(width)) != 0 ||
				state.flags != x86ByteFlagsAll {
				t.Fatal("EVEX.z supplied the missing arithmetic accumulator or changed FLAGS", name, bank)
			}
		}
	}
}

func TestX86IFMAEncodedUpperWritesCannotPreserveStaleAliases(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		var source, declarations strings.Builder
		var names []string
		for _, name := range []string{"VPMADD52HUQ", "VPMADD52LUQ"} {
			for _, bank := range []string{"X", "Y"} {
				for _, raw := range []bool{false, true} {
					for _, mode := range []string{"plain", "merge", "zero"} {
						if target.arch == "386" && !raw && mode != "plain" {
							continue // Named frontend rejects these; raw physical rows are retained.
						}
						op, mask := name, ""
						if mode != "plain" {
							mask = "K1,"
						}
						if mode == "zero" {
							op += ".Z"
						}
						instruction := op + " " + bank + "0," + bank + "1," + mask + bank + "2"
						if raw {
							encoderArch := target.arch
							if mode != "plain" {
								encoderArch = "amd64"
							}
							instruction = x86RawNumericalInstruction(t, encoderArch, instruction)
						}
						function := fmt.Sprint("Upper", len(names))
						names = append(names, function)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-4\nVPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\n"+
							"MOVL $-1,AX\nVPBROADCASTD AX,Z2\nMOVL $0,AX\nKMOVD AX,K1\n%s\n"+
							"VEXTRACTI32X4 $3,Z2,X3\nPEXTRD $0,X3,AX\nMOVL AX,ret+0(FP)\nRET\n", function, instruction)
						fmt.Fprintf(&declarations, "func %s()uint32\n", function)
					}
				}
			}
		}
		x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
			if err != nil {
				t.Fatal("complete IFMA upper-alias source lost its initialized inputs", target, api, err)
			}
			x86VectorUpperRequireZeroReturns(t, ir, names)
		}
	}
}
