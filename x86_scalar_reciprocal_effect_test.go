package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// Independent complete estimate family; RCP14/28 are different ISA classes.
var x86ScalarReciprocalOracle = []struct {
	op     string
	opcode byte
	vector bool
}{
	{"RCPSS", 0x53, false}, {"RSQRTSS", 0x52, false},
	{"VRCPSS", 0x53, true}, {"VRSQRTSS", 0x52, true},
}

func TestX86ScalarReciprocalCompleteIndependentGoRowsAndTypedEffects(t *testing.T) {
	legacy, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(legacy), "var yxm = []ytab{\n\t{Zm_r_xm, 1, argList{Yxm, Yxr}},\n}") {
		t.Fatal("complete legacy reciprocal input grammar changed")
	}
	for _, row := range x86ScalarReciprocalOracle[:2] {
		if want := fmt.Sprintf("{A%s, yxm, Pf3, opBytes{0x%02x}}", row.op, row.opcode); !strings.Contains(string(legacy), want) {
			t.Fatal("independent legacy reciprocal opcode/prefix changed", want)
		}
	}
	rules, err := goasmrules.LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, rule := range rules {
		if rule.Opcode != "VRCPSS" && rule.Opcode != "VRSQRTSS" {
			continue
		}
		counts[rule.Opcode]++
		code := "0x53"
		if rule.Opcode == "VRSQRTSS" {
			code = "0x52"
		}
		if rule.RowIndex != 0 || rule.Ytab != "_yvrcpss" || rule.Prefix != "Pavx" ||
			rule.ZCase != "Zvex_rm_v_r" || rule.ZOffset != 2 || rule.EncodingOffset != 0 ||
			strings.Join(rule.Classes, ",") != "Yxm,Yxr,Yxr" ||
			!reflect.DeepEqual(rule.OpBytes, []string{"avxEscape | vex128 | vexF3 | vex0F | vexW0", code}) {
			t.Fatal("complete independent VEX reciprocal row changed", rule)
		}
	}
	if !reflect.DeepEqual(counts, map[string]int{"VRCPSS": 1, "VRSQRTSS": 1}) {
		t.Fatal("scalar reciprocal has no EVEX, mask or packed-width row", counts)
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86ScalarReciprocalOracle {
			for _, source := range []string{"X0", "value+0(FP)", "(AX)"} {
				t.Run(arch+"/"+row.op+"/"+source, func(t *testing.T) {
					args := source + ",X2"
					if row.vector {
						args = source + ",X1,X2"
					}
					ins := x86ScalarLaneInstruction(t, row.op+" "+args)
					effect, known, err := x86TypedInstructionByteEffect(ins.Op, ins, arch)
					if !known || err != nil || !effect.requiresResultProof || effect.dynamicMemory ||
						effect.flagsRead != 0 || effect.flagsDefined != 0 || effect.flagsKilled != 0 || len(effect.operands) != len(ins.Args) {
						t.Fatal("complete scalar reciprocal typed source/upper/write effect missing", effect, known, err)
					}
					for index, operand := range effect.operands {
						width := int64(16)
						if index == 0 {
							width = 4
						}
						if operand.index != index || !reflect.DeepEqual(operand.operand, ins.Args[index]) || operand.width != width ||
							operand.read != (index < len(ins.Args)-1 || !row.vector) || operand.write != (index == len(ins.Args)-1) {
							t.Fatal("scalar source width or independent upper-half role changed", operand)
						}
					}
				})
			}
		}
	}
}

func TestX86ScalarReciprocalSelectedBytesUpperAliasesAndUnrelatedState(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86ScalarReciprocalOracle {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				args, base := "X0,X2", 2
				if row.vector {
					args, base = "X0,X1,X2", 1
				}
				ins := x86ScalarLaneInstruction(t, row.op+" "+args)
				for sourceMissing := -1; sourceMissing < 16; sourceMissing++ {
					for upperMissing := -1; upperMissing < 16; upperMissing++ {
						state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
						state.xmm[0], state.xmm[base], state.vectorUpper[2] = 0xffff, 0xffff, 0x55aa00ffff000000
						state.pointerGP[7], state.masks[1] = true, true
						if sourceMissing >= 0 {
							state.xmm[0] &^= 1 << uint(sourceMissing)
						}
						if upperMissing >= 0 {
							state.xmm[base] &^= 1 << uint(upperMissing)
						}
						before, want := state.clone(), state.clone()
						computed := uint16(0xf)
						if sourceMissing >= 0 && sourceMissing < 4 {
							computed = 0 // Unknown scalar stays unknown, never an implementation zero.
						}
						want.xmm[2] = state.xmm[base]&0xfff0 | computed
						if row.vector {
							want.vectorUpper[2] = ^uint64(0xffff)
						}
						if !x86ResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, want) {
							t.Fatal("scalar estimate invented numerical input/upper bytes or altered FLAGS/DF/storage", sourceMissing, upperMissing, before, state, want)
						}
					}
				}
			})
		}
	}
}

func TestX86ScalarReciprocalInitializedPublicInputsAndMXCSRSource(t *testing.T) {
	for _, row := range x86ScalarReciprocalOracle {
		for _, memory := range []bool{false, true} {
			t.Run(fmt.Sprint(row.op, "/memory=", memory), func(t *testing.T) {
				scalar, load := "(AX)", ""
				if !memory {
					scalar, load = "X0", "MOVSS (AX),X0\n"
				}
				args, destination := scalar+",X1", "X1"
				if row.vector {
					args, destination = scalar+",X1,X2", "X2"
				}
				source := "TEXT ·Value(SB),4,$0-24\nMOVQ out+0(FP),DI\nMOVQ p+8(FP),AX\nMOVQ upper+16(FP),BX\n" +
					"MOVUPS (BX),X1\nSTC\n" + load + row.op + " " + args + "\nMOVUPS " + destination +
					",(DI)\nSETCS 16(DI)\nSTMXCSR 20(DI)\nRET\n"
				declaration := "func Value(out *[24]byte,p *uint32,upper *[16]byte)\n"
				goAssemblerOracleOutput(t, "amd64", source, "", true)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						if _, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api); err != nil {
							t.Fatal("valid complete scalar estimate source with observable MXCSR rejected", err)
						}
						missing := strings.Replace(source, "MOVQ p+8(FP),AX\n", "", 1)
						if _, err := x86ScalarFPBitViewAPI(t, missing, declaration, "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("scalar estimate supplied its own native input", err)
						}
						missing = strings.Replace(source, "MOVQ out+0(FP),DI\n", "", 1)
						if _, err := x86ScalarFPBitViewAPI(t, missing, declaration, "amd64", "x86_64-unknown-linux-gnu", api); !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("scalar estimate supplied its own result/MXCSR destination", err)
						}
					})
				}
			})
		}
	}
}
