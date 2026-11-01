package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type x86IntegerSelfCompareCase struct {
	row                string
	width              int
	legacy, maskResult bool
	masked, maskAlias  bool
}

// Enumerate the two complete Go comparison families independently of their
// implementation maps. The original row/attribute tests own the full tables.
func x86IntegerSelfCompareCases(arch string) []x86IntegerSelfCompareCase {
	var rows []x86IntegerSelfCompareCase
	for _, op := range []string{"PCMPEQB", "PCMPEQW", "PCMPEQL", "PCMPEQQ", "PCMPGTB", "PCMPGTW", "PCMPGTL", "PCMPGTQ"} {
		rows = append(rows, x86IntegerSelfCompareCase{row: op + " X6,X6", width: 16, legacy: true})
		vector := "V" + strings.ReplaceAll(op, "L", "D")
		for _, bank := range []string{"X", "Y"} {
			width := 16
			if bank == "Y" {
				width = 32
			}
			for _, destination := range []string{bank + "2", bank + "6"} {
				rows = append(rows, x86IntegerSelfCompareCase{
					row: fmt.Sprintf("%s %s6,%s6,%s", vector, bank, bank, destination), width: width,
				})
			}
		}
		for _, bank := range []string{"X", "Y", "Z"} {
			width := map[string]int{"X": 16, "Y": 32, "Z": 64}[bank]
			rows = append(rows, x86IntegerSelfCompareCase{
				row: fmt.Sprintf("%s %s6,%s6,K0", vector, bank, bank), width: width, maskResult: true,
			})
			if arch == "amd64" {
				for _, maskAlias := range []bool{false, true} {
					destination := "K0"
					if maskAlias {
						destination = "K1"
					}
					rows = append(rows, x86IntegerSelfCompareCase{
						row:   fmt.Sprintf("%s %s6,%s6,K1,%s", vector, bank, bank, destination),
						width: width, maskResult: true, masked: true, maskAlias: maskAlias,
					})
				}
			}
		}
	}
	if arch == "amd64" {
		for _, op := range x86ImmediateCompareResultMembers {
			for _, bank := range []string{"X", "Y", "Z"} {
				for _, immediate := range []int{0, 1, 2, 3, 4, 5, 6, 7, 128, 255} {
					for _, masked := range []bool{false, true} {
						mask := ""
						if masked {
							mask = "K1,"
						}
						rows = append(rows, x86IntegerSelfCompareCase{
							row:   fmt.Sprintf("%s $%d,%s6,%s6,%sK0", op, immediate, bank, bank, mask),
							width: map[string]int{"X": 16, "Y": 32, "Z": 64}[bank], maskResult: true, masked: masked,
						})
					}
				}
			}
		}
	}
	return rows
}

func TestX86IntegerSelfCompareIndependentImmediateAndBankAxes(t *testing.T) {
	for _, op := range x86ImmediateCompareResultMembers {
		for _, bank := range []string{"X", "Y", "Z"} {
			t.Run(op+"/"+bank, func(t *testing.T) {
				var source strings.Builder
				source.WriteString("TEXT f(SB),4,$0-0\n")
				check := func(immediate, register int) {
					row := fmt.Sprintf("%s $%d,%s%d,%s%d,K0", op, immediate, bank, register, bank, register)
					ins := x86ScalarLaneInstruction(t, row)
					state := x86ResultState{}
					if !x86ResultTransfer(ins, &state, nil, 0, "amd64") || !state.masks[0] {
						t.Fatal("independent imm8/register axis lost its same-view result", row)
					}
					source.WriteString(row + "\n")
				}
				for immediate := 0; immediate < 256; immediate++ {
					check(immediate, 6)
				}
				for register := 0; register < 32; register++ {
					check(0, register)
				}
				source.WriteString("RET\n")
				code := x86PackedShiftActualGoBytes(t, "amd64", source.String())
				if len(code) != (256+32)*7+1 || code[len(code)-1] != 0xc3 {
					t.Fatal("original complete EVEX register/imm8 byte layout changed", len(code))
				}
				for immediate := 0; immediate < 256; immediate++ {
					if code[7*immediate] != 0x62 || code[7*immediate+6] != byte(immediate) {
						t.Fatal("original Go encoded a different imm8", immediate)
					}
				}
			})
		}
	}
}

func TestX86IntegerSelfCompareCompleteNumericalEffects(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		rows := x86IntegerSelfCompareCases(arch)
		var original strings.Builder
		original.WriteString("TEXT f(SB),4,$0-0\n")
		for _, row := range rows {
			original.WriteString(row.row + "\n")
		}
		original.WriteString("RET\n")
		goAssemblerOracleOutput(t, arch, original.String(), "", true)
		for _, row := range rows {
			t.Run(arch+"/"+row.row, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, row.row)
				effect, known, err := x86TypedPackedIntegerCompareByteEffect(ins.Op, ins, arch)
				if !known || err != nil {
					t.Fatal("complete comparison descriptor", effect, err)
				}
				for _, operand := range effect.operands {
					if operand.read && operand.operand.Kind == OpReg && !amd64IsKOperand(operand.operand) {
						t.Fatal("typed descriptor retains a value dependency on identical integer inputs")
					}
				}
				for _, consumer := range x86ResultGPSIMDConsumers {
					for _, seeded := range []bool{false, true} {
						state := x86ResultState{direction: x86ResultDirectionBackward}
						state.masks[1] = row.masked
						if seeded {
							state.vectorUpper[6], state.vectorUpper[2] = 1<<63, 1<<60
							state.flags, state.pointerGP[7] = x86ByteFlagsAll, true
						}
						want := state.clone()
						if row.maskResult {
							index := 0
							if row.maskAlias {
								index = 1
							}
							want.masks[index] = true
						} else {
							index := 2
							if row.legacy || strings.HasSuffix(row.row, "6") {
								index = 6
							}
							want.writeVector(index, row.width, x86CallerVectorByteMask(int64(row.width)), row.legacy)
						}
						if !consumer.step(ins, &state, nil, 0, arch) || !reflect.DeepEqual(state, want) {
							t.Fatal("same physical integer inputs retained a false numerical dependency or changed unrelated state", consumer.name, seeded)
						}
					}
				}
			})
		}
	}
}

func TestX86IntegerSelfCompareOriginalIdiomThreeAPIsFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		register := "X14"
		if target.arch == "386" {
			register = "X6"
		}
		source := "TEXT Value(SB),4,$0-4\nPCMPEQL " + register + "," + register +
			"\nPEXTRD $0," + register + ",AX\nMOVL AX,ret+0(FP)\nRET\n"
		t.Run(target.triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32", target.arch, target.triple, api)
				if err != nil {
					t.Fatal("original self-comparison initialization idiom needs no incoming vector value", api, err)
				}
				x86ScalarFPNamedConstantResult(t, ir, "Value", []uint64{0xffffffff})
				for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86IntegerSelfCompareRetainsInputAndSourceBoundaries(t *testing.T) {
	for _, row := range []string{
		"PCMPEQL X5,X6", "PCMPGTL X5,X6", "VPCMPEQD X5,X6,X2", "VPCMPGTQ Y5,Y6,Y2",
		"VPCMPEQB Z5,Z6,K0", "VPCMPD $3,Z5,Z6,K0", "VPCMPUQ $7,Z5,Z6,K0",
		"PCMPEQL (AX),X6", "VPCMPEQD (AX),Z6,K0", "VPCMPQ $0,(AX),Z6,K0",
		"VPCMPEQD X6,X6,K1,K0", "VPCMPB $0,Z6,Z6,K1,K0",
		"CMPPS X6,X6,$0", "VCMPPS $0,Y6,Y6,Y2",
	} {
		t.Run(row, func(t *testing.T) {
			for _, consumer := range x86ResultGPSIMDConsumers {
				state := x86ResultState{flags: x86ByteFlagsAll, pointerGP: [16]bool{0: true}}
				before := state.clone()
				if consumer.step(x86ScalarLaneInstruction(t, row), &state, nil, 0, "amd64") || !reflect.DeepEqual(state, before) {
					t.Fatal("self-comparison supplied another input, mask, memory or floating-point role", consumer.name)
				}
			}
		})
	}
	for _, mutation := range []string{"encoded", "raw origin", "address size", "unbound address", "segment", "raw return"} {
		t.Run(mutation, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, "PCMPEQL X6,X6")
			switch mutation {
			case "encoded":
				ins.x86Encoded = true
			case "raw origin":
				ins.x86SourceRaw = &x86SourceRawInstruction{op: "PCMPEQL"}
			case "address size":
				ins.x86AddressBits = 32
			case "unbound address":
				ins.x86UnboundAddressOverride = true
			case "segment":
				ins.x86SegmentPrefix = 0x64
			case "raw return":
				ins.x86RawNearReturn = new(x86RawNearReturnForm)
			}
			state := x86ResultState{}
			if x86ResultTransfer(ins, &state, nil, 0, "amd64") {
				t.Fatal("named numerical identity manufactured a physical source role")
			}
		})
	}
}
