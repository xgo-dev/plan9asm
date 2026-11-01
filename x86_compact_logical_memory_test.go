package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86CompactExpandLogicalMemoryAvailability(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, opcode := range x86CompactExpandResultMembers {
			expand := strings.Contains(opcode, "EXPAND")
			modes := []string{"unmasked", "merge"}
			if expand {
				modes = append(modes, "zero")
			}
			for _, width := range []struct {
				bank  string
				bytes int
			}{{"X", 16}, {"Y", 32}, {"Z", 64}} {
				for _, mode := range modes {
					t.Run(arch+"/"+opcode+"/"+width.bank+"/"+mode, func(t *testing.T) {
						row := x86CompactExpandResultInstruction(opcode, width.bank, mode)
						from, to := width.bank+"1", "ret+0(FP)"
						if expand {
							from, to = width.bank+"0", "input+0(FP)"
						}
						instruction := x86ScalarLaneInstruction(t, strings.Replace(row, from, to, 1))
						state := x86ResultState{fp: make([]bool, width.bytes), masks: [8]bool{1: mode != "unmasked"},
							flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
						owned := make([]bool, width.bytes)
						for index := range owned {
							owned[index] = true
							state.fp[index] = expand || mode != "unmasked"
						}
						state.writeVector(0, 64, ^uint64(0), false)
						state.writeVector(1, 64, ^uint64(0), false)
						before, expected := state.clone(), state.clone()
						boundary := int64(0)
						if expand {
							boundary = int64(width.bytes)
							expected.writeVector(1, width.bytes, x86CallerVectorByteMask(int64(width.bytes)), false)
						} else {
							for index := range expected.fp {
								expected.fp[index] = true
							}
						}
						if !x86ResultTransfer(instruction, &state, owned, boundary, arch) || !reflect.DeepEqual(state, expected) {
							t.Fatal("complete logical memory bytes did not produce the exact family effect", instruction.Raw)
						}
						if expand || mode != "unmasked" {
							for missing := range before.fp {
								partial := before.clone()
								partial.fp[missing] = false
								unchanged := partial.clone()
								if x86ResultTransfer(instruction, &partial, owned, boundary, arch) || !reflect.DeepEqual(partial, unchanged) {
									t.Fatal("unknown memory byte became an active read or guaranteed masked write", missing)
								}
							}
						}
						for missing := range owned {
							partialOwned := append([]bool(nil), owned...)
							partialOwned[missing] = false
							partial := before.clone()
							if x86ResultTransfer(instruction, &partial, partialOwned, boundary, arch) || !reflect.DeepEqual(partial, before) {
								t.Fatal("missing field changed part of a rejected logical memory transfer", missing)
							}
						}
						if !expand {
							partial := before.clone()
							if x86ResultTransfer(instruction, &partial, owned, int64(width.bytes), arch) || !reflect.DeepEqual(partial, before) {
								t.Fatal("compact store acquired write permission for incoming FP parameters")
							}
						}
					})
				}
			}
		}
	}
}

func TestX86PackedExpandLogicalFPAcrossScalarFieldsThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, opcode := range []string{"VEXPANDPS", "VEXPANDPD", "VPEXPANDB", "VPEXPANDW", "VPEXPANDD", "VPEXPANDQ"} {
			for _, width := range []struct {
				bank  string
				bytes int
			}{{"X", 16}, {"Y", 32}, {"Z", 64}} {
				for _, mode := range []string{"unmasked", "merge", "zero"} {
					var arguments []string
					for index := 0; index < width.bytes/8; index++ {
						arguments = append(arguments, fmt.Sprintf("a%d uint64", index))
					}
					arguments = append(arguments, "mask uint64")
					declaration := "func Value(" + strings.Join(arguments, ",") + ") uint32"
					instruction := strings.Replace(x86CompactExpandResultInstruction(opcode, width.bank, mode), width.bank+"0", "a0+0(FP)", 1)
					extract, register := "", "X1"
					if width.bytes == 32 {
						extract, register = "VEXTRACTI128 $1,Y1,X2\n", "X2"
					} else if width.bytes == 64 {
						extract, register = "VEXTRACTI32X4 $3,Z1,X2\n", "X2"
					}
					source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\nKMOVQ mask+%d(FP),K1\nVPXORD Z1,Z1,Z1\n%s\n%sPEXTRD $3,%s,AX\nMOVL AX,ret+%d(FP)\nRET\n",
						width.bytes+12, width.bytes, instruction, extract, register, width.bytes+8)
					goAssemblerOracleOutput(t, target.arch, source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(target.triple+"/"+opcode+"/"+width.bank+"/"+mode+"/"+api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
							if err != nil || ir == "" {
								t.Fatal("complete Go scalar fields did not supply their logical compact source", err)
							}
							if mode != "unmasked" {
								x86ExpandRequireEveryScalarInput(t, ir, width.bytes/8)
							}
						})
					}
				}
			}
		}
	}
}

func x86ExpandRequireEveryScalarInput(t *testing.T, ir string, inputs int) {
	t.Helper()
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := parseIRModuleInContext(context, ir)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	options := llvm.NewPassBuilderOptions()
	defer options.Dispose()
	if err := module.RunPasses("default<O2>", llvm.TargetMachine{}, options); err != nil {
		t.Fatal(err)
	}
	function := module.NamedFunction("Value")
	if function.IsNil() {
		t.Fatal("logical field observer lost the actual function")
	}
	for index := 0; index < inputs; index++ {
		if function.Param(index).FirstUse().IsNil() {
			t.Fatal("a full-mask-dependent scalar field was lost behind another field's alloca", index)
		}
	}
}
