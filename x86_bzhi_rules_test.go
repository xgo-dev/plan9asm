package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86BZHICompleteRegisterBanks(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		registers := strings.Fields("AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R14 R15")
		if arch == "386" {
			registers = registers[:8]
		}
		var original strings.Builder
		original.WriteString("TEXT f(SB),4,$0-0\n")
		count := 0
		for _, op := range []string{"BZHIL", "BZHIQ"} {
			for _, control := range registers {
				for _, source := range registers {
					for _, destination := range registers {
						row := fmt.Sprintf("%s %s,%s,%s", op, control, source, destination)
						original.WriteString(row + "\n")
						instruction := x86ScalarLaneInstruction(t, row)
						if _, known, err := x86ScalarBitFieldProperties(instruction.Op, instruction, arch); !known || err != nil {
							t.Fatal("complete original GP bank rejected", arch, row, err)
						}
						count++
					}
				}
			}
		}
		original.WriteString("RET\n")
		goAssemblerOracleOutput(t, arch, original.String(), "", true)
		if count != 2*len(registers)*len(registers)*len(registers) {
			t.Fatal("incomplete original BZHI register bank", arch, count)
		}
	}
}

func TestX86BZHIResultByteHolesAliasesAndFlags(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"BZHIL", "BZHIQ"} {
			width := int64(4)
			if arch == "amd64" && op == "BZHIQ" {
				width = 8
			}
			for _, source := range []string{"AX", "BX"} {
				for _, output := range []string{"AX", "BX", "CX", "SP", "BP"} {
					instruction := x86ScalarLaneInstruction(t, op+" AX,"+source+","+output)
					for _, consumer := range x86ResultGPSIMDConsumers {
						for missing := -1; missing < int(width)+1; missing++ {
							state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
							input, _, _ := x86ResultGP(Reg(source), width, arch)
							state.gp[0], state.gp[input] = 1, uint8((uint16(1)<<uint(width))-1)
							if missing == 0 {
								state.gp[0] &^= 1
							} else if missing > 0 {
								state.gp[input] &^= 1 << uint(missing-1)
							}
							before := state.clone()
							accept := missing == -1 && output != "SP" && (arch == "386" || output != "BP")
							if got := consumer.step(instruction, &state, nil, 0, arch); got != accept {
								t.Fatal("BZHI input/destination dependency changed", arch, op, source, output, consumer.name, missing, got)
							}
							want := before.clone()
							if accept {
								index, _, _ := x86ResultGP(Reg(output), width, arch)
								want.gp[index] = 0xff
								want.flags = x86ByteFlagCF | x86ByteFlagOF | x86ByteFlagZF | x86ByteFlagSF
							}
							if !reflect.DeepEqual(state, want) {
								t.Fatal("BZHI partially applied a failed effect or changed unrelated state", arch, op, source, output, missing)
							}
						}
					}
				}
			}
		}
	}
}

func TestX86BZHINativeReadAndOpaqueInputsStaySeparate(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range []string{"BZHIL", "BZHIQ"} {
			for _, role := range []string{"paired", "standalone", "missing-index-byte", "numerical-base", "unknown-offset", "raw", "encoded", "address-override", "opaque-control"} {
				t.Run(arch+"/"+op+"/"+role, func(t *testing.T) {
					instruction := x86ScalarLaneInstruction(t, op+" AX,(BX),CX")
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.gp[0], state.pointerGP[3] = 1, true
					native := true
					switch role {
					case "standalone":
						native = false
					case "missing-index-byte":
						state.gp[0] = 2 // AH is not BZHI's index.
					case "numerical-base":
						state.pointerGP[3], state.gp[3] = false, 0xff
					case "unknown-offset":
						instruction.Args[1].Mem.Index, instruction.Args[1].Mem.Scale = SI, 4
					case "raw":
						instruction.x86SourceRaw = &x86SourceRawInstruction{}
					case "encoded":
						instruction.x86Encoded = true
					case "address-override":
						instruction.x86AddressBits = 32
					case "opaque-control":
						state.pointerGP[0] = true
					}
					before := state.clone()
					accepted, known := x86ResultScalarBitFieldStep(instruction, &state, nil, 0, arch, native)
					if !known || accepted != (role == "paired") || !accepted && !reflect.DeepEqual(state, before) {
						t.Fatal("BZHI read continuation borrowed another source role", known, accepted, role)
					}
				})
			}
		}
	}
}
