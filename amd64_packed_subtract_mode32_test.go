package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestX86PackedSubtract386HighRegisterDoesNotAcquirePhysicalBinding(t *testing.T) {
	for _, opcode := range []string{"VPSUBB", "VPSUBW", "VPSUBD", "VPSUBQ", "VPSUBSB", "VPSUBSW", "VPSUBUSB", "VPSUBUSW"} {
		for _, bank := range []string{"X", "Y"} {
			for position := 0; position < 3; position++ {
				for _, high := range []int{16, 31} {
					args := []string{bank + "0", bank + "1", bank + "2"}
					args[position] = fmt.Sprintf("%s%d", bank, high)
					row := opcode + " " + strings.Join(args, ",")
					t.Run(strings.ReplaceAll(row, " ", "_"), func(t *testing.T) {
						source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
						requireX86GoAssemblerResult(t, "386", source, true)
						file, err := Parse(ArchAMD64, source)
						if err != nil {
							t.Fatal(err)
						}
						instruction := file.Funcs[0].Instrs[1]
						if _, recognized, err := x86PackedSubtractProperties(instruction, "386"); !recognized || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("Go-accepted mode32 high bank became a physical-register permission: recognized=%v err=%v", recognized, err)
						}
						ctx, output := newAMD64CtxWithFuncForTest(t, file.Funcs[0], FuncSig{Ret: Void}, nil)
						ctx.goarch = "386"
						before := output.String()
						if recognized, _, err := ctx.lowerPackedIntegerSubtract(instruction.Op, instruction); !recognized ||
							!errors.Is(err, ErrProbeNeedsContext) || output.String() != before {
							t.Fatalf("unproved mode32 high bank emitted IR: recognized=%v err=%v", recognized, err)
						}
					})
				}
			}
		}
	}
}

func TestX86PackedSubtract386HighRegisterActualByteIdentities(t *testing.T) {
	for _, opcode := range []string{"VPSUBB", "VPSUBW", "VPSUBD", "VPSUBQ", "VPSUBSB", "VPSUBSW", "VPSUBUSB", "VPSUBUSW"} {
		for _, bank := range []string{"X", "Y"} {
			for operand := 0; operand < 3; operand++ {
				args := []string{bank + "0", bank + "1", bank + "2"}
				args[operand] = bank + "16"
				row := opcode + " " + strings.Join(args, ",")
				t.Run(strings.ReplaceAll(row, " ", "_"), func(t *testing.T) {
					code := x86PackedFirstGoInstructionBytes(t, "386", row)
					ins, length, recognized, err := decodedX86PackedIntegerArithmeticInstruction(code, 64)
					if len(code) != 6 || !recognized || err != nil || length != 6 || ins.Op != Op(opcode) || len(ins.Args) != 3 {
						t.Fatalf("actual EVEX byte identity %s/%x: %+v/%d/%t/%v", row, code, ins, length, recognized, err)
					}
					for index, argument := range args {
						if ins.Args[index].Reg != Reg(argument) {
							t.Fatalf("%s/%x operand%d: %s != %s", row, code, index, ins.Args[index].Reg, argument)
						}
					}
					if _, _, recognized, err := decodedX86PackedIntegerArithmeticInstruction(code, 32); !recognized || err == nil {
						t.Fatalf("raw mode32 high bank obtained false permission: %s/%x", row, code)
					}
				})
			}
		}
	}
}

func TestX86PackedSubtract386BroadcastHighRegisterNeedsContext(t *testing.T) {
	for _, opcode := range []string{"VPSUBD", "VPSUBQ"} {
		for _, bank := range []string{"X", "Y"} {
			for position := 1; position < 3; position++ {
				args := []string{"(AX)", bank + "1", bank + "2"}
				args[position] = bank + "16"
				row := opcode + ".BCST " + strings.Join(args, ",")
				t.Run(strings.ReplaceAll(row, " ", "_"), func(t *testing.T) {
					source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
					requireX86GoAssemblerResult(t, "386", source, true)
					file, err := Parse(ArchAMD64, source)
					if err != nil {
						t.Fatal(err)
					}
					if _, known, err := x86PackedSubtractProperties(file.Funcs[0].Instrs[1], "386"); !known || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("broadcast high bank became a mode32 binding: %v", err)
					}
				})
			}
		}
	}
}
