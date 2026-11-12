package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestX86ImplicitMultiplyOriginalGoGrammarAndEncoding(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86ImplicitMultiplyCases(arch) {
			t.Run(arch+"/"+row.op, func(t *testing.T) {
				code := x86OrderingHintGoBytes(t, arch, "TEXT product(SB),4,$0-0\n"+row.op+" BX\nRET\n")
				var want []byte
				if row.width == 2 {
					want = append(want, 0x66)
				} else if row.width == 8 {
					want = append(want, 0x48)
				}
				opcode, modrm := byte(0xf7), byte(0xe3)
				if row.width == 1 {
					opcode = 0xf6
				}
				if strings.HasPrefix(row.op, "IMUL") {
					modrm += 8
				}
				want = append(want, opcode, modrm, 0xc3)
				if !bytes.Equal(code, want) {
					t.Fatalf("actual Go implicit row bytes=%x, independent row=%x", code, want)
				}
				registers := strings.Fields("AX CX DX BX SP BP SI DI")
				if arch == "amd64" {
					registers = append(registers, strings.Fields("R8 R9 R10 R11 R12 R13 R14 R15")...)
				}
				if row.width == 1 {
					registers = append(registers, strings.Fields("AL AH BL BH CL CH DL DH")...)
					if arch == "amd64" {
						registers = append(registers, strings.Fields("BPB SIB DIB R8B R9B R10B R11B R12B R13B R14B R15B")...)
					}
				}
				var bank strings.Builder
				bank.WriteString("TEXT bank(SB),4,$0-32\n")
				for _, register := range registers {
					if arch == "386" && row.width == 1 && register == "SP" {
						continue // Go rejects direct SP byte; BP/SI/DI use its BX synthesis.
					}
					fmt.Fprintf(&bank, "%s %s\n", row.op, register)
				}
				for _, source := range []string{"x+0(FP)", "x+1(FP)", "4(AX)(SI*2)", "table(SB)"} {
					fmt.Fprintf(&bank, "%s %s\n", row.op, source)
				}
				bank.WriteString("RET\n")
				goAssemblerOracleOutput(t, arch, bank.String(), "", true)
			})
		}
		for _, instruction := range []string{"MULB $1", "IMULB AX,BX", "MULL X0", "MULL $slot+0(FP)", "MULL AX,BX", "MULQ X0"} {
			t.Run(arch+"/invalid/"+instruction, func(t *testing.T) {
				goAssemblerOracleOutput(t, arch, "TEXT invalid(SB),4,$0-0\n"+instruction+"\nRET\n", "", false)
			})
		}
		if arch == "386" {
			for _, instruction := range []string{"MULQ AX", "IMULQ AX", "MULB SP", "MULB R8B"} {
				t.Run(arch+"/invalid/"+instruction, func(t *testing.T) {
					goAssemblerOracleOutput(t, arch, "TEXT invalid(SB),4,$0-0\n"+instruction+"\nRET\n", "", false)
				})
			}
		}
	}
}

func TestX86ImplicitMultiplyFiveTargetOriginalGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete implicit product objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			appendFunction := func(body, declaration string) {
				name := fmt.Sprintf("Product%d", strings.Count(source.String(), "TEXT ·"))
				source.WriteString(strings.ReplaceAll(body, "Value", name))
				declarations.WriteString(strings.ReplaceAll(declaration, "Value", name) + "\n")
			}
			for _, row := range x86ImplicitMultiplyCases(target.arch) {
				appendFunction(row.source, row.declaration)
			}
			for _, row := range x86ImplicitMultiplyFPCases(target.arch) {
				for _, stem := range []string{"MUL", "IMUL"} {
					body, declaration := x86ImplicitMultiplyFPFixture(row, stem, target.arch)
					appendFunction(body, declaration)
				}
			}
			count := 40
			if target.arch == "386" {
				count = 30
			}
			if strings.Count(source.String(), "TEXT ·") != count {
				t.Fatal("complete implicit product/FP source inventory changed")
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || strings.Count(ir, "define ") != count {
						t.Fatal("complete typed product object fixture failed", err)
					}
					for _, optimized := range []bool{false, true} {
						input := ir
						if optimized {
							input = x86MulDivRoundOptimize(t, input)
						}
						for _, level := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimized, level), func(t *testing.T) {
								x86PackedStringCompileObject(t, llc, target.triple, input, level)
							})
						}
					}
				})
			}
		})
	}
}
