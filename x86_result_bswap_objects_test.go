package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestX86ByteSwapOriginalGoCompleteGrammarAndBytes(t *testing.T) {
	registers := strings.Fields("AX CX DX BX SP BP SI DI R8 R9 R10 R11 R12 R13 R14 R15")
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"BSWAPL", "BSWAPQ"} {
			t.Run(arch+"/"+op+"/Go-g-register-alias", func(t *testing.T) {
				source := "TEXT swap(SB),4,$0-0\n" + op + " g\nRET\n"
				if arch == "386" {
					goAssemblerOracleOutput(t, arch, source, "", false)
					return
				}
				code := x86OrderingHintGoBytes(t, arch, source)
				physical := x86OrderingHintGoBytes(t, arch, strings.ReplaceAll(source, " g\n", " R14\n"))
				if !bytes.Equal(code, physical) {
					t.Fatal("official source g alias did not retain its exact R14 encoding")
				}
			})
			for index, register := range registers {
				t.Run(arch+"/"+op+"/"+register, func(t *testing.T) {
					source := "TEXT swap(SB),4,$0-0\n" + op + " " + register + "\nRET\n"
					if arch == "386" && (op == "BSWAPQ" || index >= 8) {
						goAssemblerOracleOutput(t, arch, source, "", false)
						return
					}
					code := x86OrderingHintGoBytes(t, arch, source)
					var want []byte
					if op == "BSWAPQ" {
						want = append(want, 0x48|byte(index/8))
					} else if index >= 8 {
						want = append(want, 0x41)
					}
					want = append(want, 0x0f, 0xc8+byte(index%8), 0xc3)
					if !bytes.Equal(code, want) {
						t.Fatalf("complete original Go BSWAP bytes=%x, independent encoding=%x", code, want)
					}
				})
			}
			for _, operand := range []string{"AL", "AH", "X0", "M0", "K1", "FS", "TLS", "R16", "$1", "(AX)", "ret+0(FP)", "table(SB)", "AX,BX", ""} {
				t.Run(arch+"/"+op+"/reject/"+operand, func(t *testing.T) {
					goAssemblerOracleOutput(t, arch, "TEXT swap(SB),4,$0-0\n"+op+" "+operand+"\nRET\n", "", false)
				})
			}
			for _, suffix := range []string{".Z", ".SAE"} {
				t.Run(arch+"/"+op+"/reject-suffix/"+suffix, func(t *testing.T) {
					goAssemblerOracleOutput(t, arch, "TEXT swap(SB),4,$0-0\n"+op+suffix+" AX\nRET\n", "", false)
				})
			}
		}
		for _, op := range []string{"BSWAPB", "BSWAPW"} {
			t.Run(arch+"/reject-name/"+op, func(t *testing.T) {
				goAssemblerOracleOutput(t, arch, "TEXT swap(SB),4,$0-0\n"+op+" AX\nRET\n", "", false)
			})
		}
	}
}

// The complete ordinary numerical cohort excludes physical SP/AMD64 BP, whose
// original Go encodings are observed above without inventing their entry role.
// L on amd64 returns the full64-bit word, independently observing zero extension.
func x86ByteSwapObjectFixture(t *testing.T, arch string) (string, string) {
	t.Helper()
	word, typ, move, push, pop := 8, "uint64", "MOVQ", "PUSHQ", "POPQ"
	registers := strings.Fields("AX CX DX BX SI DI R8 R9 R10 R11 R12 R13 R14 R15")
	ops := []string{"BSWAPL", "BSWAPQ"}
	if arch == "386" {
		word, typ, move, push, pop = 4, "uint32", "MOVL", "PUSHL", "POPL"
		registers, ops = strings.Fields("AX CX DX BX BP SI DI"), []string{"BSWAPL"}
	}
	var source, declarations strings.Builder
	for _, op := range ops {
		for _, register := range registers {
			name := op + "_" + register
			fmt.Fprintf(&declarations, "func %s(x %s) %s\n", name, typ, typ)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s x+0(FP),%s\n%s %s\n%s %s,ret+%d(FP)\nRET\n", name, 2*word, move, register, op, register, move, register, word)
		}
		fmt.Fprintf(&declarations, "func Sparse%s(x byte) byte\n", op)
		fmt.Fprintf(&source, "TEXT ·Sparse%s(SB),4,$0-%d\nMOVB x+0(FP),AX\n%s AX\n%s AX\nMOVB AX,ret+%d(FP)\nRET\n", op, word+1, op, op, word)
		fmt.Fprintf(&declarations, "func Status%s(x,seed %s) %s\n", op, typ, typ)
		fmt.Fprintf(&source, "TEXT ·Status%s(SB),4,$0-%d\n%s x+0(FP),BX\n%s seed+%d(FP)\nPOPF%s\n%s BX\nPUSHF%s\n%s AX\nCLD\n%s AX,ret+%d(FP)\nRET\n", op, 3*word, move, push, word, move[3:], op, move[3:], pop, move, 2*word)
	}
	return source.String(), declarations.String()
}

func TestX86ByteSwapObjectFixtureCompleteNumericalRoles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		source, declarations := x86ByteSwapObjectFixture(t, arch)
		count := 32
		if arch == "386" {
			count = 9
		}
		if strings.Count(source, "TEXT ·") != count || strings.Count(declarations, "func ") != count {
			t.Fatal("complete numerical bank/partial/FLAGS fixture inventory changed")
		}
		x86ResultGPSIMDAdmissionAPIs(t, arch, source, declarations, true)
	}
}

func TestX86ByteSwapOriginalGoAndLLVMFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("BSWAP complete objects require LLVM22 llc")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := x86ByteSwapObjectFixture(t, target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete BSWAP source failed", err)
					}
					for _, optimizeIR := range []bool{false, true} {
						input := ir
						if optimizeIR {
							input = x86MulDivRoundOptimize(t, input)
						}
						for _, level := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimizeIR, level), func(t *testing.T) {
								x86PackedStringCompileObject(t, llc, target.triple, input, level)
							})
						}
					}
				})
			}
		})
	}
}
