package plan9asm

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func x86IFMACompleteInputObjects(t *testing.T, bank string) {
	t.Helper()
	for _, target := range x86RawReturnTargets {
		for _, raw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/raw=%t", target.triple, raw), func(t *testing.T) {
				word, suffix := goWordSize(target.arch), "Q"
				if word == 4 {
					suffix = "L"
				}
				var source, declarations strings.Builder
				count := 0
				for _, name := range []string{"VPMADD52LUQ", "VPMADD52HUQ"} {
					for _, mode := range []string{"plain", "merge", "zero"} {
						if target.arch == "386" && !raw && mode != "plain" {
							continue // Named frontend cap; physical raw rows remain in this matrix.
						}
						for _, input := range []string{bank + "0", "(SI)", "broadcast"} {
							op, mask, operand := name, "", input
							if input == "broadcast" {
								op, operand = op+".BCST", "(SI)"
							}
							if mode != "plain" {
								mask = "K1,"
							}
							if mode == "zero" {
								op += ".Z"
							}
							instruction := op + " " + operand + "," + bank + "1," + mask + bank + "2"
							if raw {
								encoderArch := target.arch
								if mode != "plain" {
									encoderArch = "amd64" // Low registers/default SI address have the same physical row.
								}
								instruction = x86RawNumericalInstruction(t, encoderArch, instruction)
							}
							function := fmt.Sprint("IFMA", count)
							fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\nMOV%s out+0(FP),DI\n"+
								"MOV%s a+%d(FP),SI\nMOV%s b+%d(FP),BX\nMOV%s old+%d(FP),CX\n"+
								"VMOVUPS (SI),Z0\nVMOVUPS (BX),Z1\nVMOVUPS (CX),Z2\n"+
								"MOVL $-1431655766,AX\nKMOVD AX,K1\nPUSH%s $0\nPOPF%s\n%s\n"+
								"VMOVUPS Z2,(DI)\nPUSHF%s\nPOP%s AX\nMOV%s AX,64(DI)\nRET\n",
								function, 4*word, suffix, suffix, word, suffix, 2*word, suffix, 3*word,
								suffix, suffix, instruction, suffix, suffix, suffix)
							fmt.Fprintf(&declarations, "func %s(out *[80]byte,a,b,old *[64]byte)\n", function)
							count++
						}
					}
				}
				want := 18
				if target.arch == "386" && !raw {
					want = 6
				}
				if count != want {
					t.Fatal("complete IFMA source/mask/broadcast inventory changed", count, want)
				}
				x86RawNumericalFamilyObjects(t, source.String(), declarations.String(), target.arch, target.triple)
			})
		}
	}
}

func TestX86IFMACompleteXInputObjects(t *testing.T) { x86IFMACompleteInputObjects(t, "X") }
func TestX86IFMACompleteYInputObjects(t *testing.T) { x86IFMACompleteInputObjects(t, "Y") }
func TestX86IFMACompleteZInputObjects(t *testing.T) { x86IFMACompleteInputObjects(t, "Z") }

func TestX86IFMADeadNativeInputsCannotBorrowVoidOrBool(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, name := range []string{"VPMADD52HUQ", "VPMADD52LUQ"} {
			for _, raw := range []bool{false, true} {
				instruction := name + " (SI),X1,X2"
				if raw {
					instruction = x86RawNumericalInstruction(t, target.arch, instruction)
				}
				source := "TEXT ·Value(SB),4,$0\n" + instruction + "\nRET\n"
				for _, declaration := range []string{"func Value()", "func Value(unused bool)"} {
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("dead IFMA silently discarded its native input access", target, name, raw, api, err)
						}
					}
				}
			}
		}
	}
}

func TestX86IFMAPhysicalMode32MaskIsNotANamedFrontendLimit(t *testing.T) {
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM 22 llvm-mc required")
	}
	row := "VPMADD52LUQ X0,X1,K1,X2"
	code := x86OrderingHintGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
	var bytes strings.Builder
	for _, b := range code[:len(code)-1] {
		fmt.Fprintf(&bytes, "0x%02x ", b)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	command := exec.CommandContext(ctx, mc, "--disassemble", "--triple=i386-unknown-linux-gnu")
	command.Stdin = strings.NewReader(bytes.String() + "\n")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	cancel()
	if err != nil || !strings.Contains(strings.ToLower(string(output)), "vpmadd52luq") || strings.Contains(string(output), "warning:") {
		t.Fatal("independent physical mode32 mask row did not assemble", err, string(output))
	}
	if _, n, known, err := decodedX86IFMAInstruction(code, 32); !known || err != nil || n != len(code)-1 {
		t.Fatal("valid physical mode32 IFMA inherited the named frontend's operand cap", known, n, err)
	}
}
