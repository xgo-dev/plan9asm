package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86BroadcastThreeAPIFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move, typ := 8, "MOVQ", "uint64"
			if target.arch == "386" {
				word, move, typ = 4, "MOVL", "uint32"
			}
			for _, raw := range []bool{false, true} {
				t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
					var body strings.Builder
					fmt.Fprintf(&body, "%s x+0(FP),AX\nPINSRD $0,AX,X3\nPINSRD $1,AX,X3\n", move)
					for _, spec := range x86BroadcastTestDirectory {
						if spec.source != "X" && spec.source != "XG" {
							continue
						}
						for _, input := range spec.source {
							src := map[rune]string{'X': "X3", 'G': "AX"}[input]
							for _, bank := range spec.destinations {
								row := fmt.Sprintf("%s %s,%c3", spec.name, src, bank)
								emitX86GoEncodedTestInstructionForArch(t, &body, row, raw, target.arch)
							}
						}
					}
					fmt.Fprintf(&body, "VPEXTRQ $0,X3,BX\n%s BX,ret0+%d(FP)\nRET", move, word)
					declaration := "func Value(x " + typ + ") " + typ + "\nfunc Mask()\n"
					_, file, sig, source := x86ResultInitializationFixture(t, target.arch, declaration, body.String())
					if !raw {
						for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
							if err := check(file.Funcs[0], sig, target.arch); err != nil {
								t.Fatal(err)
							}
						}
					}
					var maskBody strings.Builder
					maskBody.WriteString("TEXT ·Mask(SB),4,$0-0\nMOVL $42,AX\nKMOVD AX,K3\n")
					for _, op := range []string{"VPBROADCASTMB2Q", "VPBROADCASTMW2D"} {
						for _, bank := range []string{"X", "Y", "Z"} {
							emitX86GoEncodedTestInstructionForArch(t, &maskBody, op+" K3,"+bank+"2", raw, target.arch)
						}
					}
					source += maskBody.String() + "RET\n"
					goAssemblerOracleOutput(t, target.arch, source, "", true)
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
							if err != nil {
								t.Fatal(err)
							}
							x86ResultInitializationObject(t, llc, target.triple, ir, "register-broadcast-"+api)
						})
					}
				})
			}
		})
	}
}

// The raw witness is always produced by the actual SDK in this fixture's mode.
func emitX86GoEncodedTestInstructionForArch(t *testing.T, source *strings.Builder, row string, raw bool, arch string) {
	t.Helper()
	if !raw {
		source.WriteString(row + "\n")
		return
	}
	code := assembleX87ControlBytes(t, arch, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
	if len(code) == 0 || code[len(code)-1] != 0xc3 {
		t.Fatal("original object missing RET")
	}
	for _, b := range code[:len(code)-1] {
		fmt.Fprintf(source, "BYTE $%#x\n", b)
	}
}
