package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86ValueStackTransportProgram(arch string) (string, string, []string) {
	word := "Q"
	if arch == "386" {
		word = "L"
	}
	registers := strings.Fields("AX BX CX DX SI DI")
	if arch == "amd64" {
		registers = append(registers, "R8", "R15")
	} else {
		registers = append(registers, "BP")
	}
	var source, declarations strings.Builder
	var names []string
	for index, register := range registers {
		name := fmt.Sprintf("OpaqueTransport%d", index)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-4\nPUSH%s %s\nMOVL $13,%s\nPOP%s %s\nMOVL $7,AX\nMOVL AX,ret+0(FP)\nRET\n",
			name, word, register, register, word, register)
		declarations.WriteString("func " + name + "() uint32\n")
		names = append(names, name)
	}
	source.WriteString("TEXT ·PartialTransport(SB),4,$0-4\nMOVB $7,BL\nPUSH" + word + " BX\nPOP" + word + " AX\nMOVBLZX AL,AX\nMOVL AX,ret+0(FP)\nRET\n")
	declarations.WriteString("func PartialTransport() uint32\n")
	names = append(names, "PartialTransport")
	return source.String(), declarations.String(), names
}

func TestX86ValueStackPureRegisterTransportKeepsExactAvailability(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations, names := x86ValueStackTransportProgram(target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("pure saved/partial GP transport requires no unknown numerical observation", err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, target.triple, text, level)
						}
					}
				})
			}
		})
	}
}

func TestX86ValueStackRegisterTransportCannotInventBitsOrPointerRoles(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		word := "Q"
		if target.arch == "386" {
			word = "L"
		}
		for _, row := range []struct{ name, body string }{
			{"unknown-byte", "PUSH" + word + " BX\nPOP" + word + " AX\nMOVBLZX AL,AX"},
			{"unknown-other-byte", "MOVB $7,BL\nPUSH" + word + " BX\nPOP" + word + " AX\nMOVBLZX AH,AX"},
			{"unknown-address", "PUSH" + word + " BX\nPOP" + word + " AX\nMOVL (AX),AX"},
			{"unknown-stack-pointer", "PUSH" + word + " BX\nPOP" + word + " SP\nMOVL $7,AX"},
		} {
			t.Run(target.triple+"/"+row.name, func(t *testing.T) {
				source := "TEXT ·Value(SB),4,$0-4\n" + row.body + "\nMOVL AX,ret+0(FP)\nRET\n"
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32", target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("private transport invented a byte, pointee or physical SP role", api, err)
					}
				}
			})
		}
	}
}

func TestX86ValueStackAMD64FrameRegisterNeedsItsSeparateRole(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		if target.arch != "amd64" {
			continue // Mode32 BP is an ordinary GP; the positive matrix covers it.
		}
		t.Run(target.triple, func(t *testing.T) {
			for _, register := range []string{"SP", "BP"} {
				source := "TEXT ·Value(SB),4,$0-4\nPUSHQ " + register + "\nPOPQ AX\nMOVL $7,AX\nMOVL AX,ret+0(FP)\nRET\n"
				x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, source, "func Value() uint32", target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatal("private numerical copy acquired a physical stack/frame role", register, api, err)
					}
				}
			}
		})
	}
}
