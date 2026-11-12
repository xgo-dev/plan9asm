//go:build go1.27

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func fixedLocalAliasedFrameProgram() (string, string, []string) {
	var assembly, declarations strings.Builder
	var expected []string
	for _, register := range []Reg{AX, BX, CX, DX, SI, DI, BP, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"} {
		for _, address := range []string{"MOVQ SP,%s", "LEAQ 16(SP),%s"} {
			name := fmt.Sprintf("Value%d", len(expected))
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$160-16\n", name)
			fmt.Fprintf(&assembly, address+"\n", register)
			fmt.Fprintf(&assembly, "MOVQ $7,8(%s)\nMOVQ 8(%s),AX\nMOVQ AX,ret0+8(FP)\nRET\n", register, register)
			fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
			expected = append(expected, "0000000000000007")
		}
	}
	return assembly.String(), declarations.String(), expected
}

func TestGoAMD64FixedLocalAliasedFrameObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	assembly, declarations, expected := fixedLocalAliasedFrameProgram()
	if len(expected) != 30 {
		t.Fatal("complete GP/address family inventory changed", len(expected))
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, file, options := fixedLocalTransportFixture(t, assembly, declarations, target.name, target.triple)
			if !GoAMD64FixedLocalFrameBindingNeeded(file, "amd64") {
				t.Fatal("complete aliased scratch source bypassed actual frame capture")
			}
			var names []string
			for index := range expected {
				names = append(names, fmt.Sprintf("%s.Value%d", pkg.Path, index))
			}
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal("complete aliased scratch source rejected", err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
					compileLLVMToObject(t, llc, target.triple, "alias-frame.ll", "alias-frame.o", ir)
					compileLLVMToObject(t, llc, target.triple, "alias-frame-opt.ll", "alias-frame-opt.o", x86MulDivRoundOptimize(t, ir))
				})
		})
	}
}
