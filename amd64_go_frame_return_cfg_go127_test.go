//go:build go1.27

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func fixedLocalReturnCFGProgram() (string, string, []string) {
	var assembly, declarations strings.Builder
	var expected []string
	for _, flags := range []string{"", "4,"} {
		for _, value := range []int{0, 7} {
			name := fmt.Sprintf("Value%d", len(expected))
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),%s$160-16\nMOVQ $%d,AX\nMOVQ AX,8(SP)\n", name, flags, value)
			assembly.WriteString("loop:\nTESTQ AX,AX\nJNE work\nMOVQ 8(SP),AX\nMOVQ AX,ret0+8(FP)\nRET\nwork:\nXORQ AX,AX\nJMP loop\n")
			fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
			expected = append(expected, fmt.Sprintf("%016x", value))
		}
	}
	return assembly.String(), declarations.String(), expected
}

func TestGoAMD64FixedLocalReturnCFGObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	assembly, declarations, expected := fixedLocalReturnCFGProgram()
	if len(expected) != 4 {
		t.Fatal("complete split/NOSPLIT and branch inventory changed", len(expected))
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly, declarations, target.name, target.triple)
			var names []string
			for index := range expected {
				names = append(names, fmt.Sprintf("%s.Value%d", pkg.Path, index))
			}
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal("original source with early RET and final local backedge", err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
					compileLLVMToObject(t, llc, target.triple, "return-cfg.ll", "return-cfg.o", ir)
					compileLLVMToObject(t, llc, target.triple, "return-cfg-opt.ll", "return-cfg-opt.o", x86MulDivRoundOptimize(t, ir))
				})
		})
	}
}
