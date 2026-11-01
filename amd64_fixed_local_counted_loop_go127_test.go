//go:build go1.27

package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixedLocalCountedLoopProgram(t *testing.T) (string, string, []string) {
	t.Helper()
	var assembly, declarations strings.Builder
	assembly.WriteString(fixedLocalAddressData)
	var expected []string
	appendFunction := func(body, want string) {
		name := fmt.Sprintf("Value%d", len(expected))
		_, _, source := fixedLocalCountedLoopFixture(t, body)
		assembly.WriteString(strings.Replace(source, "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
		expected = append(expected, want)
	}
	for _, row := range fixedLocalCountedLoopCases() {
		// Every stored qword is input + 2, read once after the complete
		// loop; a separate canary contributes 77. Native callers use -1.
		appendFunction(row.body, fmt.Sprintf("%016x", row.iterations+77))
	}
	for _, descending := range []bool{false, true} {
		appendFunction(fixedLocalCountedLiteralBody(descending), "64686c7074787c80")
	}
	return assembly.String(), declarations.String(), expected
}

func fixedLocalCountedLiteralBody(descending bool) string {
	first, offset, limit, update, branch := 0, 0, 4, "ADDQ", "JB"
	if descending {
		first, offset, limit, update, branch = 4, -8, 0, "SUBQ", "JA"
	}
	return fmt.Sprintf("LEAQ literal<>(SB),BP\nMOVQ $0,8(SP)\nMOVQ $%d,SI\nloop:\n"+
		"MOVQ %d(BP)(SI*8),AX\nMOVQ AX,16(SP)(SI*8)\nADDQ AX,8(SP)\n"+
		"%s $1,SI\nCMPQ SI,$%d\n%s loop\nMOVQ 8(SP),AX", first, offset, update, limit, branch)
}

func TestGoAMD64FixedLocalCountedLoopObjects(t *testing.T) {
	assembly, declarations, expected := fixedLocalCountedLoopProgram(t)
	if len(expected) != 38 {
		t.Fatal("counted-loop object inventory changed", len(expected))
	}
	fixedLocalCountedLoopObjects(t, assembly, declarations, len(expected))
}

func fixedLocalCountedLoopObjects(t *testing.T, assembly, declarations string, count int) {
	t.Helper()
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly, declarations, target.name, target.triple)
			var names []string
			for index := 0; index < count; index++ {
				names = append(names, fmt.Sprintf("%s.Value%d", pkg.Path, index))
			}
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal("original bounded-loop source rejected", err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
					compileLLVMToObject(t, llc, target.triple, "counted-loop.ll", "counted-loop.o", ir)
					compileLLVMToObject(t, llc, target.triple, "counted-loop-opt.ll", "counted-loop-opt.o", x86MulDivRoundOptimize(t, ir))
				})
		})
	}
}

func TestGoAMD64FixedLocalCountedLiteralLoopGuards(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	valid := fixedLocalCountedLiteralBody(false)
	for _, row := range []struct{ name, body string }{
		{"last read exceeds DATA", strings.Replace(valid, "CMPQ SI,$4", "CMPQ SI,$5", 1)},
		{"negative first read", strings.Replace(valid, "MOVQ 0(BP)", "MOVQ -8(BP)", 1)},
		{"readonly indexed store", strings.Replace(valid, "MOVQ 0(BP)(SI*8),AX", "MOVQ AX,0(BP)(SI*8)", 1)},
		{"readonly indexed RMW", strings.Replace(valid, "MOVQ 0(BP)(SI*8),AX", "ADDQ AX,0(BP)(SI*8)", 1)},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, _, source := fixedLocalCountedLoopFixture(t, row.body)
			pkg, request, file, options := fixedLocalTransportFixture(t, fixedLocalAddressData+source,
				"func Value(a uint64) uint64\n", "linux/amd64", "x86_64-unknown-linux-gnu")
			owner := requireGoAMD64FrameCapture(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			if _, err := owner.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("counted loop acquired an invalid DATA extent or write", err)
			}
		})
	}
}
