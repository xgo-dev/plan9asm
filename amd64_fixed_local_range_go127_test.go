//go:build go1.27

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func fixedLocalReadonlyRangeProgram(t *testing.T) (string, string, []fixedLocalRangeCase) {
	t.Helper()
	var assembly, declarations strings.Builder
	for offset := 0; offset < 240; offset += 8 {
		// Each source qword advances all eight bytes independently. Runtime
		// expectations construct a byte array instead of parsing these DATA.
		word := uint64(0x0807060504030201) + uint64(offset)*0x0101010101010101
		fmt.Fprintf(&assembly, "DATA literal<>+%d(SB)/8,$0x%016x\n", offset, word)
	}
	assembly.WriteString("GLOBL literal<>(SB),8,$240\n")
	rows := fixedLocalRangeCases()
	if len(rows) != 48 {
		t.Fatal("complete readonly range source inventory changed", len(rows))
	}
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(fixedLocalConstantIndexFunction(name, row.body))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	return assembly.String(), declarations.String(), rows
}

func TestGoAMD64FixedLocalReadonlyRangeObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	assembly, declarations, rows := fixedLocalReadonlyRangeProgram(t)
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly, declarations, target.name, target.triple)
			var names []string
			for index := range rows {
				names = append(names, fmt.Sprintf("%s.Value%d", pkg.Path, index))
			}
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal("original bounded readonly DATA index rejected", err)
					}
					if !strings.Contains(ir, "internal constant [240 x i8]") {
						t.Fatal("the original complete readonly DATA allocation was lost")
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
					compileLLVMToObject(t, llc, target.triple, "readonly-range.ll", "readonly-range.o", ir)
					compileLLVMToObject(t, llc, target.triple, "readonly-range-opt.ll", "readonly-range-opt.o", x86MulDivRoundOptimize(t, ir))
				})
		})
	}
}

func TestGoAMD64FixedLocalReadonlyRangeOwnerLifetime(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	assembly := fixedLocalRangeData + fixedLocalConstantIndexFunction("Value", fixedLocalRangePrefix+fixedLocalRangeLoad)
	pkg, request, file, options := fixedLocalTransportFixture(t, assembly,
		"func Value(a uint64) uint64\n", "linux/amd64", "x86_64-unknown-linux-gnu")
	fixedLocalDataAPIs(t, pkg, file, assembly, options, fixedLocalRequireContext)
	source := requireGoAMD64FrameCapture(t, pkg, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bound, err := source.BindFixedLocal(ctx, pkg, file, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct{ old, replacement string }{
		{",8,$240", ",8,$256"},
		{"CMPQ R9,$16", "CMPQ R9,$17"},
		{"0x0102030405060708", "0x0102030405060709"},
		{fixedLocalRangeData, ""},
	} {
		input := strings.Replace(assembly, mutation.old, mutation.replacement, 1)
		parsed, err := Parse(ArchAMD64, input)
		if err != nil {
			t.Fatal(err)
		}
		fixedLocalDataAPIs(t, pkg, parsed, input, bound, fixedLocalRequireContext)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	fixedLocalDataAPIs(t, pkg, file, assembly, bound, fixedLocalRequireContext)
}
