package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestGoAMD64FixedLocalIntegerCompareCompleteObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	rows := fixedLocalIntegerCompareCases()
	if len(rows) != 168 {
		t.Fatal("complete comparison object inventory changed", len(rows))
	}
	var assembly, declarations strings.Builder
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(fixedLocalIntegerCompareSource(row), "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(p *uint64, a uint64) uint64\n", name)
	}
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			pkg, request, _, options := fixedLocalTransportFixture(t,
				assembly.String(), declarations.String(), target.name, target.triple)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal("complete fixed-frame integer comparisons failed translation", err)
					}
					optimized := fixedLocalIntegerCompareConstantResults(t, ir, pkg.Path, rows)
					compileLLVMToObject(t, llc, target.triple, "compare.ll", "compare.o", ir)
					compileLLVMToObject(t, llc, target.triple, "compare-opt.ll", "compare-opt.o", optimized)
				})
		})
	}
}

// Parse and optimize each complete module once. Check the actual return value
// of every self relation, including unknown inputs, rather than IR substrings.
func fixedLocalIntegerCompareConstantResults(t *testing.T, ir, path string, rows []fixedLocalIntegerCompareCase) string {
	t.Helper()
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := parseIRModuleInContext(context, ir)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
		t.Fatal(err)
	}
	for index := range rows {
		function := module.NamedFunction(fmt.Sprintf("%s.Value%d", path, index))
		if function.IsNil() || function.FirstBasicBlock().IsNil() {
			t.Fatal("complete source omitted original function", index)
		}
	}
	options := llvm.NewPassBuilderOptions()
	defer options.Dispose()
	if err := module.RunPasses("default<O2>", llvm.TargetMachine{}, options); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for index, row := range rows {
		if !row.self {
			continue
		}
		checked++
		want := ^uint64(0)
		if strings.Contains(row.operation, "PCMPGT") {
			want = 0
		}
		function := module.NamedFunction(fmt.Sprintf("%s.Value%d", path, index))
		returns := 0
		for block := function.FirstBasicBlock(); !block.IsNil(); block = llvm.NextBasicBlock(block) {
			for instruction := block.FirstInstruction(); !instruction.IsNil(); instruction = llvm.NextInstruction(instruction) {
				if instruction.IsAReturnInst().IsNil() {
					continue
				}
				returns++
				if instruction.OperandsCount() != 1 || instruction.Operand(0).IsAConstantInt().IsNil() ||
					instruction.Operand(0).ZExtValue() != want {
					t.Fatalf("self relation %s did not return %016x: %s", row.name, want, function.String())
				}
			}
		}
		if returns != 1 {
			t.Fatal("self relation lost its sole return", row.name, returns)
		}
	}
	if checked != 48 {
		t.Fatal("self-comparison constant inventory changed", checked)
	}
	return module.String()
}
