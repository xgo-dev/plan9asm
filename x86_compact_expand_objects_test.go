package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86CompactExpandInitializedWholeFamilyObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	var source, declarations strings.Builder
	var names []string
	for _, op := range x86CompactExpandResultMembers {
		for _, bank := range []string{"X", "Y", "Z"} {
			for _, mode := range []string{"unmasked", "merge", "zero"} {
				for _, alias := range []bool{false, true} {
					name := fmt.Sprintf("Value%s%s%sAlias%t", op, bank, mode, alias)
					instruction := x86CompactExpandResultInstruction(op, bank, mode)
					if alias {
						instruction = strings.Replace(instruction, bank+"0", bank+"1", 1)
					}
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-4\nMOVL $7,AX\nKMOVD AX,K1\n"+
						"VPXORD Z0,Z0,Z0\nVPXORD Z1,Z1,Z1\n%s\nPEXTRD $0,X1,AX\nMOVL AX,ret+0(FP)\nRET\n", name, instruction)
					fmt.Fprintf(&declarations, "func %s() uint32\n", name)
					names = append(names, name)
				}
			}
		}
	}
	if len(names) != 216 {
		t.Fatal("complete initialized family denominator changed", len(names))
	}
	for _, target := range dataRelocationTargets {
		if target.arch != ArchAMD64 {
			continue
		}
		t.Run(target.triple, func(t *testing.T) {
			dataRelocationGoObject(t, source.String(), target.goos, target.goarch, true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.goarch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete initialized compact/expand family rejected", err)
					}
					x86CompactExpandRequireAllDefinitions(t, ir, names)
					for _, optimized := range []bool{false, true} {
						objectIR := ir
						if optimized {
							objectIR = x86DwordProductIROptimize(t, ir)
						}
						for _, level := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR-O2=%t/backend%s", optimized, level), func(t *testing.T) {
								x86PackedStringCompileObject(t, llc, target.triple, objectIR, level)
							})
						}
					}
				})
			}
		})
	}
}

func x86CompactExpandRequireAllDefinitions(t *testing.T, ir string, names []string) {
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
	for _, name := range names {
		function := module.NamedFunction(name)
		if function.IsNil() || function.FirstBasicBlock().IsNil() {
			t.Fatal("complete family omitted an original function body", name)
		}
	}
}
