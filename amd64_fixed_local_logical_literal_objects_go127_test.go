//go:build go1.27

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type fixedLocalLogicalLiteralKernel struct {
	name       string
	row        fixedLocalLogicalLiteralCase
	annihilate bool
}

func fixedLocalLogicalLiteralKernels(t *testing.T) []fixedLocalLogicalLiteralKernel {
	t.Helper()
	var kernels []fixedLocalLogicalLiteralKernel
	for _, row := range fixedLocalLogicalLiteralCases() {
		kernels = append(kernels, fixedLocalLogicalLiteralKernel{row: row})
		name := strings.TrimPrefix(row.opcode, "V")
		if name == "PAND" || name == "PANDN" || name == "POR" {
			kernels = append(kernels, fixedLocalLogicalLiteralKernel{row: row, annihilate: true})
		}
	}
	if len(kernels) != 45 {
		t.Fatal("complete logical literal source denominator changed", len(kernels))
	}
	for index := range kernels {
		kernels[index].name = fmt.Sprintf("Value%d", index)
	}
	return kernels
}

func fixedLocalLogicalLiteralProgram(kernels []fixedLocalLogicalLiteralKernel) (string, string) {
	var assembly, declarations strings.Builder
	for _, kernel := range kernels {
		source := fixedLocalLogicalLiteralSource(kernel.row, kernel.annihilate)
		source = strings.ReplaceAll(source, "mask<>", kernel.name+"Mask<>")
		source = strings.Replace(source, "·Value", "·"+kernel.name, 1)
		assembly.WriteString(source)
		fmt.Fprintf(&declarations, "func %s(input, output *byte)\n", kernel.name)
	}
	return assembly.String(), declarations.String()
}

func TestGoAMD64FixedLocalLogicalLiteralThreeTargetObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	kernels := fixedLocalLogicalLiteralKernels(t)
	for _, target := range []struct{ name, triple string }{
		{"linux/amd64", "x86_64-unknown-linux-gnu"},
		{"darwin/amd64", "x86_64-apple-darwin"},
		{"windows/amd64", "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			for start := 0; start < len(kernels); start += 24 {
				end := start + 24
				if end > len(kernels) {
					end = len(kernels)
				}
				t.Run(fmt.Sprint(start/24), func(t *testing.T) {
					assembly, declarations := fixedLocalLogicalLiteralProgram(kernels[start:end])
					pkg, request, _, options := fixedLocalTransportFixture(t, assembly, declarations, target.name, target.triple)
					fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
						func(t *testing.T, ir string, err error) {
							if err != nil {
								t.Fatal("complete constant-mask logical program did not translate", err)
							}
							var names []string
							for _, kernel := range kernels[start:end] {
								names = append(names, pkg.Path+"."+kernel.name)
							}
							x86CompactExpandRequireAllDefinitions(t, ir, names)
							compileLLVMToObject(t, llc, target.triple, "logical-literal.ll", "logical-literal.o", ir)
							compileLLVMToObject(t, llc, target.triple, "logical-literal-opt.ll", "logical-literal-opt.o", x86MulDivRoundOptimize(t, ir))
						})
				})
			}
		})
	}
	t.Log("45 complete kernels: 36 formats and 9 annihilators; 3 targets, 3 independent API owners, O0/O2; no execution claim")
}
