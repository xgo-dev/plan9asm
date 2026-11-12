//go:build darwin || linux

package plan9asm

import (
	"runtime"
	"testing"
)

// Reuse the exact discovering native programs, but execute only portable
// LLVM semantics on the current host. Original native ISA remains a separate
// required cross-runtime owner. No Rosetta or native-ISA claim follows here.
func TestX86PackedShiftOriginalFaultProgramPortableMemorySemantics(t *testing.T) {
	source, signatures, declarations, rows, required := x86PackedShiftFaultProgram()
	x86PackedFaultProgramPortableMemory(t, source,
		x86PackedFaultProgramGoDeclarations(signatures, "out,data,count *byte"),
		declarations, rows, required)
}

func TestX86PackedUnpackOriginalFaultProgramPortableMemorySemantics(t *testing.T) {
	source, signatures, declarations, rows := x86PackedUnpackFaultProgram()
	x86PackedFaultProgramPortableMemory(t, source,
		x86PackedFaultProgramGoDeclarations(signatures, "input,out *byte"),
		declarations, rows, []bool{true, true, true, true})
}

func x86PackedFaultProgramPortableMemory(t *testing.T, source, goDeclarations, prototypes, rows string, required []bool) {
	t.Helper()
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	execution := x86FloatCompareExecution{llc: llc, compiler: []string{clang},
		triple: testTargetTriple(runtime.GOOS, runtime.GOARCH)}
	driver := x86MemoryFaultDriver(prototypes, rows)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, goDeclarations, "amd64", execution.triple, api)
			if err != nil {
				t.Fatal("original complete program lacks a paired numerical continuation", err)
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					executable := execution.compileLLVM(t, "packed-memory", text, driver, level)
					x86CheckMemoryAccessMatrix(t, execution, executable, required)
				}
			}
		})
	}
}
