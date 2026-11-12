package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86ImplicitMultiplyNativeMemoryLinuxAMD64Objects(t *testing.T) {
	x86ImplicitMultiplyNativeObjects(t, "amd64", "x86_64-unknown-linux-gnu")
}

func TestX86ImplicitMultiplyNativeMemoryDarwinAMD64Objects(t *testing.T) {
	x86ImplicitMultiplyNativeObjects(t, "amd64", "x86_64-apple-darwin")
}

func TestX86ImplicitMultiplyNativeMemoryWindowsAMD64Objects(t *testing.T) {
	x86ImplicitMultiplyNativeObjects(t, "amd64", "x86_64-pc-windows-msvc")
}

func TestX86ImplicitMultiplyNativeMemoryLinux386Objects(t *testing.T) {
	x86ImplicitMultiplyNativeObjects(t, "386", "i386-unknown-linux-gnu")
}

func TestX86ImplicitMultiplyNativeMemoryWindows386Objects(t *testing.T) {
	x86ImplicitMultiplyNativeObjects(t, "386", "i686-pc-windows-msvc")
}

// Orthogonal witnesses: every family member, base/SIB addressing, both
// accumulator outputs, and a read-before-write DX address alias. Each capture
// owns 40 amd64 or 30 mode32 functions, not a repeated full grammar Cartesian.
func x86ImplicitMultiplyNativeObjects(t *testing.T, arch, triple string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	var assembly, declarations strings.Builder
	count := 0
	for _, row := range x86ImplicitMultiplyNativeOracle {
		if arch == "386" && row.bits == 64 {
			continue
		}
		for _, address := range []string{"(BX)", "1(BX)(CX*2)", "(DX)"} {
			for _, output := range []string{"AX", "DX"} {
				if address == "(DX)" && output == "DX" {
					continue // B preserves its real pointer; no pointer-to-NUM return.
				}
				source, declaration := x86ImplicitMultiplyNativeSource(fmt.Sprint("Product", count), row.op, arch, address, output, false)
				assembly.WriteString(source)
				declarations.WriteString(declaration + "\n")
				count++
			}
		}
	}
	want := 40
	if arch == "386" {
		want = 30
	}
	if count != want {
		t.Fatal("complete native multiply member/alias witness directory changed", count)
	}
	x86LEAActualTargetGoObject(t, arch, triple, assembly.String())
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, assembly.String(), declarations.String(), arch, triple, api)
			if err != nil || strings.Count(ir, "define ") != want {
				t.Fatal("complete initialized native multiply objects lost their source continuation", err)
			}
			optimized := x86DwordProductIROptimize(t, ir)
			for _, pipeline := range []struct{ name, text, level string }{
				{"O0", ir, "-O0"}, {"O2", ir, "-O2"}, {"IR-O2/O2", optimized, "-O2"},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					if strings.Count(pipeline.text, "load volatile i") != want || strings.Contains(pipeline.text, "store volatile") {
						t.Fatal("complete exact-width reads disappeared or gained stores")
					}
					for _, bits := range []int{8, 16, 32, 64} {
						reads := 10 // Two signedness members times five independent forms.
						if arch == "386" && bits == 64 {
							reads = 0
						}
						x86ImplicitMultiplyNativeExactReads(t, pipeline.text, bits, reads)
					}
					x86PackedStringCompileObject(t, llc, triple, pipeline.text, pipeline.level)
				})
			}
		})
	}
}
