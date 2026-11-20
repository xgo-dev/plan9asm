//go:build darwin || (linux && amd64)

package plan9asm

import (
	"debug/elf"
	"debug/macho"
	"os"
	"runtime"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/nativeoracle"
)

// Compile/link the complete original-byte C oracle even without native x86
// execution. This gate needs no Rosetta, QEMU or AVX-capable host CPU.
func TestX86FloatingMinMaxNativeCCompileLinkOnly(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	compiler := []string{clang, "-target", triple}
	if runtime.GOOS == "darwin" {
		ctx, cancel := runtimeOracleStageContext(t)
		flags, err := nativeoracle.DarwinClangFlags(ctx, os.Environ())
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		compiler = append(compiler, flags...)
	}
	rows := x86MinMaxNativeCases()
	if len(rows) != 128 {
		t.Fatal("complete SSE/VEX native oracle inventory changed", len(rows))
	}
	source, declarations, driver := x86MinMaxNativeDriver(t, rows, triple)
	ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, "Go")
	if err != nil {
		t.Fatal(err)
	}
	execution := x86FloatCompareExecution{llc: llc, triple: triple, compiler: compiler}
	binary := execution.compileLLVM(t, "minmax-all-native-c", ir, driver, "-O2")
	if runtime.GOOS == "darwin" {
		object, err := macho.Open(binary)
		if err != nil {
			t.Fatal(err)
		}
		defer object.Close()
		if object.Cpu != macho.CpuAmd64 {
			t.Fatal("native C oracle linked for a different CPU", object.Cpu)
		}
	} else {
		object, err := elf.Open(binary)
		if err != nil {
			t.Fatal(err)
		}
		defer object.Close()
		if object.Machine != elf.EM_X86_64 {
			t.Fatal("native C oracle linked for a different CPU", object.Machine)
		}
	}
	t.Log("128 original-byte MIN/MAX programs and C oracle compiled+linked; NOT executed")
}
