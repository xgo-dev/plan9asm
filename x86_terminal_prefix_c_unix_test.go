//go:build darwin || (linux && amd64)

package plan9asm

import (
	"os"
	"runtime"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/nativeoracle"
)

// Validate the real fork/wait signal fixture and translated x86 callbacks even
// when this host cannot execute them. The Linux counterpart owns actual faults.
func TestX86TerminalPrefixFaultCFixtureCompileLinkOnly(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 compiler/backend required for the actual C fault fixture")
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	compiler := []string{clang, "-target", triple}
	if runtime.GOOS == "darwin" {
		stage, cancel := runtimeOracleStageContext(t)
		flags, err := nativeoracle.DarwinClangFlags(stage, os.Environ())
		cancel()
		if err != nil {
			t.Fatal("actual macOS SDK required", err)
		}
		compiler = append(compiler, flags...)
	}
	execution := x86FloatCompareExecution{llc: llc, triple: triple, compiler: compiler}
	source, declarations := x86TerminalPrefixReadSource()
	ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, "Go")
	if err != nil {
		t.Fatal("C fixture's actual translated callbacks rejected", err)
	}
	path := execution.compileLLVM(t, "terminal-prefix-fixture", ir, x86TerminalPrefixReadC(), "-O2")
	t.Logf("actual C fault fixture compiled and linked target=%s executable=%s; NOT executed", triple, path)
}
