//go:build darwin || (linux && amd64)

package plan9asm

import (
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/nativeoracle"
)

// These hosts have a real matching x86 C SDK/sysroot. Only compilation/linking
// occurs: even a host without AVX512 must validate the C oracle and .byte/AX
// constraints. Default Windows/ARM Linux source/object owners remain separate.
func TestX86Reciprocal14NativeCFixturesCompileLinkOnly(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 compiler/backend required for C fixture qualification")
	}
	triple := testTargetTriple(runtime.GOOS, "amd64")
	compiler := []string{clang, "-target", triple}
	if runtime.GOOS == "darwin" {
		ctx, cancel := runtimeOracleStageContext(t)
		flags, err := nativeoracle.DarwinClangFlags(ctx, os.Environ())
		cancel()
		if err != nil {
			t.Fatal("actual macOS SDK required for compile-only x86 fixture", err)
		}
		compiler = append(compiler, flags...)
	}
	execution := x86FloatCompareExecution{llc: llc, triple: triple, compiler: compiler}
	qualify := func(t *testing.T, source, declarations, mainC string) {
		ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, "Go")
		if err != nil {
			t.Fatal("C fixture's actual translated callback source rejected", err)
		}
		path := execution.compileLLVM(t, "rcp14-c-fixture", ir, mainC, "-O2")
		if runtime.GOOS == "darwin" {
			file, err := macho.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if file.Cpu != macho.CpuAmd64 {
				t.Fatal("compile-only fixture has foreign architecture", file.Cpu)
			}
		} else {
			file, err := elf.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if file.Machine != elf.EM_X86_64 {
				t.Fatal("compile-only fixture has foreign architecture", file.Machine)
			}
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("actual C fixture compiled+linked target=%s executableSHA=%x; NOT executed", triple, sha256.Sum256(payload))
	}
	for _, profile := range []int{5, 6} {
		var rows []x86Reciprocal14NativeRow
		for _, row := range x86Reciprocal14NativeRows() {
			if row.id < 132 && row.source != 0 && row.profile() == profile {
				rows = append(rows, row)
			}
		}
		for start := 0; start < len(rows); start += 32 {
			end := start + 32
			if end > len(rows) {
				end = len(rows)
			}
			t.Run(fmt.Sprintf("fault/profile%d/batch%d", profile, start/32), func(t *testing.T) {
				source, declarations, fixture := x86Reciprocal14NativeFaultProgram(t, rows[start:end], profile)
				qualify(t, source, declarations, fixture)
			})
		}
	}
	t.Run("values", func(t *testing.T) {
		rows := x86Reciprocal14NativeRows()[:8]
		source, declarations, prototypes := x86Reciprocal14NativeSource(rows, false)
		fixture := strings.NewReplacer("@PROTOTYPES@", prototypes, "@ROWS@", x86Reciprocal14NativeMetadata(rows, false),
			"@TRACE@", strconv.Quote(filepath.Join(t.TempDir(), "unexecuted.trace")), "@COUNT@", "1").Replace(x86Reciprocal14NativeValuesC)
		qualify(t, source, declarations, fixture)
	})
}
