package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestGloblUnresolvedSizeNeverCreatesGuessedStorage(t *testing.T) {
	for _, expression := range []string{
		"$const_tlsSize", "$(machTimebaseInfo__size)", "$(16 + callbackArgs__size)",
	} {
		t.Run(expression, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "GLOBL ·data(SB),8,"+expression+"\n")
			if err != nil {
				t.Fatal(err)
			}
			global := file.Globl[0]
			if global.Size != 0 || global.SizeRaw != expression {
				t.Errorf("unresolved global acquired guessed storage: %#v", global)
			}
			// A caller-supplied numeric field cannot override unresolved source.
			file.Globl[0].Size = 64
			for _, direct := range []bool{false, true} {
				ctx := llvm.NewContext()
				var module llvm.Module
				if direct {
					module, err = translateModuleDirectInContext(ctx, file, Options{Goarch: "amd64"})
				} else {
					module, err = TranslateModuleInContext(ctx, file, Options{Goarch: "amd64"})
				}
				created := !module.IsNil()
				if created {
					module.Dispose()
				}
				ctx.Dispose()
				if created || !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("unresolved global produced a module: direct=%t created=%t error=%v", direct, created, err)
				}
			}
			var output strings.Builder
			if err := emitDataGlobals(&output, file, func(s string) string { return s }); !errors.Is(err, ErrProbeNeedsContext) || output.Len() != 0 {
				t.Errorf("text emitter guessed storage: output=%q error=%v", output.String(), err)
			}
		})
	}
}

func TestGloblSizeRejectsNonintegerOrMalformedExpressions(t *testing.T) {
	for _, expression := range []string{
		"$1.5", "$(1.5)", "$-1", "$(missing +)", "$(missing())",
		"$(missing[0])", "$()", "$\"size\"", "$(4 / 0)", "$(missing 8)",
	} {
		if _, err := parseGLOBLStmt("·data(SB),8," + expression); err == nil {
			t.Errorf("invalid storage size accepted: %s", expression)
		}
	}
}

func TestGloblResolvedSizesCompileAcrossArchitectures(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var source strings.Builder
	source.WriteString("#define COUNT 4\n")
	for index, expression := range []string{"$32", "$0x20", "$(1<<5)", "$(64/2)", "$(-(-32))", "$(COUNT*8)"} {
		fmt.Fprintf(&source, "GLOBL data%d(SB),8,%s\n", index, expression)
	}
	for _, target := range []struct {
		arch   Arch
		goarch string
		triple string
	}{
		{ArchAMD64, "386", "i386-unknown-linux-gnu"},
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu"},
		{ArchARM, "arm", "armv7-unknown-linux-gnueabihf"},
		{ArchARM64, "arm64", "aarch64-unknown-linux-gnu"},
		{ArchWASM, "wasm", "wasm32-unknown-unknown"},
	} {
		t.Run(target.goarch, func(t *testing.T) {
			goAssemblerOracleOutput(t, target.goarch, source.String(), "", true)
			file, err := Parse(target.arch, source.String())
			if err != nil {
				t.Fatal(err)
			}
			for _, global := range file.Globl {
				if global.Size != 32 || global.SizeRaw != "" {
					t.Fatalf("resolved integer expression changed: %#v", global)
				}
			}
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			module, err := TranslateModuleInContext(ctx, file, Options{Goarch: target.goarch, TargetTriple: target.triple})
			if err != nil {
				t.Fatal(err)
			}
			defer module.Dispose()
			compileLLVMToObject(t, llc, target.triple, "globals.ll", "globals.o", module.String())
		})
	}
}
