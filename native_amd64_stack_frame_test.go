package plan9asm

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	llvm "github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

func TestNativeAMD64StackFrameTracksGoStackForms(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, row := range []struct {
			name, body string
			balanced   bool
		}{
			{"word", "PUSHW AX\nPOPW DX", true},
			{"flags", "PUSHFQ\nPOPFQ", true},
			{"adjust", "ADJSP $8\nADJSP $-8", true},
			{"segment_native_width", "PUSHL FS\nPOPL FS", true},
			{"unbalanced_push", "PUSHW AX", false},
			{"unbalanced_pop", "POPQ AX", false},
			{"unbalanced_flags", "PUSHFW", false},
			{"unbalanced_adjust", "ADJSP $8", false},
			{"mismatched_width", "PUSHW AX\nPOPQ AX", false},
		} {
			t.Run(goos+"/"+row.name, func(t *testing.T) {
				source := "#include \"textflag.h\"\nTEXT physical<>(SB),NOSPLIT|NOFRAME,$0-0\n" + row.body + "\nRET\n"
				opts := NativeOptions{GOOS: goos, GOARCH: "amd64", PackagePath: "probe"}
				if row.balanced {
					nativeAMD64OriginalObject(t, goos, source)
					nativeAMD64PhysicalObjects(t, source, opts)
					return
				}
				dir := t.TempDir()
				file := filepath.Join(dir, "original.s")
				if err := os.WriteFile(file, []byte(source), 0o600); err != nil {
					t.Fatal(err)
				}
				stage, cancel := runtimeOracleStageContext(t)
				defer cancel()
				observed, err := goasmcmd.Observe(stage, dir, append(os.Environ(),
					"GOROOT="+runtime.GOROOT(), "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off",
					"GOOS="+goos, "GOARCH=amd64"), filepath.Join(runtime.GOROOT(), "bin/go"),
					"tool", "asm", "-I", filepath.Join(runtime.GOROOT(), "pkg/include"), "-o", filepath.Join(dir, "original.o"), file)
				if stage.Err() != nil || err == nil || !observed.Waited || observed.ExitCode != 1 ||
					!strings.Contains(string(observed.Stderr), "unbalanced PUSH/POP") {
					t.Fatalf("unknown original Go stack rejection: %v; exit=%d\n%s\n%s", err, observed.ExitCode, observed.Stdout, observed.Stderr)
				}
				t.Log("actual Go rejected this complete source", string(observed.Stderr))
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				mod, err := TranslateNativeModule(ctx, []byte(source), opts)
				if err == nil {
					mod.Dispose()
					t.Fatal("Go-invalid stack acquired a native module")
				}
				if !mod.IsNil() {
					t.Fatal("rejected source returned a partial module")
				}
			})
		}
	}
}
