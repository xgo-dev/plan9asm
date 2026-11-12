package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86CallerSavedGRuntimeAssembly(assembly, mode string) string {
	// Reuse independent W/L/Q LEA mathematics, including preservation of the
	// initialized high bytes. The incoming g never supplies numerical data.
	assembly = strings.ReplaceAll(assembly, "AX", "R14")
	save, restore := "WORD $0x5641\n", "WORD $0x5e41\n"
	if mode == "named" {
		save, restore = "PUSHQ R14\n", "POPQ R14\n"
	} else if mode == "nested" {
		save = "PUSHQ R14\nMOVQ $91,R14\nPUSHQ R14\n"
		restore = "POPQ R14\nPOPQ R14\n"
	}
	assembly = strings.ReplaceAll(assembly, "LONG $0xf8e48348\n", "LONG $0xf8e48348\n"+save)
	return strings.ReplaceAll(assembly, "WORD $0x8948\nBYTE $0xec", restore+"WORD $0x8948\nBYTE $0xec")
}

func x86CallerSavedGOriginalObserver() (goTest, assembly string) {
	var source strings.Builder
	source.WriteString(`
// This native observer is a separate test-only oracle, never a numerical
// input or declaration used to authorize the translated caller's source.
func savedGContext() (gvalue, spvalue, bpvalue uint64)
func TestOriginalSavedGContext(t *testing.T) {
 for iteration := 0; iteration < 64; iteration++ {
`)
	for _, form := range x86CallerLEARuntimeForms() {
		fmt.Fprintf(&source, `
  {
   x, y := []uint64{11,23}, []uint64{29,31}
   beforeG, beforeSP, beforeBP := savedGContext()
   _ = Call%s(x,y)
   afterG, afterSP, afterBP := savedGContext()
   if beforeG == 0 || beforeG != afterG || beforeSP != afterSP || beforeBP != afterBP {
    t.Fatalf("%s changed native caller context g=%%x/%%x SP=%%x/%%x BP=%%x/%%x",
     beforeG,afterG,beforeSP,afterSP,beforeBP,afterBP)
   }
  }
`, form.name, form.name)
	}
	source.WriteString(" }\n}\n")
	return source.String(), `TEXT ·savedGContext(SB),4,$0-24
MOVQ R14,AX
MOVQ AX,gvalue+0(FP)
MOVQ SP,AX
MOVQ AX,spvalue+8(FP)
MOVQ BP,AX
MOVQ AX,bpvalue+16(FP)
RET
`
}

func TestCrossLinuxRuntimeMatrixX86GoCallerPrivateSavedG(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("saved-g execution requires the Linux/amd64 runtime counterpart")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	for _, mode := range []string{"raw", "named", "nested"} {
		t.Run(mode, func(t *testing.T) {
			goSource, original, goTest, cOracle := x86CallerLEARuntimeSources()
			assembly := x86CallerSavedGRuntimeAssembly(original, mode)
			observer, observerAssembly := x86CallerSavedGOriginalObserver()
			dir := t.TempDir()
			for name, source := range map[string]string{
				"go.mod": "module caller\n\ngo 1.20\n", "value.go": goSource,
				"value_amd64.s": assembly, "value_test.go": goTest + observer,
				"context_test_amd64.s": observerAssembly,
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
			}
			stage, cancel := runtimeOracleStageContext(t)
			defer cancel()
			command := exec.CommandContext(stage, "go", "test", "-p=2", "-vet=off", "-count=1", ".")
			command.Dir = dir
			command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local",
				"GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
			if output, err := runtimeOracleCombinedOutput(stage, command); err != nil {
				t.Fatalf("actual Go saved-g numerical/context oracle: %v\n%s", err, output)
			}

			pkg := x86CallerRuntimePackage(t, goSource, assembly)
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			triple := testTargetTriple(runtime.GOOS, "amd64")
			translation, err := translateGoModuleInContext(ctx, pkg, []byte(assembly), GoModuleOptions{
				FileName: "value_amd64.s", GOARCH: "amd64", TargetTriple: triple,
				ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer translation.Module.Dispose()
			var runner []string
			if crossRosetta {
				runner = []string{"/usr/bin/arch", "-x86_64"}
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "saved_g", triple,
				translation.Module.String(), cOracle, runner)
		})
	}
}
