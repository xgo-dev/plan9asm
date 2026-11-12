//go:build go1.27

package plan9asm

import (
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestGoX86PackedStringOriginalSDKIndexCompleteSourceThreeAPIs(t *testing.T) {
	goX86PackedStringOriginalSDKIndexComplete(t, false)
}

func TestGoX86PackedStringOriginalSDKIndexCompleteSourceLLVM22Objects(t *testing.T) {
	goX86PackedStringOriginalSDKIndexComplete(t, true)
}

// Each root owns a fresh complete source/CPU producer and its original stage
// deadline. Object work cannot consume the source-only owner's five minutes.
func goX86PackedStringOriginalSDKIndexComplete(t *testing.T, objects bool) {
	llc := ""
	if objects {
		llc = findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc is required for complete original SDK objects")
		}
	}
	ctx, request, metadata, _ := numericalSDKAssemblyFixture(t)
	request.AssemblyFile = "index_amd64.s"
	source, err := CaptureGoX86SDKNumericalReadSource(ctx, request)
	if err != nil {
		t.Fatal("actual complete SDK source/CPU/compiler precondition", err)
	}
	defer closeNumericalConsumerSource(t, source)
	pkg, _, _ := numericalSDKOriginalTypedPackage(t, metadata, request.AssemblyFile)
	sizes := types.SizesFor("gc", "amd64")
	file := source.file
	if len(file.Funcs) != 3 || len(file.Data) != 0 || len(file.Globl) != 0 {
		t.Fatal("complete original three-TEXT member changed")
	}
	resolve := func(symbol string) string { return numericalNativeName(goTextSymbolForResolution(symbol), pkg.Path) }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", sizes, sizes, nil)
	if err != nil {
		t.Fatal("complete actual SDK declarations and private graph inventory", err)
	}
	options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: resolve, Sigs: sigs}
	bound, err := source.BindNumericalReads(ctx, pkg, file, options)
	if err != nil {
		t.Fatal("original CPU/read/source join", err)
	}
	original, err := os.ReadFile(filepath.Join(request.Directory, request.AssemblyFile))
	if err != nil {
		t.Fatal(err)
	}
	objectCount := 0
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			// Dispose every module/context before creating object artifacts.
			// Both object axes consume this unchanged complete original IR.
			ir, result := func() (string, error) {
				if api == "text" {
					return Translate(file, bound)
				}
				context := llvm.NewContext()
				defer context.Dispose()
				var module llvm.Module
				var result error
				if api == "module" {
					module, result = TranslateModuleInContext(context, file, bound)
				} else {
					var translated *GoModuleTranslation
					translated, result = translateGoModuleInContext(context, pkg, original, GoModuleOptions{GOOS: "linux", GOARCH: "amd64", TargetTriple: bound.TargetTriple,
						FileName: request.AssemblyFile, ResolveSym: bound.ResolveSym, NumericalReads: bound.NumericalReads})
					if translated != nil {
						module = translated.Module
					}
				}
				if !module.IsNil() {
					defer module.Dispose()
					return module.String(), result
				}
				return "", result
			}()
			if result != nil {
				t.Fatal("complete unchanged original SDK source must translate successfully", result)
			}
			if ir == "" || strings.Count(ir, "load volatile <16 x i8>") < 2 {
				t.Fatal("complete original full m128 reads missing")
			}
			t.Log("complete unchanged SDK numerical/IR source succeeded")
			if objects {
				for _, optimizeIR := range []bool{false, true} {
					input, label := ir, "IR-original"
					if optimizeIR {
						input, label = x86MulDivRoundOptimize(t, ir), "IR-O2"
					}
					for _, backend := range []string{"-O0", "-O2"} {
						t.Run(label+"/backend"+backend, func(t *testing.T) {
							x86PackedStringCompileObject(t, llc, bound.TargetTriple, input, backend)
							objectCount++
						})
					}
				}
			}
		})
	}
	if objects && objectCount != 12 {
		t.Fatal("complete three-API/IR/backend object denominator changed", objectCount)
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("original complete source changed after all consumers", err)
	}
	t.Logf("complete unchanged SDK source: LLVM objects=%d; no native execution claim", objectCount)
}
