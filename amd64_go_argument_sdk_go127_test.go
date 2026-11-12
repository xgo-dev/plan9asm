//go:build go1.27

package plan9asm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func amd64SDKArgumentTranslate(t *testing.T, api string, pkg GoPackage, file *File, options Options) (string, error) {
	t.Helper()
	if api == "text" {
		return Translate(file, options)
	}
	context := llvm.NewContext()
	defer context.Dispose()
	var module llvm.Module
	var err error
	if api == "module" {
		module, err = TranslateModuleInContext(context, file, options)
	} else {
		source := options.NumericalReads.source
		original, failure := os.ReadFile(filepath.Join(source.request.Directory, source.request.AssemblyFile))
		if failure != nil {
			t.Fatal(failure)
		}
		goos, _, _ := strings.Cut(source.request.Target, "/")
		result, failure := translateGoModuleInContext(context, pkg, original, GoModuleOptions{
			GOARCH: options.Goarch, GOOS: goos, TargetTriple: options.TargetTriple, FileName: source.request.AssemblyFile,
			NumericalReads: options.NumericalReads, ResolveSym: options.ResolveSym,
		})
		err = failure
		if result != nil {
			module = result.Module
		}
	}
	if !module.IsNil() {
		defer module.Dispose()
		if err == nil {
			return module.String(), nil
		}
	}
	return "", err
}

func amd64SDKTypedArgumentsWholeSource(t *testing.T, member string, apis ...string) {
	t.Helper()
	if len(apis) == 0 {
		apis = []string{"text", "module", "go-module"}
	}
	seen := make(map[string]bool)
	for _, api := range apis {
		if api != "text" && api != "module" && api != "go-module" || seen[api] {
			t.Fatal("invalid or repeated complete-source API", api)
		}
		seen[api] = true
	}
	var llc string
	if member == "compare_amd64.s" {
		llc = findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("complete original Compare objects require LLVM22 llc")
		}
	}
	ctx, request, metadata, _ := numericalSDKAssemblyFixture(t)
	request.AssemblyFile = member
	original, err := os.ReadFile(filepath.Join(request.Directory, member))
	if err != nil {
		t.Fatal(err)
	}
	source, err := CaptureGoX86SDKNumericalReadSource(ctx, request)
	if err != nil {
		t.Fatal("unchanged complete original SDK source/compiler/CPU join", err)
	}
	defer closeNumericalConsumerSource(t, source)
	pkg, file, options := numericalSDKOriginalTypedPackage(t, metadata, member)
	if len(file.Funcs) != 3 || len(file.Data)+len(file.Globl) != 0 || len(source.reads) != 1 ||
		len(metadata.observation.Objects.Sources) != len(metadata.guard.selection.SFiles) {
		t.Fatal("complete original three TEXT/all selected ASM/CPU inventory changed")
	}
	sizes := types.SizesFor("gc", "amd64")
	options.Sigs, err = goSigsForAsmFile(pkg, file, options.ResolveSym, "amd64", sizes, sizes, nil)
	if err != nil || len(options.Sigs) != 2 {
		t.Fatal("actual full original declaration inventory", err)
	}
	before, err := x86CallerSourceFingerprint(file)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := source.BindNumericalReads(ctx, pkg, file, options)
	if err != nil {
		t.Fatal("complete original typed carrier/compiler/source binding", err)
	}
	for _, api := range apis {
		t.Run(api, func(t *testing.T) {
			ir, err := amd64SDKArgumentTranslate(t, api, pkg, file, bound)
			if member == "equal_amd64.s" {
				// The complete source also has a custom tail-entry obligation;
				// either may reject before the unbound 8(DX) closure read.
				// The declared-byte consumer matrix independently checks that
				// exact hidden read. Neither rejection is whole-file success.
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("whole equal source acquired an unproved entry or closure contract", err)
				}
				t.Log("complete original equal source remains Context (NOT file pass):", err)
				return
			}
			if err != nil || ir == "" {
				t.Fatal("whole original Compare source still needs an independent contract", err)
			}
			context := llvm.NewContext()
			defer context.Dispose()
			module, err := parseIRModuleInContext(context, ir)
			if !module.IsNil() {
				defer module.Dispose()
			}
			if err != nil {
				t.Fatal("complete translated Compare module did not parse", err)
			}
			if err := amd64ArgumentCompareEntryTypes(module); err != nil {
				t.Fatal("complete original grouped entry transport differs", err)
			}
			for _, optimizeIR := range []bool{false, true} {
				t.Run(fmt.Sprintf("IR_O2=%t", optimizeIR), func(t *testing.T) {
					input := ir
					if optimizeIR {
						input = x86MulDivRoundOptimize(t, input)
					}
					for _, level := range []string{"-O0", "-O2"} {
						t.Run("backend"+level, func(t *testing.T) {
							x86PackedStringCompileObject(t, llc, options.TargetTriple, input, level)
						})
					}
				})
			}
		})
	}
	after, err := x86CallerSourceFingerprint(file)
	if err != nil || after != before {
		t.Fatal("consumer changed the original source", err)
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("final original numerical source Verify", err)
	}
	if err := metadata.Verify(ctx); err != nil {
		t.Fatal("final original complete header/archive Verify", err)
	}
	afterBytes, err := os.ReadFile(filepath.Join(request.Directory, member))
	if err != nil || sha256.Sum256(afterBytes) != sha256.Sum256(original) {
		t.Fatal("original SDK bytes changed", err)
	}
	role := "Context only; no object/native/closure/stack proof"
	if member == "compare_amd64.s" {
		role = fmt.Sprintf("%d LLVM22 object axes; no native/closure/stack proof", 4*len(apis))
	}
	t.Logf("member=%s APIs=%v completeTEXTs=3 declaredEntries=2 allSelectedASM=%d sourceSHA=%x; %s", member, apis, len(metadata.guard.selection.SFiles), sha256.Sum256(original), role)
}

// Each API owns a fresh complete capture, before/final verification and all
// four object axes. Scheduling them independently avoids spending one shared
// five-minute source lease across three expensive compiler observations.
// Together these roots retain the entire original three-TEXT, twelve-object
// scope; they do not cache or share mutable source observations.
func TestGoX86SDKAMD64CompareTypedArgumentsWholeSource(t *testing.T) {
	amd64SDKTypedArgumentsWholeSource(t, "compare_amd64.s", "text")
}

func TestGoX86SDKAMD64CompareTypedArgumentsWholeSourceModule(t *testing.T) {
	amd64SDKTypedArgumentsWholeSource(t, "compare_amd64.s", "module")
}

func TestGoX86SDKAMD64CompareTypedArgumentsWholeSourceGoModule(t *testing.T) {
	amd64SDKTypedArgumentsWholeSource(t, "compare_amd64.s", "go-module")
}

func TestGoX86SDKAMD64EqualTypedArgumentsWholeSource(t *testing.T) {
	amd64SDKTypedArgumentsWholeSource(t, "equal_amd64.s")
}
