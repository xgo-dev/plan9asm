//go:build go1.27

package plan9asm

import (
	"errors"
	"go/types"
	"reflect"
	"strings"
	"testing"
)

func numericalSDKMapsReadCapture(t *testing.T, arch, name string) (*GoX86NumericalReadSource, error) {
	t.Helper()
	goos, selectedArch, target := "linux", arch, "linux/"+arch
	if os, architecture, paired := strings.Cut(arch, "/"); paired {
		goos, selectedArch, target = os, architecture, arch
	}
	ctx, request := sdkASMDataRequest(t, selectedArch, "internal/runtime/maps")
	request.Target = target
	for index, pair := range request.Environment {
		if strings.HasPrefix(pair, "GOOS=") {
			request.Environment[index] = "GOOS=" + goos
		}
	}
	owner, err := CaptureGoNumericalStorageOwner(ctx, GoNumericalStorageCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, PackagePath: request.PackagePath, Target: request.Target,
		Environment: request.Environment, SDKGlobals: true,
		Variables: []GoNumericalStorageReference{{PackagePath: request.PackagePath, Name: "aeskeysched"}},
	})
	if err != nil {
		t.Fatal("actual selected mutable SDK global precondition", err)
	}
	t.Cleanup(owner.Close)
	data, err := CaptureGoX86SDKASMDataSource(ctx, request)
	if err != nil {
		t.Fatal("actual complete SDK maps source/object/DATA precondition", err)
	}
	t.Cleanup(func() {
		if err := data.Close(); err != nil {
			t.Error(err)
		}
	})
	literals, err := CaptureGoX86SDKReadonlyLiteralDataOwner(ctx, data)
	if err != nil {
		t.Fatal("independent actual private readonly initializer precondition", err)
	}
	t.Cleanup(func() {
		if err := literals.Close(); err != nil {
			t.Error(err)
		}
	})
	source, err := CaptureGoX86SDKNumericalReadSource(ctx, GoX86NumericalReadCaptureRequest{
		GoBinary: request.GoBinary, Directory: request.Directory, PackagePath: request.PackagePath, Target: request.Target,
		Environment: request.Environment, AssemblyFile: name, Owners: []*GoNumericalStorageOwner{owner}, ReadonlyLiterals: literals,
	})
	if err != nil {
		return source, err
	}
	t.Cleanup(func() { closeNumericalConsumerSource(t, source) })
	return source, nil
}

func TestGoX86NumericalReadOriginalSDKMapsScalarRegisterEntry(t *testing.T) {
	source, err := numericalSDKMapsReadCapture(t, "amd64", "memhash_nosimd_amd64.s")
	if err != nil {
		t.Fatal("complete SDK source/native/read join", err)
	}
	if len(source.file.Funcs) != 2 || len(source.reads) != 6 {
		t.Fatal("actual complete scalar maps source/native read inventory changed")
	}
	pkg, _, options := numericalSDKLiteralPackage(t, source.literals.source, source.request.AssemblyFile)
	file := source.file
	for name, args := range map[string][]LLVMType{"memHash32AES": {I32, I64}, "memHash64AES": {I64, I64}} {
		sig := options.Sigs[pkg.Path+"."+name]
		declaration := pkg.Types.Scope().Lookup(name).(*types.Func).Type().(*types.Signature)
		if !reflect.DeepEqual(sig.Args, args) || sig.Ret != I64 || len(sig.ArgRegs) != 0 ||
			len(sig.Frame.Params) != 2 || sig.Frame.Params[0].Type != args[0] || sig.Frame.Params[1].Type != I64 ||
			declaration.Params().At(0).Name() != "k" || declaration.Params().At(1).Name() != "h" {
			t.Fatal("original integer language declarations were replaced by native comments or pointer transport", name, sig)
		}
	}
	for _, fn := range file.Funcs {
		if !strings.HasSuffix(fn.Sym, "<ABIInternal>") {
			t.Fatal("original SDK entry selector is absent")
		}
	}
	bound, err := source.BindNumericalReads(source.sdk.originalContext, pkg, file, options)
	if err != nil {
		t.Fatal("complete original register declaration binding", err)
	}
	for _, api := range []string{"text", "module", "context", "go-module"} {
		t.Run(api, func(t *testing.T) {
			ir := numericalFamilyTranslate(t, api, pkg, file, bound)
			if !strings.Contains(ir, "external global [128 x i8]") || strings.Contains(ir, "constant [128") ||
				strings.Count(ir, "aesenc ($2), $0") != 6 {
				t.Fatal("original mutable SDK AES read/entry behavior lost", ir)
			}
			numericalLLVM22Axes(t, ir, options.TargetTriple, nil)
		})
	}
	for _, selected := range []string{"original-selector", "canonical-declaration"} {
		t.Run(selected+"-resolver-guard", func(t *testing.T) {
			changed := options
			changed.ResolveSym = func(symbol string) string {
				if symbol == "·memHash32AES<ABIInternal>" && selected == "original-selector" ||
					symbol == "·memHash32AES" && selected == "canonical-declaration" {
					return pkg.Path + ".foreignEntry"
				}
				return options.ResolveSym(symbol)
			}
			if _, err := source.BindNumericalReads(source.sdk.originalContext, pkg, file, changed); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("different source/logical resolver acquired the original native ABI entry", err)
			}
		})
	}
}

func TestGoX86NumericalReadOriginalSDKMapsRemainingMemoryContracts(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			source, err := numericalSDKMapsReadCapture(t, arch, "memhash_"+arch+".s")
			if err != nil {
				t.Fatal("complete original literal/source/native observation", err)
			}
			pkg, _, options := numericalSDKLiteralPackage(t, source.literals.source, source.request.AssemblyFile)
			want := 4
			functions := 2
			if arch == "386" {
				want = 2
				functions = 4
			}
			if len(source.file.Funcs) != functions {
				t.Fatal("complete original function inventory changed", len(source.file.Funcs))
			}
			literals := make(map[string]int64)
			for _, global := range source.file.Globl {
				literals[global.Sym] = global.Size
			}
			accesses, addressBitObservers := 0, 0
			for _, fn := range source.file.Funcs {
				// Query every original function, including the alignment observer.
				// No subset is translated, rebound, or given a public certificate.
				sig := options.Sigs[options.ResolveSym(fn.Sym)]
				facts, err := proveX86SDKLiteralAccesses(fn, sig, arch, literals)
				if err != nil {
					if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "linked address-bit observation requires independent native alignment or physical identity") {
						t.Fatal("original literal-only analysis reached another unclosed source role", err)
					}
					addressBitObservers++
					continue
				}
				accesses += len(facts)
			}
			if accesses != want || addressBitObservers != 1 {
				t.Fatal("original readonly envelopes or address observer inventory changed", accesses, addressBitObservers)
			}
			bound, err := source.BindNumericalReads(source.sdk.originalContext, pkg, source.file, options)
			if bound.NumericalReads != nil || !errors.Is(err, ErrProbeNeedsContext) ||
				!strings.Contains(err.Error(), "linked address-bit observation requires independent native alignment or physical identity") {
				t.Fatal("full original file acquired an unauthenticated linked-address/boolean contract", err)
			}
		})
	}
}
