//go:build go1.27

package plan9asm

import (
	"errors"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

type foreignABI0CallFixture struct {
	name, target, declarations, outgoing string
	args                                 []LLVMType
}

func foreignABI0CallFixtures() []foreignABI0CallFixture {
	return []foreignABI0CallFixture{
		{
			name: "SDK-copy-pointer-pointer-word", target: "runtime.memmove",
			declarations: "import _ \"runtime\"\nfunc Value(dst, src *byte, n uintptr) uint64\n",
			outgoing:     "MOVQ AX,0(SP)\nMOVQ BX,8(SP)\nMOVQ CX,16(SP)\n",
			args:         []LLVMType{Ptr, Ptr, I64},
		},
		{
			name: "SDK-clear-pointer-word", target: "runtime.memclrNoHeapPointers",
			declarations: "import _ \"runtime\"\nfunc Value(dst, src *byte, n uintptr) uint64\n",
			outgoing:     "MOVQ AX,0(SP)\nMOVQ CX,8(SP)\n",
			args:         []LLVMType{Ptr, I64},
		},
		{
			name: "local-Go-body-pointer-pointer-word", target: "example.invalid/framefixture.Callee",
			declarations: "func Value(dst, src *byte, n uintptr) uint64\n" +
				"//go:noinline\nfunc Callee(dst, src *byte, n uintptr) { if n != 0 { *dst = *src } }\n",
			outgoing: "MOVQ AX,0(SP)\nMOVQ BX,8(SP)\nMOVQ CX,16(SP)\n",
			args:     []LLVMType{Ptr, Ptr, I64},
		},
	}
}

func foreignABI0CallAssembly(fixture foreignABI0CallFixture) string {
	target := strings.ReplaceAll(fixture.target, ".", "·")
	if strings.HasPrefix(fixture.target, "example.invalid/framefixture.") {
		target = "·Callee"
	}
	return "TEXT ·Value(SB),4,$64-32\n" +
		"MOVQ dst+0(FP),AX\nMOVQ src+8(FP),BX\nMOVQ n+16(FP),CX\n" + fixture.outgoing +
		"MOVQ AX,24(SP)\nMOVQ BX,32(SP)\nMOVQ CX,40(SP)\nMOVQ $37,48(SP)\n" +
		"CALL " + target + "(SB)\n" +
		"MOVQ 24(SP),R8\nMOVQ 32(SP),R9\nMOVQ 40(SP),AX\nADDQ 48(SP),AX\n" +
		"MOVQ AX,ret+24(FP)\nRET\n"
}

func foreignABI0Fixture(t *testing.T, fixture foreignABI0CallFixture, assembly string) (GoPackage, GoAMD64FrameCaptureRequest, *File, Options) {
	t.Helper()
	_, request := goAMD64FrameSourceFixture(t)
	filename := filepath.Join(request.Directory, "value.go")
	source := "package framefixture\n" + fixture.declarations
	if err := os.WriteFile(filename, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), []byte(assembly), 0600); err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, filename, source, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := (&types.Config{Sizes: types.SizesFor("gc", "amd64"), Importer: importer.Default()}).Check(
		"example.invalid/framefixture", fset, []*ast.File{syntax}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkg := GoPackage{Path: typed.Path(), Types: typed, Syntax: []*ast.File{syntax}, Imports: make(map[string]*types.Package)}
	for _, dependency := range typed.Imports() {
		pkg.Imports[dependency.Path()] = dependency
	}
	caller, err := DeriveGoFuncABI0Signature(pkg.Path+".Value", typed.Scope().Lookup("Value").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	callee := FuncSig{Name: fixture.target, Args: append([]LLVMType(nil), fixture.args...), Ret: Void}
	for index, typ := range fixture.args {
		callee.Frame.Params = append(callee.Frame.Params, FrameSlot{Offset: int64(index) * 8, Type: typ, Index: index, Field: -1})
	}
	// ABI0 parameter metadata intentionally has empty Name fields; the real
	// producer retains source names on flattened results, not parameters.
	if fixture.target == pkg.Path+".Callee" {
		actual, err := DeriveGoFuncABI0Signature(fixture.target, typed.Scope().Lookup("Callee").(*types.Func), "amd64", types.SizesFor("gc", "amd64"))
		if err != nil || !reflect.DeepEqual(actual, callee) {
			t.Fatalf("actual/consumer complete ABI0 metadata differs: err=%v\nactual=%#v\nconsumer=%#v", err, actual, callee)
		}
		callee = actual
	}
	// This independent literal layout is a consumer expectation, never an SDK
	// source/ABI certificate. Capture must derive and authenticate its own callee.
	file, err := Parse(ArchAMD64, assembly)
	if err != nil {
		t.Fatal(err)
	}
	return pkg, request, file, Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", ResolveSym: testResolveSym(pkg.Path),
		Sigs: map[string]FuncSig{caller.Name: caller, callee.Name: callee},
	}
}

func foreignABI0OriginalLink(t *testing.T, request GoAMD64FrameCaptureRequest) {
	t.Helper()
	// A package archive alone leaves cross-package ABI0 references unresolved.
	// Link an owned complete main so a missing SDK adapter is fixture failure,
	// not translator RED. The child is not a declaration/source authority.
	directory := filepath.Join(request.Directory, "linkprobe")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	main := "package main\nimport probe \"example.invalid/framefixture\"\n" +
		"func main() { var a, b byte; if probe.Value(&a, &b, 0) != 37 { panic(\"call result\") } }\n"
	if err := os.WriteFile(filepath.Join(directory, "main.go"), []byte(main), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	env := append(append([]string(nil), request.Environment...), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0",
		"GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off", "GOFLAGS=", "GOPROXY=off")
	binary := filepath.Join(t.TempDir(), "original-linked")
	output, err := goasmcmd.Run(ctx, request.Directory, env, request.GoBinary, "build", "-p=1", "-o", binary, "./linkprobe")
	if err != nil {
		t.Fatalf("original Go complete main did not link the actual ABI0 target (not translator RED): %v\n%s", err, output)
	}
	if info, err := os.Stat(binary); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		t.Fatal("original Go omitted complete linked executable", err)
	}
}

func TestGoAMD64FrameForeignABI0OriginalGoLink(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, fixture := range foreignABI0CallFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			_, request, _, _ := foreignABI0Fixture(t, fixture, foreignABI0CallAssembly(fixture))
			foreignABI0OriginalLink(t, request)
		})
	}
}

func TestGoAMD64FrameForeignABI0PointersCaptureAndObjects(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	for _, fixture := range foreignABI0CallFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			pkg, request, file, options := foreignABI0Fixture(t, fixture, foreignABI0CallAssembly(fixture))
			foreignABI0OriginalLink(t, request)
			t.Run("signatures-alone", func(t *testing.T) {
				fixedLocalAPIs(t, pkg, file, options, func(t *testing.T, ir string, err error) {
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("callee signature alone authorized a physical frame/call", err, ir)
					}
				})
			})
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					foreignABI0CallObjects(t, fixture, ir, err)
				})
		})
	}
}

func foreignABI0CallObjects(t *testing.T, fixture foreignABI0CallFixture, ir string, err error) {
	t.Helper()
	global := llvmGlobal(fixture.target)
	// LLVM's printer can remove optional identifier quotes. Only canonicalize
	// this exact target token to the existing formatter.
	normalized := strings.ReplaceAll(ir, "@"+fixture.target+"(", global+"(")
	call := "call void " + global + "(ptr "
	if err != nil || !strings.Contains(normalized, call) || strings.Contains(normalized, "define void "+global+"(") {
		t.Fatal("an actual separate typed ABI0 callee was rejected, dropped or privately inlined", err, ir)
	}
	ordinaryGoFrameCallObjects(t, ir)
}

func TestGoAMD64FrameForeignABI0SDKDefaultsStayOwnedAndStrict(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	fixture := foreignABI0CallFixtures()[0]
	pkg, request, file, options := foreignABI0Fixture(t, fixture, foreignABI0CallAssembly(fixture))
	expected := options.Sigs[fixture.target]
	delete(options.Sigs, fixture.target)
	foreignABI0OriginalLink(t, request)
	t.Run("owner-derived-three-APIs", func(t *testing.T) {
		fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
			func(t *testing.T, ir string, err error) {
				foreignABI0CallObjects(t, fixture, ir, err)
			})
		if _, changed := options.Sigs[fixture.target]; changed {
			t.Fatal("binding inserted a callee into the consumer's original map")
		}
	})
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	owner, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	}()
	bound, err := owner.BindFixedLocal(ctx, pkg, file, options)
	if err != nil || !reflect.DeepEqual(bound.Sigs[fixture.target], expected) {
		t.Fatalf("owner default differs from independently expected complete ABI0 metadata: %v\nactual=%#v\nexpected=%#v", err, bound.Sigs[fixture.target], expected)
	}
	t.Run("public-default-slices-cannot-change-owner", func(t *testing.T) {
		changed := bound.Sigs[fixture.target]
		changed.Frame.Params[0].Offset++
		bound.Sigs[fixture.target] = changed
		if !reflect.DeepEqual(owner.callees[fixture.target].signature, expected) {
			t.Fatal("public default slices alias the private source declaration")
		}
		fixedLocalAPIs(t, pkg, file, bound, func(t *testing.T, ir string, err error) {
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("mutated derived metadata retained a callable signature", err, ir)
			}
		})
	})
	t.Run("caller-signature-is-not-derived", func(t *testing.T) {
		missing := options
		missing.Sigs = nil
		if _, err := owner.BindFixedLocal(ctx, pkg, file, missing); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("a foreign SDK callee granted the caller's missing signature", err)
		}
	})
	t.Run("same-package-callee-stays-explicit", func(t *testing.T) {
		local := foreignABI0CallFixtures()[2]
		pkg, request, file, options := foreignABI0Fixture(t, local, foreignABI0CallAssembly(local))
		delete(options.Sigs, local.target)
		actual, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := actual.Close(); err != nil {
				t.Error(err)
			}
		}()
		if _, err := actual.BindFixedLocal(ctx, pkg, file, options); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("the foreign SDK default widened same-package consumer metadata", err)
		}
	})
}

func TestGoAMD64FrameForeignABI0SuppliedLayoutAndSourceBoundaries(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	fixture := foreignABI0CallFixtures()[0]
	pkg, request, file, options := foreignABI0Fixture(t, fixture, foreignABI0CallAssembly(fixture))
	foreignABI0OriginalLink(t, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil {
		t.Fatal("actual SDK callee must capture before its independent consumer negatives", err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	}()
	t.Logf("actual SDK callee complete signature=%#v\nconsumer=%#v", source.callees[fixture.target].signature, options.Sigs[fixture.target])
	for _, name := range []string{"wrong-register-ABI", "wrong-slot", "wrong-pointer-width", "foreign-resolver"} {
		t.Run(name, func(t *testing.T) {
			changed := options
			changed.Sigs, err = cloneFixedLocalSigs(options.Sigs)
			if err != nil {
				t.Fatal(err)
			}
			sig := changed.Sigs[fixture.target]
			switch name {
			case "wrong-register-ABI":
				sig.ArgRegs = []Reg{AX, BX, CX}
			case "wrong-slot":
				sig.Frame.Params[1].Offset++
			case "wrong-pointer-width":
				sig.Args[0], sig.Frame.Params[0].Type = I32, I32
			case "foreign-resolver":
				changed.ResolveSym = func(string) string { return "other.Callee" }
			}
			changed.Sigs[fixture.target] = sig
			if _, err := source.BindFixedLocal(ctx, pkg, file, changed); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("supplied ABI/resolver substituted an actual SDK call", err)
			}
		})
	}
	// A rejected consumer does not substitute for this independent source test:
	// use a fresh producer before changing the actual declaration on disk.
	mutationSource, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil {
		t.Fatal("fresh producer needed before source-mutation negative", err)
	}
	defer func() {
		if err := mutationSource.Close(); err != nil {
			t.Error(err)
		}
	}()
	path := filepath.Join(request.Directory, "value.go")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	after := strings.Replace(string(before), "n uintptr", "n uint32", 1)
	if after == string(before) {
		t.Fatal("source mutation did not change the real declaration")
	}
	if err := os.WriteFile(path, []byte(after), 0600); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(mutationSource.Verify(ctx), ErrProbeNeedsContext) {
		t.Fatal("mutated source retained its call lease")
	}
}

func TestGoAMD64FrameForeignABI0SDKOwnerCannotBeRetaggedOrRevived(t *testing.T) {
	goAMD64FramePrepareOwnedToolCache(t)
	fixture := foreignABI0CallFixtures()[0]
	pkg, request, _, _ := foreignABI0Fixture(t, fixture, foreignABI0CallAssembly(fixture))
	foreignABI0OriginalLink(t, request)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil {
		t.Fatal("actual SDK call must capture before source-owner retagging", err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	}()
	selected, found := source.imports["runtime"]
	if !found || !selected.Standard || selected.Export == "" || !filepath.IsAbs(selected.Dir) {
		t.Fatal("SDK target lost its actual private selected-source owner")
	}
	changed := selected
	changed.Standard = false
	source.imports["runtime"] = changed
	if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
		t.Fatal("retagged SDK package still authorized the callee")
	}
	source.imports["runtime"] = selected
	if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
		t.Fatal("restoring selected metadata revived a revoked SDK call owner")
	}
}
