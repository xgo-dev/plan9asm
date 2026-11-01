package gotoolprofile

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm"
)

func amd64OriginalFixedLocalFixture(t *testing.T) (AMD64OriginalObservationRequest, plan9asm.GoPackage, *plan9asm.File, plan9asm.Options, string) {
	t.Helper()
	request := amd64OriginalObservationFixture(t, "numeric")
	declaration := "package observation\nfunc Value(a,b,c,d uint64) uint64\n"
	assembly := `#include "textflag.h"
#include "local.h"
TEXT ·Value(SB),NOSPLIT,$160-40
MOVQ a+0(FP),AX
MOVQ b+8(FP),CX
MOVQ c+16(FP),DX
MOVQ d+24(FP),BX
MOVQ SP,R11
MOVQ $31,R9
NOTQ R9
ANDQ R9,SP
ADDQ $ADVANCE,SP
MOVQ R11,96(SP)
MOVQ AX,16(SP)
MOVQ CX,24(SP)
MOVQ DX,48(SP)
MOVQ BX,56(SP)
MOVOU 48(SP),X0
PADDL 16(SP),X0
MOVQ X0,AX
MOVQ 96(SP),R11
MOVQ R11,SP
MOVQ AX,ret+32(FP)
RET
`
	for name, source := range map[string]string{"value.go": declaration, "value_amd64.s": assembly, "local.h": "#define ADVANCE 32\n"} {
		if err := os.WriteFile(filepath.Join(request.Directory, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, filepath.Join(request.Directory, "value.go"), declaration, 0)
	if err != nil {
		t.Fatal(err)
	}
	sizes := types.SizesFor("gc", "amd64")
	typed, err := (&types.Config{Sizes: sizes}).Check(request.PackagePath, fset, []*ast.File{syntax}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := plan9asm.DeriveGoFuncABI0Signature(request.PackagePath+".Value", typed.Scope().Lookup("Value").(*types.Func), "amd64", sizes)
	if err != nil {
		t.Fatal(err)
	}
	// The existing root factory independently reconstructs the same actual CPP.
	expanded := strings.Replace(assembly, "#include \"textflag.h\"", "#define NOSPLIT 4", 1)
	expanded = strings.Replace(expanded, "#include \"local.h\"", "#define ADVANCE 32", 1)
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, expanded)
	if err != nil {
		t.Fatal(err)
	}
	pkg := plan9asm.GoPackage{Path: typed.Path(), Types: typed, Syntax: []*ast.File{syntax}}
	options := plan9asm.Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", typed.Path()+".", 1) },
		Sigs:       map[string]plan9asm.FuncSig{sig.Name: sig},
	}
	return request, pkg, file, options, expanded
}

func amd64OriginalFixedLocalAPIs(t *testing.T, pkg plan9asm.GoPackage, file *plan9asm.File, options plan9asm.Options, assembly string, wantContext bool) {
	t.Helper()
	check := func(t *testing.T, ir string, err error) {
		t.Helper()
		if wantContext {
			if err == nil || ir != "" {
				t.Fatalf("revoked or unbound original source retained permission: %v", err)
			}
		} else if err != nil || !strings.Contains(ir, "fixed_local_native") {
			t.Fatalf("independently captured fixed-local source failed: %v", err)
		}
	}
	t.Run("Translate", func(t *testing.T) {
		ir, err := plan9asm.Translate(file, options)
		check(t, ir, err)
	})
	t.Run("Module", func(t *testing.T) {
		ctx := llvm.NewContext()
		defer ctx.Dispose()
		module, err := plan9asm.TranslateModuleInContext(ctx, file, options)
		ir := ""
		if !module.IsNil() {
			defer module.Dispose()
			ir = module.String()
		}
		check(t, ir, err)
	})
	t.Run("GoModule", func(t *testing.T) {
		translated, err := plan9asm.TranslateGoModule(pkg, []byte(assembly), plan9asm.GoModuleOptions{
			GOOS: "linux", GOARCH: "amd64", TargetTriple: options.TargetTriple,
			ResolveSym: options.ResolveSym, Sizes: types.SizesFor("gc", "amd64"),
			ManualSig: func(name string) (plan9asm.FuncSig, bool) { sig, found := options.Sigs[name]; return sig, found },
		})
		ir := ""
		if translated != nil && !translated.Module.IsNil() {
			defer translated.Module.Dispose()
			ir = translated.Module.String()
		}
		check(t, ir, err)
	})
}

func TestAMD64OriginalFixedLocalIndependentFactoryAndRevocation(t *testing.T) {
	for _, axis := range []string{"close-owner", "close-binding", "source", "export", "selection", "metadata", "include", "expired"} {
		t.Run(axis, func(t *testing.T) {
			request, pkg, file, options, assembly := amd64OriginalFixedLocalFixture(t)
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded)
			if err != nil {
				t.Fatal(err)
			}
			defer observed.Close()
			amd64OriginalFixedLocalAPIs(t, pkg, file, options, assembly, true)
			bound, binding, err := observed.BindFixedLocal(ctx, pkg, file, "value_amd64.s", options)
			if err != nil {
				t.Fatal(err)
			}
			if err := binding.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			amd64OriginalFixedLocalAPIs(t, pkg, file, bound, assembly, false)
			switch axis {
			case "close-owner":
				if err := observed.Close(); err != nil {
					t.Fatal(err)
				}
			case "close-binding":
				if err := binding.Close(); err != nil {
					t.Fatal(err)
				}
			case "expired":
				cancel()
			case "export":
				export := observed.state.packages[request.PackagePath].Export
				cache := originalObservationEnvironment(request.Environment, "GOCACHE")
				relative, err := filepath.Rel(cache, export)
				if err != nil || !filepath.IsLocal(relative) {
					t.Fatal("export mutation is not in the explicitly owned fixture cache")
				}
				original, err := os.ReadFile(export)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := os.WriteFile(export, original, 0600); err != nil {
						t.Error(err)
					}
				})
				if err := os.WriteFile(export, append(append([]byte(nil), original...), 0), 0600); err != nil {
					t.Fatal(err)
				}
			case "source":
				if err := os.WriteFile(filepath.Join(request.Directory, "value.go"), []byte("package observation\nfunc Value(a,b,c,d int64) uint64\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "selection":
				if err := os.WriteFile(filepath.Join(request.Directory, "late.go"), []byte("package observation\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "metadata":
				if err := os.WriteFile(filepath.Join(request.Directory, "go.mod"), []byte("module example.invalid/changed\ngo 1.20\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "include":
				if err := os.WriteFile(filepath.Join(request.Directory, "local.h"), []byte("#define ADVANCE 64\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := binding.Verify(ctx); err == nil {
				t.Fatal("changed/closed observation retained its owning actual-object binding")
			}
			amd64OriginalFixedLocalAPIs(t, pkg, file, bound, assembly, true)
		})
	}
}

func TestAMD64OriginalFixedLocalQueryAndJSONCannotMintPermission(t *testing.T) {
	request, pkg, file, options, assembly := amd64OriginalFixedLocalFixture(t)
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	defer observed.Close()
	bound, _, err := observed.BindFixedLocal(ctx, pkg, file, "value_amd64.s", options)
	if err != nil {
		t.Fatal(err)
	}
	for _, axis := range []string{"options", "owner", "binding", "different-file", "changed-layout"} {
		t.Run(axis, func(t *testing.T) {
			switch axis {
			case "options":
				data, err := json.Marshal(bound.Sigs)
				if err != nil {
					t.Fatal(err)
				}
				changed := options
				if err := json.Unmarshal(data, &changed.Sigs); err != nil {
					t.Fatal(err)
				}
				amd64OriginalFixedLocalAPIs(t, pkg, file, changed, assembly, true)
			case "owner":
				var unbound AMD64OriginalPackageObservation
				if _, _, err := unbound.BindFixedLocal(ctx, pkg, file, "value_amd64.s", options); err == nil {
					t.Fatal("zero owner minted a source capability")
				}
			case "binding":
				var unbound AMD64OriginalFixedLocalBinding
				if err := unbound.Verify(ctx); err == nil {
					t.Fatal("zero binding became ready")
				}
			case "different-file":
				changed, err := plan9asm.Parse(plan9asm.ArchAMD64, strings.Replace(assembly, "PADDL", "PADDQ", 1))
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := observed.BindFixedLocal(ctx, pkg, changed, "value_amd64.s", options); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
					t.Fatalf("source mutation accepted: %v", err)
				}
			case "changed-layout":
				changed := options
				changed.Sigs = make(map[string]plan9asm.FuncSig)
				for name, sig := range options.Sigs {
					sig.Frame.Params = append([]plan9asm.FrameSlot(nil), sig.Frame.Params...)
					sig.Frame.Params[0].Offset++
					changed.Sigs[name] = sig
				}
				if _, _, err := observed.BindFixedLocal(ctx, pkg, file, "value_amd64.s", changed); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
					t.Fatalf("layout mutation accepted: %v", err)
				}
			}
		})
	}
}

func TestAMD64OriginalFixedLocalResolverMayCloseOwner(t *testing.T) {
	if os.Getenv("PLAN9ASM_ORIGINAL_FIXED_LOCAL_REENTRANT") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		stdout, stderr, err := RunBounded(ctx, "", replaceEnv(os.Environ(), map[string]string{"PLAN9ASM_ORIGINAL_FIXED_LOCAL_REENTRANT": "1"}),
			os.Args[0], "-test.run=^TestAMD64OriginalFixedLocalResolverMayCloseOwner$", "-test.timeout=50s", "-test.v")
		if err != nil {
			t.Fatalf("actual reentrant observer child failed: %v\n%s%s", err, stdout, stderr)
		}
		return
	}
	request, pkg, file, options, _ := amd64OriginalFixedLocalFixture(t)
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	defer observed.Close()
	resolve := options.ResolveSym
	options.ResolveSym = func(symbol string) string {
		if err := observed.Close(); err != nil {
			t.Error(err)
		}
		return resolve(symbol)
	}
	if _, binding, err := observed.BindFixedLocal(ctx, pkg, file, "value_amd64.s", options); err == nil || binding != nil {
		t.Fatalf("reentrant Close was ignored: %v", err)
	}
}

func TestAMD64OriginalFixedLocalBroaderObservationRetainsFactoryContext(t *testing.T) {
	for _, role := range []string{"nested", "bodyful", "import", "sdk-import", "data", "sibling", "pointer"} {
		t.Run(role, func(t *testing.T) {
			request := amd64OriginalObservationFixture(t, role)
			if role == "pointer" {
				if err := os.WriteFile(filepath.Join(request.Directory, "value.go"),
					[]byte("package observation\nfunc Value(a *uint64) uint64\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := amd64OriginalObservationContext(t)
			defer cancel()
			observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded)
			if err != nil {
				t.Fatal(err)
			}
			defer observed.Close()
			actual := observed.state.packages[request.PackagePath]
			set := token.NewFileSet()
			var syntax []*ast.File
			for _, name := range actual.GoFiles {
				file, err := parser.ParseFile(set, filepath.Join(actual.Dir, name), nil, 0)
				if err != nil {
					t.Fatal(err)
				}
				syntax = append(syntax, file)
			}
			imports := importer.ForCompiler(set, "gc", func(path string) (io.ReadCloser, error) {
				if mapped, found := actual.ImportMap[path]; found {
					path = mapped
				}
				return os.Open(observed.state.packages[path].Export)
			})
			sizes := types.SizesFor("gc", "amd64")
			typed, err := (&types.Config{Importer: imports, Sizes: sizes}).Check(request.PackagePath, set, syntax, nil)
			if err != nil {
				t.Fatal(err)
			}
			pkg := plan9asm.GoPackage{Path: typed.Path(), Types: typed, Syntax: syntax}
			sig, err := plan9asm.DeriveGoFuncABI0Signature(pkg.Path+".Value", typed.Scope().Lookup("Value").(*types.Func), "amd64", sizes)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(actual.Dir, "value_amd64.s"))
			if err != nil {
				t.Fatal(err)
			}
			file, err := plan9asm.Parse(plan9asm.ArchAMD64, strings.Replace(string(data), "#include \"textflag.h\"", "#define NOSPLIT 4", 1))
			if err != nil {
				t.Fatal(err)
			}
			options := plan9asm.Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
				ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", pkg.Path+".", 1) },
				Sigs:       map[string]plan9asm.FuncSig{sig.Name: sig}}
			bound, binding, err := observed.BindFixedLocal(ctx, pkg, file, "value_amd64.s", options)
			if role == "bodyful" || role == "import" || role == "sdk-import" {
				// Complete ordinary declarations are independently compiled and
				// rechecked. They add no native permission beyond this actual
				// numeric frame and its existing full-source proof.
				if err != nil || binding == nil {
					t.Fatalf("original numeric source lost complete %s handoff: %v", role, err)
				}
				if err := binding.Verify(ctx); err != nil {
					t.Fatal(err)
				}
				amd64OriginalFixedLocalAPIs(t, pkg, file, bound,
					strings.Replace(string(data), "#include \"textflag.h\"", "#define NOSPLIT 4", 1), false)
				return
			}
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) || binding != nil {
				t.Fatalf("query-only %s role expanded numeric factory admission: %v", role, err)
			}
		})
	}
}

func TestAMD64OriginalFixedLocalOwnedArtifactReplacementFailsCleanupAndRevokes(t *testing.T) {
	request, pkg, file, options, assembly := amd64OriginalFixedLocalFixture(t)
	private, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request.Environment = replaceEnv(request.Environment, map[string]string{"TMPDIR": private})
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	defer observed.Close()
	bound, _, err := observed.BindFixedLocal(ctx, pkg, file, "value_amd64.s", options)
	if err != nil {
		t.Fatal(err)
	}
	directories, err := filepath.Glob(filepath.Join(private, "plan9asm-go-frame-object-*"))
	if err != nil || len(directories) != 1 {
		t.Fatalf("actual factory-owned artifact identity not unique: %v %v", directories, err)
	}
	original := directories[0]
	if err := os.Rename(original, original+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(original, "replacement-must-survive")
	if err := os.WriteFile(marker, []byte("not the observer-owned directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := observed.Close(); err == nil {
		t.Fatal("changed owned artifact identity suppressed cleanup failure")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("cleanup deleted a replacement directory: %v", err)
	}
	amd64OriginalFixedLocalAPIs(t, pkg, file, bound, assembly, true)
}
