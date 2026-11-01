package plan9asm

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64ABI0MainTailFixture(t *testing.T, packagePath, packageName string, tuple bool) (GoPackage, *File, string, FuncSig) {
	t.Helper()
	declaration, source := arm64ABI0TailResultFixture(tuple, "B")
	goSource := []byte("package " + packageName + "\n" + declaration + "\nfunc main() {}\n")
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, "main.go", goSource, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Defs: make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object)}
	sizes := types.SizesFor("gc", "arm64")
	typed, err := (&types.Config{Sizes: sizes}).Check(packagePath, fset, []*ast.File{syntax}, info)
	if err != nil {
		t.Fatal(err)
	}
	pkg := GoPackage{
		Path: "main", Types: typed, Syntax: []*ast.File{syntax},
		SourceSelection: &GoSourceSelection{
			Fset: fset, TypesInfo: info, Sizes: sizes,
			SelectedGoFiles: []string{"main.go"}, GoSources: map[string][]byte{"main.go": goSource},
		},
	}
	fn := typed.Scope().Lookup("Slots").(*types.Func)
	sig, err := DeriveGoFuncABI0Signature("main.Slots", fn, "arm64", sizes)
	if err != nil {
		t.Fatal(err)
	}
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	return pkg, file, source, sig
}

func arm64ABI0MainTailResolve(symbol string) string {
	return "main." + strings.TrimPrefix(goTextSymbolForResolution(symbol), "·")
}

func TestARM64ABI0TailMainPackageIdentity(t *testing.T) {
	for _, path := range []string{"main", "example.com/cmd/abizero", "command-line-arguments"} {
		for _, tuple := range []bool{false, true} {
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(fmt.Sprintf("%s/tuple=%t/%s", path, tuple, api), func(t *testing.T) {
					pkg, file, source, sig := arm64ABI0MainTailFixture(t, path, "main", tuple)
					originalTypes, originalDeclaration := pkg.Types, pkg.Types.Scope().Lookup("Slots")
					original := arm64ABI0FileSnapshot(file)
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					opt := Options{
						Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu", ResolveSym: arm64ABI0MainTailResolve,
						Sigs: map[string]FuncSig{"main.Slots": sig},
					}
					if api != "GoModule" {
						var err error
						opt.Sigs, err = BindGoARM64ABI0TailDeclarations(pkg, file, opt.ResolveSym, opt.Sigs)
						if err != nil {
							t.Fatal("actual main-package source owner was rejected:", err)
						}
					}
					var ir string
					switch api {
					case "text":
						var err error
						ir, err = Translate(file, opt)
						if err != nil {
							t.Fatal(err)
						}
					case "module":
						module, err := TranslateModuleInContext(ctx, file, opt)
						if !module.IsNil() {
							defer module.Dispose()
						}
						if err != nil {
							t.Fatal(err)
						}
						if err := llvm.VerifyModule(module, llvm.ReturnStatusAction); err != nil {
							t.Fatal(err)
						}
						ir = module.String()
					case "GoModule":
						result, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
							GOARCH: "arm64", TargetTriple: opt.TargetTriple, ResolveSym: opt.ResolveSym,
						})
						if result != nil && !result.Module.IsNil() {
							defer result.Module.Dispose()
						}
						if err != nil {
							t.Fatal(err)
						}
						if err := llvm.VerifyModule(result.Module, llvm.ReturnStatusAction); err != nil {
							t.Fatal(err)
						}
						ir = result.Module.String()
					}
					if !strings.Contains(ir, "@main.Slots(") || strings.Contains(ir, "resultbody") {
						t.Fatal("main entry/private continuation symbols differ from their executable namespace")
					}
					if pkg.Types != originalTypes || pkg.Types.Path() != path ||
						pkg.Types.Scope().Lookup("Slots") != originalDeclaration ||
						!reflect.DeepEqual(original, arm64ABI0FileSnapshot(file)) {
						t.Fatal("translation changed the actual typechecked owner or source")
					}
				})
			}
		}
	}
}

func TestARM64ABI0TailMainPackageNamespaceBoundaries(t *testing.T) {
	for _, mutation := range []string{"non-main-package", "arbitrary-symbol-path", "foreign-resolver", "different-typed-owner"} {
		t.Run(mutation, func(t *testing.T) {
			packageName := "main"
			if mutation == "non-main-package" {
				packageName = "library"
			}
			pkg, file, _, sig := arm64ABI0MainTailFixture(t, "example.com/cmd/abizero", packageName, false)
			resolve := arm64ABI0MainTailResolve
			switch mutation {
			case "arbitrary-symbol-path":
				pkg.Path = "foreign/package"
			case "foreign-resolver":
				var err error
				sig, err = DeriveGoFuncABI0Signature("foreign.Slots", pkg.Types.Scope().Lookup("Slots").(*types.Func), "arm64", pkg.SourceSelection.Sizes)
				if err != nil {
					t.Fatal(err)
				}
				resolve = func(symbol string) string {
					return "foreign." + strings.TrimPrefix(goTextSymbolForResolution(symbol), "·")
				}
			case "different-typed-owner":
				other, _, _, _ := arm64ABI0MainTailFixture(t, pkg.Types.Path(), "main", false)
				pkg.Types = other.Types
			}
			_, err := BindGoARM64ABI0TailDeclarations(pkg, file, resolve, map[string]FuncSig{sig.Name: sig})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unrelated namespace or type owner acquired a main-package binding:", err)
			}
		})
	}
}

func TestARM64ABI0TailMainPackageIdentityRevocation(t *testing.T) {
	for _, mutation := range []string{"symbol-path", "switch-to-source-path", "source-bytes", "selected-file", "Defs-object", "typed-owner"} {
		t.Run(mutation, func(t *testing.T) {
			pkg, file, _, sig := arm64ABI0MainTailFixture(t, "example.com/cmd/abizero", "main", false)
			sigs, err := BindGoARM64ABI0TailDeclarations(pkg, file, arm64ABI0MainTailResolve, map[string]FuncSig{sig.Name: sig})
			if err != nil {
				t.Fatal("complete original main-package binding prerequisite:", err)
			}
			prepared, err := PrepareGoARM64ABI0TailContinuations(file, sigs, arm64ABI0MainTailResolve)
			if err != nil {
				t.Fatal(err)
			}
			sig = sigs[sig.Name]
			switch mutation {
			case "symbol-path":
				sig.arm64ABI0TailDeclaration.packageData.Path = "foreign/package"
			case "switch-to-source-path":
				sig.arm64ABI0TailDeclaration.packageData.Path = pkg.Types.Path()
			case "source-bytes":
				pkg.SourceSelection.GoSources["main.go"][0] = '!'
			case "selected-file":
				pkg.SourceSelection.SelectedGoFiles[0] = "foreign.go"
			case "Defs-object":
				delete(pkg.SourceSelection.TypesInfo.Defs, pkg.Syntax[0].Decls[0].(*ast.FuncDecl).Name)
			case "typed-owner":
				other, _, _, _ := arm64ABI0MainTailFixture(t, pkg.Types.Path(), "main", false)
				sig.arm64ABI0TailDeclaration.packageData.Types = other.Types
			}
			if err := validateARM64ABI0TailSource(prepared.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed actual source/namespace retained its private-tail binding:", err)
			}
		})
	}
}
