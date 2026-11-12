package plan9asm

import (
	"context"
	"crypto/sha256"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const numericalFloatingDeclarations = `
type Small float32
type Wide float64
type SmallAlias = float32
type WideAlias = float64
func Direct32(x float32) float32
func Direct64(x float64) float64
func Named32(x Small) Small
func Named64(x Wide) Wide
func Alias32(x SmallAlias) SmallAlias
func Alias64(x WideAlias) WideAlias
`

// This independent type/source model is deliberately not a live factory.
// It exercises the bounded declaration adapter on every supported Go version;
// the separate current-SDK tests own actual compiler/archive/source evidence.
func numericalFloatingDeclarationModel(t *testing.T, arch, declarations string) (*GoX86NumericalReadSource, GoPackage) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(directory, "source.go")
	data := []byte("package floatingmodel\n" + declarations)
	if err := os.WriteFile(filename, data, 0600); err != nil {
		t.Fatal(err)
	}
	pkg := numericalFloatingDeclarationPackage(t, arch, "example.invalid/floatingmodel", string(data))
	guard := &GoAMD64FrameSource{request: GoAMD64FrameCaptureRequest{Directory: directory},
		selection: goAMD64FrameSelection{GoFiles: []string{"source.go"}, CompiledGoFiles: []string{filename}},
		inputs:    map[string][32]byte{filename: sha256.Sum256(data)}, imports: make(map[string]goAMD64FrameSelection)}
	return &GoX86NumericalReadSource{guard: guard, role: numericalSBOwnedSource,
		request: GoX86NumericalReadCaptureRequest{Directory: directory, PackagePath: pkg.Path}}, pkg
}

func numericalFloatingDeclarationPackage(t *testing.T, arch, path, source string) GoPackage {
	t.Helper()
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, "supplied.go", source, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := (&types.Config{Sizes: types.SizesFor("gc", arch)}).Check(path, fset, []*ast.File{syntax}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{Path: path, Types: typed, Syntax: []*ast.File{syntax}}
}

func TestGoX86NumericalFloatingScalarDeclarationFramework(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			source, pkg := numericalFloatingDeclarationModel(t, arch, numericalFloatingDeclarations)
			declarations, err := source.numericalDeclarations(context.Background(), pkg, arch)
			if err != nil || len(declarations) != 6 {
				t.Fatal("bounded numerical declaration adapter excludes ordinary scalar F32/F64", err, len(declarations))
			}
			for name, declaration := range declarations {
				floating, result := LLVMType("float"), int64(4)
				if strings.HasSuffix(name, "64") {
					floating, result = LLVMType("double"), 8
				} else if arch == "amd64" {
					result = 8
				}
				sig := declaration.signature
				if declaration.transport == goAMD64FrameNumericTransport || !strings.Contains(declaration.languageType, "float") ||
					!reflect.DeepEqual(sig.Args, []LLVMType{floating}) || sig.Ret != floating || len(sig.ArgRegs) != 0 ||
					len(sig.Frame.Params) != 1 || sig.Frame.Params[0].Offset != 0 || sig.Frame.Params[0].Type != floating ||
					len(sig.Frame.Results) != 1 || sig.Frame.Results[0].Offset != result || sig.Frame.Results[0].Type != floating ||
					sig.amd64GoArguments != nil || sig.x86FixedLocal != nil || sig.x86CallerRegions != nil {
					t.Fatal("scalar language/layout identity became NUM or native/caller/entry authority", name, declaration)
				}
			}
			for _, numericOnly := range []bool{false, true} {
				if observed, err := source.guard.typedDeclarationsForArchRole(pkg, numericOnly, arch, false, nil); observed != nil || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("numerical-only floating observer widened the ordinary frame issuer", numericOnly, err)
				}
			}
			for _, change := range []struct{ from, to string }{{"float64", "uint64"}, {"float32", "float64"}} {
				changed := numericalFloatingDeclarationPackage(t, arch, pkg.Path, "package floatingmodel\n"+
					strings.ReplaceAll(numericalFloatingDeclarations, change.from, change.to))
				if observed, err := source.numericalDeclarations(context.Background(), changed, arch); observed != nil || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("equal-width integer/precision mutation retained actual floating language identity", change, err)
				}
			}
			if err := source.Verify(context.Background()); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("pure declaration model manufactured a live source/archive capability", err)
			}
		})
	}
}

func TestGoX86NumericalFloatingScalarFrameworkKeepsOtherLanguageRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, spelling := range []string{"string", "complex64", "complex128", "[2]float32", "struct { X float64 }", "*float64", "[]float32"} {
			t.Run(arch+"/"+spelling, func(t *testing.T) {
				source, pkg := numericalFloatingDeclarationModel(t, arch, "func Feature(x "+spelling+") uint32\n")
				if observed, err := source.numericalDeclarations(context.Background(), pkg, arch); observed != nil || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("ordinary scalar observer borrowed composite/argument-carrier/pointee roles", spelling, err)
				}
			})
		}
	}
}
