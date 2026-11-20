//go:build go1.27
// +build go1.27

package plan9asm

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64TypedNativeStdlibPackage(t *testing.T, path, declarations string) GoPackage {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "declarations.go", declarations, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	conf := types.Config{Importer: importer.Default(), Sizes: types.SizesFor("gc", "arm64")}
	pkg, err := conf.Check(path, fset, []*ast.File{file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{Path: path, Types: pkg, Syntax: []*ast.File{file}}
}

func arm64TypedNativeStdlibObject(t *testing.T, sourcePath string) {
	t.Helper()
	cmd := exec.Command("go", "tool", "asm", "-p", "runtime",
		"-I", filepath.Join(testGOROOT(t), "pkg/include"),
		"-o", filepath.Join(t.TempDir(), "original.o"), sourcePath)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Go 1.27 assembler rejected unchanged standard-library source: %v\n%s", err, out)
	}
}

func TestStdlibARM64TypedNativeEffectsMemHashCompleteSource(t *testing.T) {
	goroot := testGOROOT(t)
	sourcePath := filepath.Join(goroot, "src/internal/runtime/maps/memhash_arm64.s")
	arm64TypedNativeStdlibObject(t, sourcePath)
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	declarations, err := os.ReadFile(filepath.Join(goroot, "src/internal/runtime/maps/memhash_aes_asm.go"))
	if err != nil {
		t.Fatal(err)
	}
	pkg := arm64TypedNativeStdlibPackage(t, "internal/runtime/maps", string(declarations))
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range arm64TypedNativeTargets {
		t.Run(target, func(t *testing.T) {
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			tr, err := translateGoModuleInContext(ctx, pkg, source, GoModuleOptions{
				GOARCH: "arm64", GOOS: "linux", TargetTriple: target,
				ResolveSym: testResolveSym("internal/runtime/maps"),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer tr.Module.Dispose()
			if len(tr.Functions) != 3 {
				t.Fatal("memhash complete source must retain all three functions")
			}
			compileLLVMToObject(t, llc, target, "memhash-arm64.ll", "memhash-arm64.o", tr.Module.String())
		})
	}
}

func TestStdlibARM64TypedNativeEffectsMemclrCompleteSource(t *testing.T) {
	sourcePath := filepath.Join(testGOROOT(t), "src/runtime/memclr_arm64.s")
	arm64TypedNativeStdlibObject(t, sourcePath)
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	pkg := arm64TypedNativeStdlibPackage(t, "runtime", "package runtime\nimport \"unsafe\"\nfunc memclrNoHeapPointers(ptr unsafe.Pointer,n uintptr)\n")
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range arm64TypedNativeTargets {
		t.Run(target, func(t *testing.T) {
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			tr, err := translateGoModuleInContext(ctx, pkg, source, GoModuleOptions{
				GOARCH: "arm64", GOOS: "linux", TargetTriple: target, ResolveSym: testResolveSym("runtime"),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer tr.Module.Dispose()
			compileLLVMToObject(t, llc, target, "memclr-arm64.ll", "memclr-arm64.o", tr.Module.String())
		})
	}
}
