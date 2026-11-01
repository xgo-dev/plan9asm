package plan9asm

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"testing"
)

func TestX86SignedPackedIntegerFloatRequiredNativeFaultRoot(t *testing.T) {
	const file = "amd64_signed_packed_integer_float_fault_linux_amd64_test.go"
	for _, target := range []struct{ os, arch string }{
		{"linux", "amd64"}, {"linux", "386"}, {"linux", "arm"}, {"linux", "arm64"},
		{"js", "wasm"}, {"darwin", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"},
	} {
		ctx := build.Default
		ctx.GOOS, ctx.GOARCH = target.os, target.arch
		selected, err := ctx.MatchFile(".", file)
		if err != nil || selected != (target.os == "linux" && target.arch == "amd64") {
			t.Fatal("required native fault root selection", target, selected, err)
		}
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Decls) != 2 {
		t.Fatal("native fault wrapper changed its mandatory entry")
	}
	fn, valid := parsed.Decls[1].(*ast.FuncDecl)
	if !valid || fn.Name.Name != "TestCrossLinuxRuntimeMatrixX86SignedPackedIntegerFloatNativeReadAndPrecisionFaults" ||
		fn.Body == nil || len(fn.Body.List) != 1 {
		t.Fatal("required cross-runtime fault root omitted or conditionally skipped")
	}
	statement, valid := fn.Body.List[0].(*ast.ExprStmt)
	if !valid {
		t.Fatal("native fault wrapper does not directly execute the shared oracle")
	}
	call, valid := statement.X.(*ast.CallExpr)
	if !valid || len(call.Args) != 1 {
		t.Fatal("native fault wrapper changed its shared oracle call")
	}
	callee, valid := call.Fun.(*ast.Ident)
	argument, argumentValid := call.Args[0].(*ast.Ident)
	if !valid || !argumentValid || callee.Name != "runX86SignedPackedIntegerFloatNativeReadAndPrecisionFaults" || argument.Name != "t" {
		t.Fatal("required native fault root did not invoke its owned-lifecycle oracle")
	}
}
