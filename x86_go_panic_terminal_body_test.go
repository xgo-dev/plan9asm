package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"testing"
)

func x86PanicTerminalTypedFixture(t *testing.T, declarations string) GoPackage {
	t.Helper()
	source := "package terminal\n" + declarations + "\nfunc Value(x uint32) bool\n"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "terminal.go", source, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object)}
	sizes := types.SizesFor("gc", "386")
	pkg, err := (&types.Config{Sizes: sizes}).Check("terminal", fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{Path: "terminal", Types: pkg, Syntax: []*ast.File{file}, SourceSelection: &GoSourceSelection{
		Fset: fset, TypesInfo: info, Sizes: sizes,
		SelectedGoFiles: []string{"terminal.go"}, GoSources: map[string][]byte{"terminal.go": []byte(source)},
		SelectedAssemblyFiles: []string{"terminal.s"}, Assembly: map[string]*File{"terminal.s": {Arch: ArchAMD64}},
	}}
}

func TestX86GoPanicTerminalSingleTypedBody(t *testing.T) {
	for _, name := range []string{"abort", "stopHere", "failure", "ordinaryName"} {
		t.Run(name, func(t *testing.T) {
			pkg := x86PanicTerminalTypedFixture(t, "func "+name+"(){ panic(\"failure\") }")
			bodies, err := x86GoSinglePanicBodies(pkg)
			object := pkg.Types.Scope().Lookup(name)
			if err != nil || len(bodies) != 1 || bodies[object.(*types.Func)] == nil {
				t.Fatal("the exact same selected typed builtin-panic body was not observed", name, err)
			}
		})
	}
}

func TestX86GoPanicTerminalBodyDoesNotInventCalleeAuthority(t *testing.T) {
	for name, declarations := range map[string]string{
		"returning":           "func abort(){}",
		"return":              "func abort(){ return }",
		"conditional":         "func abort(){ if false { panic(\"failure\") } }",
		"deferred-recovery":   "func abort(){ defer func(){ recover() }(); panic(\"failure\") }",
		"deferred-panic":      "func abort(){ defer func(){ panic(\"failure\") }() }",
		"recover-argument":    "func abort(){ panic(recover()) }",
		"shadow-panic":        "func panic(x string){}; func abort(){ panic(\"failure\") }",
		"result":              "func abort() uint32 { panic(\"failure\") }",
		"argument":            "func abort(x uint32) { panic(x) }",
		"generic":             "func abort[T any]() { panic(\"failure\") }",
		"method":              "type T uint32; func (T) abort(){ panic(\"failure\") }",
		"indirect":            "var p = func(){ panic(\"failure\") }; func abort(){ p() }",
		"local-alias":         "func abort(){ p:=func(){ panic(\"failure\") }; p() }",
		"bodyless":            "func abort()",
		"redirected-linkname": "//go:linkname abort other.target\nfunc abort(){ panic(\"failure\") }",
		"extra-statement":     "func abort(){ println(\"sideeffect\"); panic(\"failure\") }",
	} {
		t.Run(name, func(t *testing.T) {
			pkg := x86PanicTerminalTypedFixture(t, declarations)
			if bodies, err := x86GoSinglePanicBodies(pkg); err != nil || len(bodies) != 0 {
				t.Fatal("a returning/recovering/different declaration acquired a terminal body observation", bodies, err)
			}
		})
	}
	for _, changed := range []string{"source", "AST", "typed-builtin", "package-identity", "missing-selection"} {
		t.Run(changed, func(t *testing.T) {
			pkg := x86PanicTerminalTypedFixture(t, "func abort(){ panic(\"failure\") }")
			switch changed {
			case "source":
				pkg.SourceSelection.GoSources["terminal.go"] = []byte("package terminal\nfunc abort(){}\nfunc Value(x uint32) bool\n")
			case "AST":
				pkg.Syntax[0].Decls[0].(*ast.FuncDecl).Body.List = nil
			case "typed-builtin":
				ast.Inspect(pkg.Syntax[0], func(node ast.Node) bool {
					if identifier, ok := node.(*ast.Ident); ok && identifier.Name == "panic" {
						pkg.SourceSelection.TypesInfo.Uses[identifier] = pkg.Types.Scope().Lookup("abort")
					}
					return true
				})
			case "package-identity":
				pkg.Path = "different"
			case "missing-selection":
				pkg.SourceSelection = nil
			}
			if bodies, err := x86GoSinglePanicBodies(pkg); err == nil || len(bodies) != 0 {
				t.Fatal("changed selected source/AST/type object was accepted", bodies, err)
			}
		})
	}
}
