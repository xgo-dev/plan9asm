package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"sort"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gosym"
)

func x86PanicTerminalDeclarationFixture(t *testing.T, sources map[string]string) GoPackage {
	return x86PanicTerminalDeclarationPackageFixture(t, "terminal", sources)
}

func x86PanicTerminalDeclarationPackageFixture(t *testing.T, packagePath string, sources map[string]string) GoPackage {
	t.Helper()
	selected := &GoSourceSelection{Fset: token.NewFileSet(), Sizes: types.SizesFor("gc", "386"),
		TypesInfo: &types.Info{Types: make(map[ast.Expr]types.TypeAndValue), Defs: make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object)},
		GoSources: make(map[string][]byte), SelectedAssemblyFiles: []string{"terminal.s"}, Assembly: map[string]*File{"terminal.s": {Arch: ArchAMD64}}}
	for filename := range sources {
		selected.SelectedGoFiles = append(selected.SelectedGoFiles, filename)
	}
	sort.Strings(selected.SelectedGoFiles)
	var syntax []*ast.File
	for _, filename := range selected.SelectedGoFiles {
		source := []byte("package terminal\n" + sources[filename])
		file, err := parser.ParseFile(selected.Fset, filename, source, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		syntax = append(syntax, file)
		selected.GoSources[filename] = source
	}
	typed, err := (&types.Config{Sizes: selected.Sizes}).Check(packagePath, selected.Fset, syntax, selected.TypesInfo)
	if err != nil {
		t.Fatal(err)
	}
	return GoPackage{Path: packagePath, Types: typed, Syntax: syntax, SourceSelection: selected}
}

func TestX86GoPanicTerminalDeclarationUsesActualPackagePrefix(t *testing.T) {
	const path = "example.invalid/with.dot"
	pkg := x86PanicTerminalDeclarationPackageFixture(t, path, map[string]string{"body.go": "func arbitraryName(){ panic(1) }\n"})
	declarations, err := x86GoPanicTerminalDeclarations(pkg)
	if err != nil || len(declarations) != 1 || declarations[0].nativeName != gosym.PackagePrefix(path)+".arbitraryName" ||
		declarations[0].nativeName == path+".arbitraryName" {
		t.Fatal("selected declaration lost the actual Go object package-prefix encoding", declarations, err)
	}
}

func TestX86GoPanicTerminalDeclarationWholeSelectionRedirection(t *testing.T) {
	for name, redirected := range map[string]string{
		"detached-local": "//go:linkname abort foreign.target\n\nvar unrelated uint32\n",
		"exported-local": "//go:linkname abort\n\nvar unrelated uint32\n",
		"incoming-alias": "//go:linkname redirected terminal.abort\n\nfunc redirected()\n",
	} {
		t.Run(name, func(t *testing.T) {
			pkg := x86PanicTerminalDeclarationFixture(t, map[string]string{
				"body.go":  "func abort(){ panic(\"failure\") }\n",
				"other.go": redirected,
			})
			if declarations, err := x86GoPanicTerminalDeclarations(pkg); err != nil || len(declarations) != 0 {
				t.Fatal("detached/cross-file symbol redirection acquired an exact Go-body declaration role", declarations, err)
			}
		})
	}
}

func TestX86GoPanicTerminalDeclarationKeepsUnrelatedFunctionsAndDirectives(t *testing.T) {
	pkg := x86PanicTerminalDeclarationFixture(t, map[string]string{
		"body.go":  "func arbitraryName(){ panic(\"failure\") }\nfunc returning(){}\n",
		"other.go": "//go:linknamestd unrelated\n//go:linkname redirected foreign.target\nfunc redirected()\n",
	})
	declarations, err := x86GoPanicTerminalDeclarations(pkg)
	if err != nil || len(declarations) != 1 || declarations[0].name != "arbitraryName" || declarations[0].nativeName != "terminal.arbitraryName" ||
		declarations[0].filename != "body.go" || declarations[0].startLine != 2 || declarations[0].endLine != 2 || declarations[0].panicLine != 2 {
		t.Fatal("unrelated declarations or directive spelling changed the exact typed body query", declarations, err)
	}
}

func TestX86GoPanicTerminalDeclarationDetachedSameFile(t *testing.T) {
	pkg := x86PanicTerminalDeclarationFixture(t, map[string]string{
		"body.go": "//go:linkname arbitraryName foreign.target\n\nvar unrelated uint32\nfunc arbitraryName(){ panic(\"failure\") }\n",
	})
	if declarations, err := x86GoPanicTerminalDeclarations(pkg); err != nil || len(declarations) != 0 {
		t.Fatal("a file-level directive detached from fn.Doc retained a declaration association", declarations, err)
	}
}
