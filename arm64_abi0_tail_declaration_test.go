package plan9asm

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestARM64ABI0TailResultActualDeclarationCannotBeForged(t *testing.T) {
	for name, change := range map[string]func(*GoPackage, *FuncSig){
		"missing-selection": func(p *GoPackage, _ *FuncSig) { p.SourceSelection = nil },
		"missing-syntax":    func(p *GoPackage, _ *FuncSig) { p.Syntax = nil },
		"nil-syntax":        func(p *GoPackage, _ *FuncSig) { p.Syntax[0] = nil },
		"nil-function": func(p *GoPackage, _ *FuncSig) {
			p.Syntax[0].Decls[0] = (*ast.FuncDecl)(nil)
		},
		"missing-function-name": func(p *GoPackage, _ *FuncSig) {
			p.Syntax[0].Decls[0].(*ast.FuncDecl).Name = nil
		},
		"missing-Fset":       func(p *GoPackage, _ *FuncSig) { p.SourceSelection.Fset = nil },
		"missing-types-info": func(p *GoPackage, _ *FuncSig) { p.SourceSelection.TypesInfo = nil },
		"missing-sizes":      func(p *GoPackage, _ *FuncSig) { p.SourceSelection.Sizes = nil },
		"missing-selected":   func(p *GoPackage, _ *FuncSig) { p.SourceSelection.SelectedGoFiles = nil },
		"extra-selected": func(p *GoPackage, _ *FuncSig) {
			p.SourceSelection.SelectedGoFiles = append(p.SourceSelection.SelectedGoFiles, "unknown.go")
		},
		"changed-source-bytes": func(p *GoPackage, _ *FuncSig) {
			p.SourceSelection.GoSources["pkg.go"] = []byte("package abi0result\nfunc Slots(value uint32) (out uint64)\n")
		},
		"changed-package-path": func(p *GoPackage, _ *FuncSig) { p.Path = "foreign/abi0result" },
		"different-package-object": func(p *GoPackage, _ *FuncSig) {
			other, _ := arm64ABI0TailResultSignature(t, "func Slots(value uint64) (out uint64)")
			p.Types = other.Types
		},
		"same-layout-different-AST-object": func(p *GoPackage, _ *FuncSig) {
			p.Syntax[0].Decls[0].(*ast.FuncDecl).Name = &ast.Ident{Name: "Slots"}
		},
		"bodyful-source-role": func(p *GoPackage, s *FuncSig) {
			*p, *s = arm64ABI0TailResultSignature(t, "func Slots(value uint64) (out uint64) { return value }")
		},
		"only-typed-layout": func(_ *GoPackage, s *FuncSig) { s.arm64ABI0Declaration = nil },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("malformed actual source must return Context, not panic: %v", recovered)
				}
			}()
			declaration, source := arm64ABI0TailResultFixture(false, "B")
			pkg, sig := arm64ABI0TailResultSignature(t, declaration)
			change(&pkg, &sig)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			resolve := func(name string) string { return strings.TrimPrefix(goTextSymbolForResolution(name), "·") }
			_, err = BindGoARM64ABI0TailDeclarations(pkg, file, resolve, map[string]FuncSig{"Slots": sig})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("altered type/source/role created a private declaration binding: %v", err)
			}
		})
	}
}

func TestARM64ABI0TailResultLiveDeclarationSourceGuard(t *testing.T) {
	for _, change := range []string{"AST-body", "source-byte", "source-delete", "selected-file", "Defs-object", "package-path", "package-name", "Fset-identity", "slot-layout"} {
		t.Run(change, func(t *testing.T) {
			pkg, file, sigs := arm64ABI0BoundFixture(t)
			resolve := func(name string) string { return strings.TrimPrefix(goTextSymbolForResolution(name), "·") }
			prepared, err := PrepareGoARM64ABI0TailContinuations(file, sigs, resolve)
			if err != nil {
				t.Fatal(err)
			}
			sig := sigs["Slots"]
			switch change {
			case "AST-body":
				pkg.Syntax[0].Decls[0].(*ast.FuncDecl).Body = &ast.BlockStmt{}
			case "source-byte":
				pkg.SourceSelection.GoSources["pkg.go"][0] = 'P'
			case "source-delete":
				delete(pkg.SourceSelection.GoSources, "pkg.go")
			case "selected-file":
				pkg.SourceSelection.SelectedGoFiles[0] = "foreign.go"
			case "Defs-object":
				delete(pkg.SourceSelection.TypesInfo.Defs, pkg.Syntax[0].Decls[0].(*ast.FuncDecl).Name)
			case "package-path":
				sig.arm64ABI0TailDeclaration.packageData.Path = "foreign/package"
			case "package-name":
				pkg.Types.SetName("foreign")
			case "Fset-identity":
				set := token.NewFileSet()
				if _, err := parser.ParseFile(set, "foreign.go", pkg.SourceSelection.GoSources["pkg.go"], parser.ParseComments); err != nil {
					t.Fatal(err)
				}
				pkg.SourceSelection.Fset = set
			case "slot-layout":
				sig.Frame.Results[0].Offset++
			}
			if err := validateARM64ABI0TailSource(prepared.Funcs[0], sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("changed live source/declaration retained its result-slot capability: %v", err)
			}
		})
	}
}

func TestARM64ABI0TailResultDerivationAloneIsNotSourcePermission(t *testing.T) {
	declaration, source := arm64ABI0TailResultFixture(false, "B")
	_, sig := arm64ABI0TailResultSignature(t, declaration)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(name string) string { return strings.TrimPrefix(goTextSymbolForResolution(name), "·") }
	prepared, err := CoalesceARM64PrivateRegisterHelpers(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared.Funcs) != 2 || prepared.Funcs[0].arm64ABI0TailSource != nil {
		t.Fatal("file-only coalescer granted ABI0 permission")
	}
	_, err = Translate(prepared, Options{Goarch: "arm64", ResolveSym: resolve,
		Sigs: map[string]FuncSig{"Slots": sig}, TargetTriple: "aarch64-unknown-linux-gnu"})
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("typed layout alone acquired bodyless declaration permission: %v", err)
	}
}
