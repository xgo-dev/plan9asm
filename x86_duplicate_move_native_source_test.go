package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestX86DuplicateNativeActualSourceOwnsExactlyOnePackage(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			program := x86BuildDuplicateNativeProgram(arch)
			for _, fixture := range []struct {
				name, source, pkg string
				functions         int
			}{
				{"api.go", "package bitview\n" + program.declarations, "bitview", 90},
				{"original.go", program.originalDeclarations + "func MXCSR(value uint32) uint32\n", "oracle", 19},
				{"original_test.go", fmt.Sprintf(x86DuplicateOriginalGo, program.originalRows), "oracle", 1},
			} {
				t.Run(fixture.name, func(t *testing.T) {
					file, err := parser.ParseFile(token.NewFileSet(), fixture.name, fixture.source, parser.AllErrors)
					if err != nil {
						t.Fatal("actual native fixture is not a valid Go file", err)
					}
					functions := 0
					for _, declaration := range file.Decls {
						if _, ok := declaration.(*ast.FuncDecl); ok {
							functions++
						}
					}
					if file.Name.Name != fixture.pkg || functions != fixture.functions {
						t.Fatal("native declaration inventory changed", file.Name.Name, functions)
					}
					for _, broken := range []string{
						"package other\n" + fixture.source,
						strings.TrimPrefix(fixture.source, "package "+fixture.pkg+"\n"),
					} {
						if _, err := parser.ParseFile(token.NewFileSet(), fixture.name, broken, parser.AllErrors); err == nil {
							t.Fatal("source guard accepted a duplicate or absent package clause")
						}
					}
				})
			}
			if strings.Count(program.source, "TEXT ·Copy") != 60 ||
				strings.Count(program.source, "TEXT ·DeadCopy") != 30 ||
				strings.Count(program.originalSource, "TEXT ·Copy") != 18 ||
				len(program.faultAligned) != 30 {
				t.Fatal("complete native live/dead/original inventory changed")
			}
		})
	}
}

func TestX86DivideNativeActualSourceOwnsExactlyOnePackage(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			rows := x86DivideNativeRows(arch)
			declarations, original := x86DivideNativeDeclarationSources(rows)
			for _, fixture := range []struct{ name, source, pkg string }{
				{"api.go", "package bitview\n" + declarations, "bitview"},
				{"original.go", original, "oracle"},
			} {
				t.Run(fixture.name, func(t *testing.T) {
					file, err := parser.ParseFile(token.NewFileSet(), fixture.name, fixture.source, parser.AllErrors)
					if err != nil {
						t.Fatal("actual division fixture is not a valid Go file", err)
					}
					if file.Name.Name != fixture.pkg || len(file.Decls) != len(rows)*2 {
						t.Fatal("division live/dead declaration inventory changed", file.Name.Name, len(file.Decls))
					}
					for _, broken := range []string{
						"package other\n" + fixture.source,
						strings.TrimPrefix(fixture.source, "package "+fixture.pkg+"\n"),
					} {
						if _, err := parser.ParseFile(token.NewFileSet(), fixture.name, broken, parser.AllErrors); err == nil {
							t.Fatal("division guard accepted a duplicate or absent package clause")
						}
					}
				})
			}
		})
	}
}
