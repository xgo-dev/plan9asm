package plan9asm

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"testing"
)

func TestFixedLocalSharedHelpersBuildOnAllHosts(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			context := build.Default
			context.GOOS, context.GOARCH = goos, "amd64"
			found := map[string]int{}
			for _, name := range []string{
				"amd64_fixed_local_runtime_test.go",
				"amd64_fixed_local_packed_runtime_test.go",
				"amd64_fixed_local_original_test.go",
			} {
				if _, err := os.Stat(name); os.IsNotExist(err) {
					continue
				}
				included, err := context.MatchFile(".", name)
				if err != nil {
					t.Fatal(err)
				}
				if !included {
					continue
				}
				file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
				if err != nil {
					t.Fatal(err)
				}
				for _, declaration := range file.Decls {
					switch declaration := declaration.(type) {
					case *ast.FuncDecl:
						found[declaration.Name.Name]++
					case *ast.GenDecl:
						for _, spec := range declaration.Specs {
							if value, ok := spec.(*ast.ValueSpec); ok {
								for _, name := range value.Names {
									found[name.Name]++
								}
							}
						}
					}
				}
			}
			for _, name := range []string{"fixedLocalNativeOperations", "fixedLocalPackedRunOriginal"} {
				if found[name] != 1 {
					t.Errorf("portable tests require exactly one %s, found %d", name, found[name])
				}
			}
		})
	}
}
