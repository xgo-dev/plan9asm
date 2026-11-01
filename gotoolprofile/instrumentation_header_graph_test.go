package gotoolprofile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestInstrumentationTypeGraphRetainsModuleMetadataWithZeroMap(t *testing.T) {
	for _, origin := range []string{"authenticated_proxy", "original_zip_member"} {
		t.Run(origin, func(t *testing.T) {
			input, pkg, metadata := instrumentationTypeLegacyMetadataFixture(t)
			if origin == "original_zip_member" {
				metadata = filepath.Join(input.Original.SourceRoot, "go.mod")
				contents := input.Original.ProxyGoMod.Contents
				if err := os.WriteFile(metadata, []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
				input.Original.ProxyGoMod, input.Original.ProxyGoModPath = nil, ""
				input.Original.Sources["go.mod"] = bytesSHA256([]byte(contents))
				input.Original.Directories["."] = []string{"go.mod", "legacy.go"}
				pkg.Module.GoMod = metadata
			}
			// This existing private constructor deliberately omits the new
			// query-only index. Keeping its zero value valid must not bypass
			// the actual original/proxy metadata byte and path checks.
			graph, err := instrumentationTypeMetadataCapture(input, pkg)
			if err != nil {
				t.Fatal(err)
			}
			if graph.moduleFiles["original"] != metadata || graph.paths[metadata] != metadata {
				t.Fatal("zero-valued index lost the independently validated module metadata path")
			}
		})
	}
}

func TestInstrumentationTypeGraphModuleMetadataIndexUsesOwnedStorage(t *testing.T) {
	var zero instrumentationTypeGraph
	zero.recordModuleMetadataPath("original", "original.mod")
	zero.recordModuleMetadataPath("foreign", "foreign.mod")
	zero.recordModuleMetadataPath("original", "replacement.mod")
	if want := map[string]string{
		"original": "replacement.mod",
		"foreign":  "foreign.mod",
	}; !reflect.DeepEqual(zero.moduleFiles, want) {
		t.Fatalf("zero graph changed exact metadata indexing: got %v, want %v", zero.moduleFiles, want)
	}

	other := instrumentationTypeGraph{moduleFiles: map[string]string{"existing": "kept.mod"}}
	other.recordModuleMetadataPath("original", "other.mod")
	if other.moduleFiles["existing"] != "kept.mod" || other.moduleFiles["original"] != "other.mod" {
		t.Fatal("recording discarded an existing metadata binding")
	}
	if zero.moduleFiles["original"] != "replacement.mod" {
		t.Fatal("separate graphs share mutable metadata index storage")
	}
}

func TestInstrumentationTypeGraphModuleMetadataWritesUseRetainer(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "instrumentation_type_capture.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	writes := 0
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, left := range assignment.Lhs {
				index, ok := left.(*ast.IndexExpr)
				if !ok {
					continue
				}
				field, ok := index.X.(*ast.SelectorExpr)
				if !ok || field.Sel.Name != "moduleFiles" {
					continue
				}
				writes++
				if function.Name.Name != "recordModuleMetadataPath" {
					t.Errorf("%s bypasses the zero-value-safe private metadata recorder", function.Name.Name)
				}
			}
			return true
		})
	}
	if writes != 1 {
		t.Fatalf("expected one complete module-index mutation site, got %d", writes)
	}
}
