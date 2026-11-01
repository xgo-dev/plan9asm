//go:build go1.27

package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestGoAssemblerOracleARM64CompleteActualClassDirectory(t *testing.T) {
	path := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/arm64/anames7.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool)
	ast.Inspect(file, func(node ast.Node) bool {
		declaration, ok := node.(*ast.ValueSpec)
		if !ok || len(declaration.Names) != 1 || declaration.Names[0].Name != "cnames7" {
			return true
		}
		if len(declaration.Values) != 1 {
			t.Fatal("original complete class directory shape changed")
		}
		array, ok := declaration.Values[0].(*ast.CompositeLit)
		if !ok {
			t.Fatal("original complete class directory is not a literal")
		}
		for _, value := range array.Elts {
			literal, ok := value.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatal("original class entry is not a lexical name")
			}
			name, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			if name != "" {
				if names[name] {
					t.Fatal("duplicate original class name")
				}
				names[name] = true
			}
		}
		return false
	})
	if !reflect.DeepEqual(names, goAssemblerOracleARM64Classes) {
		t.Fatalf("complete actual DRconv namespace differs: %v / %v", names, goAssemblerOracleARM64Classes)
	}
}

func TestGoAssemblerOracleARM64CompleteActualAddrTypes(t *testing.T) {
	path := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/link.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	ast.Inspect(file, func(node ast.Node) bool {
		entry, ok := node.(*ast.ValueSpec)
		if !ok || len(entry.Names) != 1 || !strings.HasPrefix(entry.Names[0].Name, "TYPE_") {
			return true
		}
		if entry.Names[0].Name == "TYPE_NONE" {
			if len(entry.Values) != 1 {
				t.Fatal("original address-type ordinal initializer changed")
			}
			initial, ok := entry.Values[0].(*ast.Ident)
			if !ok || initial.Name != "iota" {
				t.Fatal("original address-type ordinals do not start at zero")
			}
		} else if len(entry.Values) != 0 {
			t.Fatal("original address-type ordinal overridden")
		}
		names = append(names, entry.Names[0].Name)
		return false
	})
	want := strings.Fields(`TYPE_NONE TYPE_BRANCH TYPE_TEXTSIZE TYPE_MEM TYPE_CONST TYPE_FCONST
		TYPE_SCONST TYPE_REG TYPE_ADDR TYPE_SHIFT TYPE_REGREG TYPE_REGREG2 TYPE_INDIR TYPE_REGLIST TYPE_SPECIAL`)
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("complete actual AddrType directory changed: %v", names)
	}
}
