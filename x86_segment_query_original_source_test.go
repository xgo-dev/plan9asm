package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// Parse the actual Linux-only driver on every development host. Building the
// translator on ARM64 cannot otherwise catch a generated original Go file
// missing its package clause. No subprocess or platform skip is involved.
func TestX86SegmentQueryOriginalGoSourceIsCompleteAndParseable(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "x86_segment_query_runtime_linux_amd64_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var template, declarationFormat string
	var originalCall *ast.CallExpr
	formats, calls := 0, 0
	ast.Inspect(file, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.ValueSpec:
			if len(value.Names) == 1 && value.Names[0].Name == "x86SegmentQueryOriginalGo" && len(value.Values) == 1 {
				literal, ok := value.Values[0].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Fatal("original Go test body must retain its complete source literal")
				}
				template, err = strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
			}
		case *ast.CallExpr:
			if name, ok := value.Fun.(*ast.Ident); ok && name.Name == "x86RunOriginalGoNativeSource" {
				originalCall, calls = value, calls+1
			}
			selector, ok := value.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Fprintf" || len(value.Args) < 2 {
				return true
			}
			address, ok := value.Args[0].(*ast.UnaryExpr)
			if !ok || address.Op != token.AND {
				return true
			}
			name, ok := address.X.(*ast.Ident)
			if !ok || name.Name != "declarations" {
				return true
			}
			literal, ok := value.Args[1].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatal("original Go declaration builder lost its bounded format")
			}
			format, err := strconv.Unquote(literal.Value)
			if err != nil || declarationFormat != "" && declarationFormat != format {
				t.Fatal("original live/dead query signatures diverged", err)
			}
			declarationFormat, formats = format, formats+1
		}
		return true
	})
	if calls != 1 || formats != 2 || originalCall == nil || len(originalCall.Args) != 6 || template == "" ||
		strings.Count(declarationFormat, "%s") != 1 {
		t.Fatal("complete actual original Go call/declaration/test inventory changed", calls, formats)
	}
	var declarations, rows strings.Builder
	for operation, row := range x86SegmentQueryOracle {
		for role := 0; role < 3; role++ {
			for seed := 0; seed < 2; seed++ {
				name := fmt.Sprintf("Query%d_%d_%d", operation, role, seed)
				fmt.Fprintf(&declarations, declarationFormat, name)
				fmt.Fprintf(&rows, "{%s,%d,%d,%d,%d},\n", name, operation, role, seed, row.bytes)
			}
		}
		fmt.Fprintf(&declarations, declarationFormat, fmt.Sprintf("QueryDead%d", operation))
	}
	var render func(ast.Expr) string
	render = func(expression ast.Expr) string {
		switch value := expression.(type) {
		case *ast.BasicLit:
			if value.Kind == token.STRING {
				text, err := strconv.Unquote(value.Value)
				if err == nil {
					return text
				}
			}
		case *ast.BinaryExpr:
			if value.Op == token.ADD {
				return render(value.X) + render(value.Y)
			}
		case *ast.CallExpr:
			selector, ok := value.Fun.(*ast.SelectorExpr)
			if ok && selector.Sel.Name == "String" && len(value.Args) == 0 {
				if name, ok := selector.X.(*ast.Ident); ok && name.Name == "declarations" {
					return declarations.String()
				}
			}
		}
		t.Fatal("original Go declaration source escaped its exact bounded builder")
		return ""
	}
	program := render(originalCall.Args[3])
	for name, source := range map[string]string{
		"value.go": program, "value_test.go": fmt.Sprintf(template, rows.String()),
	} {
		parsed, err := parser.ParseFile(token.NewFileSet(), name, source, parser.AllErrors)
		if err != nil || parsed == nil || parsed.Name.Name != "oracle" {
			t.Fatal("actual complete original Go source is not a valid oracle package", name, err)
		}
		if _, err := parser.ParseFile(token.NewFileSet(), name, strings.TrimPrefix(source, "package oracle\n"), parser.AllErrors); err == nil {
			t.Fatal("parser control failed to reject the old missing-package source", name)
		}
		if name == "value.go" && len(parsed.Decls) != 57 {
			t.Fatal("original Go lost a live/dead/CS declaration", len(parsed.Decls))
		}
	}
}
