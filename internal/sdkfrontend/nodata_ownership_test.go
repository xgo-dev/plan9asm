package sdkfrontend

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func sharedSDKNoDATAOwners(source []byte) error {
	file, err := parser.ParseFile(token.NewFileSet(), "owners.go", source, 0)
	if err != nil {
		return err
	}
	want := map[string][2]string{}
	for suffix, member := range map[string]string{"Count": "count_amd64.s", "IndexByte": "indexbyte_amd64.s"} {
		for ending, api := range map[string]string{"Text": "text", "Module": "module", "GoModule": "go-module"} {
			want["TestSharedSDKNoDATA"+suffix+ending] = [2]string{member, api}
		}
	}
	seen := map[string]bool{}
	var helper *ast.FuncDecl
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Name.Name == "sharedSDKNoDATAOriginalOwner" {
			helper = fn
		}
		if !strings.HasPrefix(fn.Name.Name, "TestSharedSDKNoDATA") {
			continue
		}
		axis, exists := want[fn.Name.Name]
		if !exists || seen[fn.Name.Name] || fn.Body == nil || len(fn.Body.List) != 1 {
			return fmt.Errorf("missing, duplicate or aggregated owner %s", fn.Name.Name)
		}
		expression, ok := fn.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return fmt.Errorf("conditional owner %s", fn.Name.Name)
		}
		call, ok := expression.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 3 {
			return fmt.Errorf("complete original owner call missing")
		}
		name, named := call.Fun.(*ast.Ident)
		parameter, parameterOK := call.Args[0].(*ast.Ident)
		member, memberOK := call.Args[1].(*ast.BasicLit)
		api, apiOK := call.Args[2].(*ast.BasicLit)
		if !named || name.Name != "sharedSDKNoDATAOriginalOwner" || !parameterOK || parameter.Name != "t" ||
			!memberOK || member.Value != strconv.Quote(axis[0]) || !apiOK || api.Value != strconv.Quote(axis[1]) {
			return fmt.Errorf("original member/API ownership changed")
		}
		seen[fn.Name.Name] = true
	}
	if len(seen) != 6 || helper == nil || helper.Body == nil {
		return fmt.Errorf("six independent complete original owners required")
	}
	counts := map[string]int{}
	var factory *ast.CallExpr
	var forbidden string
	ast.Inspect(helper.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if name, ok := call.Fun.(*ast.Ident); ok {
			counts[name.Name]++
			if name.Name == "sdkMinimumOriginalPackage" {
				factory = call
			}
		}
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
			counts[selector.Sel.Name]++
			if selector.Sel.Name == "Run" || strings.HasPrefix(selector.Sel.Name, "Skip") {
				forbidden = selector.Sel.Name
			}
		}
		return true
	})
	for _, name := range []string{"sdkMinimumOriginalPackage", "Capture", "BindNumericalReads", "Verify", "Translate", "TranslateModuleInContext", "TranslateGoModule"} {
		if counts[name] != 1 {
			return fmt.Errorf("complete fresh producer/consumer/guard %s changed", name)
		}
	}
	if forbidden != "" {
		return fmt.Errorf("shared or skipped complete owner: %s", forbidden)
	}
	for _, statement := range helper.Body.List {
		if assignment, ok := statement.(*ast.AssignStmt); ok && len(assignment.Rhs) == 1 && assignment.Rhs[0] == factory {
			return nil
		}
	}
	return fmt.Errorf("fresh factory is conditional or shared")
}

func TestSharedSDKNoDATAOwnersAreCompleteAndIndependent(t *testing.T) {
	source, err := os.ReadFile("nodata_go127_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if err := sharedSDKNoDATAOwners(source); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct{ old, replacement string }{
		{"TestSharedSDKNoDATACountText", "NotAnOwner"},
		{`"indexbyte_amd64.s", "go-module"`, `"count_amd64.s", "go-module"`},
		{"sdkMinimumOriginalPackage(t,", "cachedFactory(t,"},
		{"source.Verify(ctx)", "source.Unchecked(ctx)"},
		{"source.Verify(ctx)", `t.Skip("missing tools")`},
	} {
		index := strings.LastIndex(string(source), change.old)
		if index < 0 {
			t.Fatal("ownership mutation lost its source target", change.old)
		}
		changed := string(source[:index]) + change.replacement + string(source[index+len(change.old):])
		if err := sharedSDKNoDATAOwners([]byte(changed)); err == nil {
			t.Fatal("missing or shared original member/API owner was accepted", change.old)
		}
	}
}
