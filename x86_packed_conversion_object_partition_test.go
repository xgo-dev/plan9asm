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

func TestX86PackedConversionPublicObjectPartitionsComplete(t *testing.T) {
	if x86PackedConversionObjectBatchSize != 48 || x86PackedConversionObjectOwners != 4 {
		t.Fatal("complete object partition changed its bounded capture or owner inventory")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "x86_packed_conversion_raw_objects_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := make(map[string]*ast.FuncDecl)
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			functions[function.Name.Name] = function
		}
	}
	owners := make(map[string]bool)
	for _, target := range []struct{ name, arch, triple string }{
		{"Linux386", "386", "i386-unknown-linux-gnu"},
		{"Windows386", "386", "i686-pc-windows-msvc"},
		{"LinuxAMD64", "amd64", "x86_64-unknown-linux-gnu"},
		{"DarwinAMD64", "amd64", "x86_64-apple-darwin"},
		{"WindowsAMD64", "amd64", "x86_64-pc-windows-msvc"},
	} {
		rows := x86PackedConversionContinuationRows(target.arch)
		wantCount := 994
		if target.arch == "386" {
			wantCount = 928
		}
		if len(rows) != wantCount {
			t.Fatal("complete original named/raw format denominator changed", target.arch, len(rows), wantCount)
		}
		members, unique := make(map[string]bool), make(map[string]bool)
		seen := make([]int, len(rows))
		for owner := 0; owner < 4; owner++ {
			name := fmt.Sprintf("TestX86PackedConversionPublicObjects%sPart%d", target.name, owner)
			owners[name] = true
			function := functions[name]
			if function == nil || function.Body == nil || len(function.Body.List) != 1 {
				t.Fatal("missing or bypassed complete initialized object owner", name)
			}
			statement, ok := function.Body.List[0].(*ast.ExprStmt)
			if !ok {
				t.Fatal("object owner did not invoke its complete fixture", name)
			}
			call, ok := statement.X.(*ast.CallExpr)
			if !ok || len(call.Args) != 4 {
				t.Fatal("object owner changed its complete target/partition arguments", name)
			}
			callee, ok := call.Fun.(*ast.Ident)
			if !ok || callee.Name != "x86PackedConversionPublicObjectOwner" {
				t.Fatal("object owner did not invoke the real LLVM object driver", name)
			}
			argument, ok := call.Args[0].(*ast.Ident)
			if !ok || argument.Name != "t" {
				t.Fatal("object owner lost its actual test context", name)
			}
			for index, expected := range []string{strconv.Quote(target.arch), strconv.Quote(target.triple), strconv.Itoa(owner)} {
				literal, ok := call.Args[index+1].(*ast.BasicLit)
				if !ok || literal.Value != expected {
					t.Fatal("object owner borrowed another architecture/partition", name, index)
				}
			}
			for ordinal, row := range rows {
				if ordinal/48%4 != owner {
					continue
				}
				seen[ordinal]++
				if unique[row] {
					t.Fatal("duplicate complete named/raw row", target.name, row)
				}
				unique[row] = true
				op, _, _ := strings.Cut(row, " ")
				base, _, _ := strings.Cut(op, ".")
				members[base] = true
			}
		}
		for ordinal, count := range seen {
			if count != 1 {
				t.Fatal("complete row missing or owned twice", target.name, ordinal, count)
			}
		}
		if len(unique) != len(rows) || len(members) != 42 {
			t.Fatal("incomplete independent 4+38 initialized object union", target.name, len(unique), len(members))
		}
	}
	for name := range functions {
		if strings.HasPrefix(name, "TestX86PackedConversionPublicObjects") && !owners[name] {
			t.Fatal("unregistered or duplicate initialized object owner", name)
		}
	}
	driver := functions["x86PackedConversionPublicObjectOwner"]
	if driver == nil || driver.Body == nil {
		t.Fatal("missing real initialized object driver")
	}
	calls := make(map[string]int)
	ast.Inspect(driver.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if callee, ok := call.Fun.(*ast.Ident); ok {
			calls[callee.Name]++
		}
		if callee, ok := call.Fun.(*ast.SelectorExpr); ok &&
			(callee.Sel.Name == "Skip" || callee.Sel.Name == "Skipf" || callee.Sel.Name == "SkipNow") {
			t.Fatal("initialized object coverage cannot be replaced with a skip")
		}
		return true
	})
	for _, required := range []string{
		"x86PackedConversionContinuationRawRows", "x86LEAActualTargetGoObject", "x86ScalarFPBitViewAPI",
		"x86DwordProductIROptimize", "x86PackedStringCompileObject",
	} {
		if calls[required] != 1 {
			t.Fatal("driver lost the actual Go/public/LLVM stage", required, calls[required])
		}
	}
	t.Log("20 explicit owners cover every original initialized named/raw row on all five targets; object outcomes remain separately required")
}
