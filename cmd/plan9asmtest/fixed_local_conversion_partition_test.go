package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestFixedLocalConversionObjectsHaveIndependentTargetOwners(t *testing.T) {
	fixedLocalRequireIndependentTargetOwners(t, "amd64_fixed_local_conversion_test.go",
		"TestGoAMD64FixedLocalConversionActualObjects", "fixedLocalConversionActualObjects", 12)
}

func TestFixedLocalConversionNativeHasIndependentCompleteBatchOwners(t *testing.T) {
	const prefix = "TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalConversionNativeBatch"
	syntax, err := parser.ParseFile(token.NewFileSet(),
		filepath.Join("..", "..", "amd64_fixed_local_conversion_runtime_linux_amd64_test.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[int]bool)
	var roots []string
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := function.Name.Name
		if !strings.HasPrefix(name, prefix) || function.Body == nil || len(function.Body.List) != 1 {
			t.Fatal("native conversion must retain independently scheduled complete batches", name)
		}
		batch, err := strconv.Atoi(strings.TrimPrefix(name, prefix))
		if err != nil || batch < 0 || batch >= 7 || seen[batch] || name != fmt.Sprintf("%s%02d", prefix, batch) {
			t.Fatal("unknown or repeated native conversion batch", name)
		}
		statement, ok := function.Body.List[0].(*ast.ExprStmt)
		if !ok {
			t.Fatal("batch owner must call its native runtime directly", name)
		}
		call, ok := statement.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 4 {
			t.Fatal("native batch lost its complete source plan", name)
		}
		helper, ok := call.Fun.(*ast.Ident)
		if !ok || helper.Name != "fixedLocalConversionRuntimeBatch" {
			t.Fatal("native batch substituted the complete runtime", name)
		}
		literal, ok := call.Args[3].(*ast.BasicLit)
		if !ok || literal.Kind != token.INT || literal.Value != strconv.Itoa(batch) {
			t.Fatal("native runtime lost its independent batch index", name)
		}
		seen[batch] = true
		roots = append(roots, name)
	}
	if len(seen) != 7 {
		t.Fatal("missing native conversion batches", seen)
	}
	for _, count := range []int{16, 32, 64} {
		shards, err := partition(roots, count)
		if err != nil {
			t.Fatal(err)
		}
		for index, names := range shards {
			if len(names) > 2 {
				t.Fatal("native conversion batches accumulate in one shard", count, index, names)
			}
		}
	}
}

func TestFixedLocalPackedObjectsHaveIndependentTargetOwners(t *testing.T) {
	fixedLocalRequireIndependentTargetOwners(t, "amd64_fixed_local_packed_matrix_test.go",
		"TestGoAMD64FixedLocalPackedCompleteFormsActualObjects", "fixedLocalPackedActualObjects", 4)
}

func fixedLocalRequireIndependentTargetOwners(t *testing.T, filename, prefix, plan string, batches int) {
	t.Helper()
	fixedLocalRequireTargetOwners(t, filename, prefix, plan, batches,
		[]struct{ name, target, triple string }{
			{"Linux", "linux/amd64", "x86_64-unknown-linux-gnu"},
			{"Darwin", "darwin/amd64", "x86_64-apple-darwin"},
			{"Windows", "windows/amd64", "x86_64-pc-windows-msvc"},
		})
}

func fixedLocalRequireTargetOwners(t *testing.T, filename, prefix, plan string, batches int,
	platforms []struct{ name, target, triple string }) {
	t.Helper()
	syntax, err := parser.ParseFile(token.NewFileSet(),
		filepath.Join("..", "..", filename), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	type owner struct {
		target, triple string
		batch          int
	}
	want := make(map[string]owner)
	for _, platform := range platforms {
		for batch := 0; batch < batches; batch++ {
			name := fmt.Sprintf("%s%sBatch%02d", prefix, platform.name, batch)
			want[name] = owner{platform.target, platform.triple, batch}
		}
	}
	var roots []string
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || !strings.HasPrefix(function.Name.Name, prefix) {
			continue
		}
		target, found := want[function.Name.Name]
		if !found {
			t.Fatal("unknown or monolithic fixed-local object owner", function.Name.Name)
		}
		if len(function.Body.List) != 1 {
			t.Fatal("target owner must call the complete shared object plan", function.Name.Name)
		}
		statement, ok := function.Body.List[0].(*ast.ExprStmt)
		if !ok {
			t.Fatal("target owner has no direct complete-plan call", function.Name.Name)
		}
		call, ok := statement.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 4 {
			t.Fatal("target owner changed its complete-plan arguments", function.Name.Name)
		}
		helper, ok := call.Fun.(*ast.Ident)
		if !ok || helper.Name != plan {
			t.Fatal("target owner substituted its complete-plan helper", function.Name.Name)
		}
		receiver, ok := call.Args[0].(*ast.Ident)
		if !ok || receiver.Name != "t" {
			t.Fatal("batch owner must retain its actual test lifetime", function.Name.Name)
		}
		for index, expected := range []string{target.target, target.triple} {
			literal, ok := call.Args[index+1].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatal("target binding must retain its literal platform", function.Name.Name)
			}
			actual, err := strconv.Unquote(literal.Value)
			if err != nil || actual != expected {
				t.Fatal("target owner changed platform or LLVM triple", function.Name.Name, actual, expected)
			}
		}
		literal, ok := call.Args[3].(*ast.BasicLit)
		if !ok || literal.Kind != token.INT {
			t.Fatal("batch owner must retain a literal batch index", function.Name.Name)
		}
		batch, err := strconv.Atoi(literal.Value)
		if err != nil || batch != target.batch {
			t.Fatal("batch owner changed its exact conversion range", function.Name.Name, batch, target.batch)
		}
		delete(want, function.Name.Name)
		roots = append(roots, function.Name.Name)
	}
	if len(want) != 0 {
		t.Fatal("missing complete target owners", want)
	}
	shards, err := partition(roots, 32)
	if err != nil {
		t.Fatal(err)
	}
	for index, roots := range shards {
		if len(roots) > 3 {
			t.Fatalf("too many conversion object batches share shard %d: %v", index, roots)
		}
	}
}

func TestFixedLocalConversionObjectCacheIsOwnedByTheWholeTarget(t *testing.T) {
	fixedLocalRequireOwnedObjectCache(t, "amd64_fixed_local_conversion_test.go", "fixedLocalConversionActualObjects")
}

func TestFixedLocalPackedObjectCacheIsOwnedByTheWholeTarget(t *testing.T) {
	fixedLocalRequireOwnedObjectCache(t, "amd64_fixed_local_packed_matrix_test.go", "fixedLocalPackedActualObjects")
}

func fixedLocalRequireOwnedObjectCache(t *testing.T, filename, plan string) {
	t.Helper()
	syntax, err := parser.ParseFile(token.NewFileSet(),
		filepath.Join("..", "..", filename), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var helper *ast.FuncDecl
	for _, declaration := range syntax.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == plan {
			helper = function
		}
	}
	if helper == nil {
		t.Fatal("missing complete fixed-local object helper")
	}
	isCache := func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return false
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Setenv" {
			return false
		}
		receiver, ok := selector.X.(*ast.Ident)
		key, literal := call.Args[0].(*ast.BasicLit)
		return ok && receiver.Name == "t" && literal && key.Value == `"GOCACHE"`
	}
	all, parent := 0, 0
	ast.Inspect(helper.Body, func(node ast.Node) bool {
		if isCache(node) {
			all++
		}
		return true
	})
	for _, statement := range helper.Body.List {
		if _, loop := statement.(*ast.ForStmt); loop && parent == 0 {
			t.Fatal("build cache must be selected before any batch executes")
		}
		if expression, ok := statement.(*ast.ExprStmt); ok && isCache(expression.X) {
			call := expression.X.(*ast.CallExpr)
			cache, ok := call.Args[1].(*ast.CallExpr)
			if !ok || len(cache.Args) != 0 {
				t.Fatal("build cache must be created by the parent test")
			}
			selector, ok := cache.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "TempDir" {
				t.Fatal("build cache must retain test-owned cleanup")
			}
			receiver, ok := selector.X.(*ast.Ident)
			if !ok || receiver.Name != "t" {
				t.Fatal("build cache must belong to this parent test")
			}
			parent++
		}
	}
	if all != 1 || parent != 1 {
		t.Fatal("conversion batches must share exactly one parent-owned build cache", all, parent)
	}
}

func TestFixedLocalConversionPreparesLazyToolsBeforeSourceCapture(t *testing.T) {
	fixedLocalRequirePreparedTools(t, "amd64_fixed_local_conversion_test.go", "fixedLocalConversionActualObjects")
}

func TestFixedLocalConversionRuntimeKeepsOneOwnedCacheAndPreparedTools(t *testing.T) {
	fixedLocalRequireOwnedObjectCache(t, "amd64_fixed_local_conversion_runtime_unix_test.go", "fixedLocalConversionRuntimeBatch")
	fixedLocalRequirePreparedTools(t, "amd64_fixed_local_conversion_runtime_unix_test.go", "fixedLocalConversionRuntimeBatch")
}

func TestFixedLocalConversionObjectsBoundEachIndependentAPISource(t *testing.T) {
	syntax, err := parser.ParseFile(token.NewFileSet(),
		filepath.Join("..", "..", "amd64_fixed_local_conversion_test.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	chunks := 0
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "fixedLocalConversionActualObjects" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			loop, ok := node.(*ast.ForStmt)
			if !ok {
				return true
			}
			increment, ok := loop.Post.(*ast.AssignStmt)
			if !ok || increment.Tok != token.ADD_ASSIGN || len(increment.Lhs) != 1 || len(increment.Rhs) != 1 {
				return true
			}
			name, ok := increment.Lhs[0].(*ast.Ident)
			limit, literal := increment.Rhs[0].(*ast.BasicLit)
			if !ok || name.Name != "chunk" || !literal || limit.Kind != token.INT || limit.Value != "32" {
				return true
			}
			initial, ok := loop.Init.(*ast.AssignStmt)
			if !ok || initial.Tok != token.DEFINE || len(initial.Lhs) != 1 || len(initial.Rhs) != 1 {
				t.Fatal("source chunks lost their complete batch start")
			}
			left, leftOK := initial.Lhs[0].(*ast.Ident)
			right, rightOK := initial.Rhs[0].(*ast.Ident)
			if !leftOK || !rightOK || left.Name != "chunk" || right.Name != "start" {
				t.Fatal("source chunks cropped the beginning of a batch")
			}
			condition, ok := loop.Cond.(*ast.BinaryExpr)
			if !ok || condition.Op != token.LSS {
				t.Fatal("source chunks lost their complete batch boundary")
			}
			left, leftOK = condition.X.(*ast.Ident)
			right, rightOK = condition.Y.(*ast.Ident)
			if !leftOK || !rightOK || left.Name != "chunk" || right.Name != "end" {
				t.Fatal("source chunks cropped the end of a batch")
			}
			captures := 0
			ast.Inspect(loop.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if ok {
					if helper, ok := call.Fun.(*ast.Ident); ok && helper.Name == "fixedLocalFreshAPIs" {
						captures++
					}
				}
				return true
			})
			if captures != 1 {
				t.Fatal("each bounded source must retain all independently captured APIs", captures)
			}
			chunks++
			return false
		})
	}
	if chunks != 1 {
		t.Fatal("complete conversion object owners still accumulate one unbounded API source", chunks)
	}
}

func TestFixedLocalPackedPreparesLazyToolsBeforeSourceCapture(t *testing.T) {
	fixedLocalRequirePreparedTools(t, "amd64_fixed_local_packed_matrix_test.go", "fixedLocalPackedActualObjects")
}

func fixedLocalRequirePreparedTools(t *testing.T, filename, helper string) {
	t.Helper()
	syntax, err := parser.ParseFile(token.NewFileSet(),
		filepath.Join("..", "..", filename), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var prepared, captured []token.Pos
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != helper {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			switch name.Name {
			case "fixedLocalConversionPrepareToolCache":
				if len(call.Args) != 2 {
					t.Fatal("tool preparation lost its actual fixture request")
				}
				for index, expected := range []string{"t", "request"} {
					actual, ok := call.Args[index].(*ast.Ident)
					if !ok || actual.Name != expected {
						t.Fatal("tool preparation substituted its owner or environment")
					}
				}
				prepared = append(prepared, call.Pos())
			case "fixedLocalFreshAPIs":
				// Each selected API now captures independently inside this
				// owner; preparation still precedes every real capture.
				captured = append(captured, call.Pos())
			}
			return true
		})
	}
	if len(prepared) != 1 || len(captured) != 1 || prepared[0] >= captured[0] {
		t.Fatal("lazy SDK tools must be built before the unchanged bounded source capture", prepared, captured)
	}
}
