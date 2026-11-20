//go:build go1.27

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestMapsLiteralMinimumTargetsHaveIndependentCompleteOwners(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "x86_sdk_literal_minimum_go127_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := mapsLiteralMinimumCompleteOwnerPolicy(file); err != nil {
		t.Fatal(err)
	}
}

func mapsLiteralMinimumCompleteOwnerPolicy(file *ast.File) error {
	type owner struct{ helper, target string }
	owners := map[string]owner{
		"TestCompileOneX86SDKOriginalMapsLiteralMinimumSourceLinux":          {"compileOneX86SDKOriginalMapsLiteralMinimumSource", "linux"},
		"TestCompileOneX86SDKOriginalMapsLiteralMinimumSourceDarwin":         {"compileOneX86SDKOriginalMapsLiteralMinimumSource", "darwin"},
		"TestCompileOneX86SDKOriginalMapsLiteralMinimumSourceWindows":        {"compileOneX86SDKOriginalMapsLiteralMinimumSource", "windows"},
		"TestCompileOneX86SDKOriginalMapsLiteralMinimumSourceLinuxPublicCLI": {"runPublicCLIX86SDKOriginalMapsLiteralMinimumSource", "linux"},
	}
	functions := map[string]*ast.FuncDecl{}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if functions[fn.Name.Name] != nil {
			return fmt.Errorf("duplicate maps owner/helper: %s", fn.Name.Name)
		}
		functions[fn.Name.Name] = fn
		expected, required := owners[fn.Name.Name]
		if !required {
			if strings.HasPrefix(fn.Name.Name, "Test") {
				duplicated := false
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					helper, ok := call.Fun.(*ast.Ident)
					duplicated = duplicated || ok && (helper.Name == "compileOneX86SDKOriginalMapsLiteralMinimumSource" || helper.Name == "runPublicCLIX86SDKOriginalMapsLiteralMinimumSource")
					return true
				})
				if duplicated {
					return fmt.Errorf("extra duplicated heavy maps owner: %s", fn.Name.Name)
				}
			}
			continue
		}
		if fn.Body == nil || len(fn.Body.List) != 1 {
			return fmt.Errorf("target owner must unconditionally invoke its complete fixture: %s", fn.Name.Name)
		}
		expression, ok := fn.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return fmt.Errorf("target owner contains a conditional or early return: %s", fn.Name.Name)
		}
		call, ok := expression.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return fmt.Errorf("complete target fixture call missing: %s", fn.Name.Name)
		}
		helper, ok := call.Fun.(*ast.Ident)
		literal, literalOK := call.Args[1].(*ast.BasicLit)
		if !ok || helper.Name != expected.helper ||
			!literalOK || literal.Value != strconv.Quote(expected.target) {
			return fmt.Errorf("target owner lost its exact independent complete platform/role: %s", fn.Name.Name)
		}
		delete(owners, fn.Name.Name)
	}
	if len(owners) != 0 {
		return fmt.Errorf("target owners missing; source and public CLI require separate unchanged deadlines: %v", owners)
	}
	for helper, required := range map[string]map[string]int{
		"compileOneX86SDKOriginalMapsLiteralMinimumSource": {
			"arm64PrivateCLIContext": 1, "setX86SDKNumericalCLIProfile": 1,
			"Load": 1, "captureX86CallerSelections": 1, "compileOne": 1, "RunBounded": 0,
			"mapsLiteralMinimumOriginalSourceInputs": 1, "verifyMapsLiteralMinimumOriginalSourceInputs": 1,
			"ReadFile": 1, "Stat": 1,
		},
		"runPublicCLIX86SDKOriginalMapsLiteralMinimumSource": {
			"arm64PrivateCLIContext": 1, "setX86SDKNumericalCLIProfile": 1,
			"Load": 0, "compileOne": 0, "RunBounded": 1,
			"mapsLiteralMinimumOriginalSourceInputs": 1, "verifyMapsLiteralMinimumOriginalSourceInputs": 1,
			"ReadFile": 2, "Stat": 1, "Unmarshal": 1,
		},
	} {
		fn := functions[helper]
		if fn == nil || fn.Body == nil {
			return fmt.Errorf("complete maps helper missing: %s", helper)
		}
		counts := map[string]int{}
		literals := map[string]bool{}
		var forbidden string
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if literal, ok := node.(*ast.BasicLit); ok && literal.Kind == token.STRING {
				value, _ := strconv.Unquote(literal.Value)
				literals[value] = true
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				name = fun.Name
			case *ast.SelectorExpr:
				name = fun.Sel.Name
			}
			counts[name]++
			if name == "Skip" || name == "Skipf" || name == "SkipNow" || name == "WithDeadline" || name == "WithTimeout" ||
				name == "compileOneX86SDKOriginalMapsLiteralMinimumSource" || name == "runPublicCLIX86SDKOriginalMapsLiteralMinimumSource" {
				forbidden = name
			}
			return true
		})
		if forbidden != "" {
			return fmt.Errorf("maps helper duplicated a heavy role or changed/skipped its budget: %s/%s", helper, forbidden)
		}
		for name, count := range required {
			if counts[name] != count {
				return fmt.Errorf("maps complete role lost or duplicated: %s/%s count=%d want=%d", helper, name, counts[name], count)
			}
		}
		for _, literal := range []string{"define ", "external global [128 x i8]", "internal constant [256 x i8]"} {
			if !literals[literal] {
				return fmt.Errorf("complete maps TEXT/DATA gate missing: %s/%q", helper, literal)
			}
		}
		if helper == "runPublicCLIX86SDKOriginalMapsLiteralMinimumSource" {
			for _, flag := range []string{"-patterns=.", "-compile", "-keep-obj", "-strict-load"} {
				if !literals[flag] {
					return fmt.Errorf("complete public CLI flag missing: %s", flag)
				}
			}
			for literal := range literals {
				if strings.HasPrefix(literal, "-limit") || strings.HasPrefix(literal, "-asm-files") {
					return fmt.Errorf("public CLI cropped its complete original source: %s", literal)
				}
			}
		}
	}
	return nil
}

func TestMapsLiteralMinimumOwnerPolicyRejectsMissingOrDuplicatedRoles(t *testing.T) {
	find := func(file *ast.File, name string) *ast.FuncDecl {
		for _, declaration := range file.Decls {
			if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Name.Name == name {
				return fn
			}
		}
		t.Fatal("required mutation fixture missing", name)
		return nil
	}
	replace := func(file *ast.File, helper, before, after string) {
		changed := false
		ast.Inspect(find(file, helper).Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				if fun.Name == before {
					fun.Name, changed = after, true
				}
			case *ast.SelectorExpr:
				if fun.Sel.Name == before {
					fun.Sel.Name, changed = after, true
				}
			}
			return true
		})
		if !changed {
			t.Fatal("mutation did not touch its original role", before)
		}
	}
	source, public := "compileOneX86SDKOriginalMapsLiteralMinimumSource", "runPublicCLIX86SDKOriginalMapsLiteralMinimumSource"
	mutations := map[string]func(*ast.File){
		"missing independent CLI owner": func(file *ast.File) {
			find(file, "TestCompileOneX86SDKOriginalMapsLiteralMinimumSourceLinuxPublicCLI").Name.Name = "missingCLI"
		},
		"old duplicated heavy root": func(file *ast.File) {
			copy := *find(file, "TestCompileOneX86SDKOriginalMapsLiteralMinimumSourceLinux")
			copy.Name = ast.NewIdent("TestOldCombinedMapsHeavyRoot")
			file.Decls = append(file.Decls, &copy)
		},
		"CLI owner repeats source object": func(file *ast.File) {
			replace(file, "TestCompileOneX86SDKOriginalMapsLiteralMinimumSourceLinuxPublicCLI", public, source)
		},
		"source role omitted":     func(file *ast.File) { replace(file, source, "compileOne", "missingCompile") },
		"selection omitted":       func(file *ast.File) { replace(file, source, "Load", "missingLoad") },
		"typed inventory omitted": func(file *ast.File) { replace(file, source, "captureX86CallerSelections", "missingSelection") },
		"object gate omitted":     func(file *ast.File) { replace(file, source, "Stat", "missingObject") },
		"shared source deadline":  func(file *ast.File) { replace(file, source, "arm64PrivateCLIContext", "reusedContext") },
		"shared CLI deadline":     func(file *ast.File) { replace(file, public, "arm64PrivateCLIContext", "reusedContext") },
		"real CLI omitted":        func(file *ast.File) { replace(file, public, "RunBounded", "missingCLI") },
		"CLI object gate omitted": func(file *ast.File) { replace(file, public, "Stat", "missingObject") },
		"source final hash omitted": func(file *ast.File) {
			replace(file, source, "verifyMapsLiteralMinimumOriginalSourceInputs", "missingFinalSource")
		},
		"CLI final hash omitted": func(file *ast.File) {
			replace(file, public, "verifyMapsLiteralMinimumOriginalSourceInputs", "missingFinalSource")
		},
		"CLI role skipped": func(file *ast.File) {
			replace(file, public, "Helper", "SkipNow")
		},
		"whole DATA gate removed": func(file *ast.File) {
			ast.Inspect(find(file, source).Body, func(node ast.Node) bool {
				if literal, ok := node.(*ast.BasicLit); ok && literal.Value == strconv.Quote("internal constant [256 x i8]") {
					literal.Value = strconv.Quote("missing DATA")
				}
				return true
			})
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "x86_sdk_literal_minimum_go127_test.go", nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			mutate(file)
			if err := mapsLiteralMinimumCompleteOwnerPolicy(file); err == nil {
				t.Fatal("broken independent complete owner policy passed")
			}
		})
	}
}
