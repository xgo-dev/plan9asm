package plan9asm

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

// This is scheduling policy, not source or compilation authority. Each owner
// must still execute the unchanged complete-source helper and its live guards.
func TestX86SDKCRC32ProfilesHaveIndependentCompleteOwners(t *testing.T) {
	source, err := os.ReadFile("cmd/plan9asmll/x86_sdk_numerical_source_go127_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range x86SDKCRC32ProfileOwners() {
		t.Run(owner.profile, func(t *testing.T) {
			if err := x86SDKCRC32ProfileOwnerError(source, owner.name, owner.profile); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestX86SDKCRC32ProfileOwnerPolicyRejectsSharedOrMissingProfiles(t *testing.T) {
	const explicit = `func TestCompileOneX86SDKOriginalCRC32NumericalDataJoin(t *testing.T) {
	t.Run("explicit", func(t *testing.T) {
		compileX86SDKOriginalCRC32NumericalDataJoin(t, "explicit")
	})
}`
	const defaults = `func TestCompileOneX86SDKOriginalCRC32NumericalDataJoinEffectiveDefaults(t *testing.T) {
	t.Run("effective-defaults", func(t *testing.T) {
		compileX86SDKOriginalCRC32NumericalDataJoin(t, "effective-defaults")
	})
}`
	const prefix = "package main\nimport \"testing\"\n"
	valid := prefix + explicit + "\n" + defaults
	check := func(source string) error {
		for _, owner := range x86SDKCRC32ProfileOwners() {
			if err := x86SDKCRC32ProfileOwnerError([]byte(source), owner.name, owner.profile); err != nil {
				return err
			}
		}
		return nil
	}
	t.Run("valid", func(t *testing.T) {
		if err := check(valid); err != nil {
			t.Fatal(err)
		}
	})
	for _, row := range []struct{ name, source string }{
		{"missing-explicit", prefix + defaults},
		{"missing-defaults", prefix + explicit},
		{"shared-loop", prefix + `func TestCompileOneX86SDKOriginalCRC32NumericalDataJoin(t *testing.T) {
	for _, profile := range []string{"explicit", "effective-defaults"} {
		t.Run(profile, func(t *testing.T) { compileX86SDKOriginalCRC32NumericalDataJoin(t, profile) })
	}
}` + "\n" + defaults},
		{"wrong-profile", prefix + explicit + "\n" + strings.ReplaceAll(defaults, `"effective-defaults"`, `"explicit"`)},
		{"extra-profile", prefix + strings.Replace(explicit, "\n}", `
	t.Run("effective-defaults", func(t *testing.T) {
		compileX86SDKOriginalCRC32NumericalDataJoin(t, "effective-defaults")
	})
}`, 1) + "\n" + defaults},
		{"different-helper", strings.ReplaceAll(valid, "compileX86SDKOriginalCRC32NumericalDataJoin(t,", "compileUnrelatedSource(t,")},
	} {
		t.Run(row.name, func(t *testing.T) {
			if err := check(row.source); err == nil {
				t.Fatal("incomplete/shared profile ownership accepted")
			}
		})
	}
}

func x86SDKCRC32ProfileOwners() []struct{ name, profile string } {
	return []struct{ name, profile string }{
		{"TestCompileOneX86SDKOriginalCRC32NumericalDataJoin", "explicit"},
		{"TestCompileOneX86SDKOriginalCRC32NumericalDataJoinEffectiveDefaults", "effective-defaults"},
	}
}

func x86SDKCRC32ProfileOwnerError(source []byte, name, profile string) error {
	file, err := parser.ParseFile(token.NewFileSet(), "crc32-source-owners.go", source, 0)
	if err != nil {
		return err
	}
	var owner *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == name {
			if owner != nil {
				return fmt.Errorf("duplicate profile owner %s", name)
			}
			owner = function
		}
	}
	if owner == nil || owner.Body == nil {
		return fmt.Errorf("missing independent complete-source profile owner %s", name)
	}
	// One literal t.Run owns one profile. A loop over both profiles would still
	// share go test's deadline even when it makes a fresh context per subtest.
	if len(owner.Body.List) != 1 {
		return fmt.Errorf("%s must own exactly one literal profile", name)
	}
	statement, ok := owner.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return fmt.Errorf("%s cannot share a loop/branch profile lease", name)
	}
	run, ok := statement.X.(*ast.CallExpr)
	if !ok || len(run.Args) != 2 {
		return fmt.Errorf("%s must invoke one profile subtest", name)
	}
	method, ok := run.Fun.(*ast.SelectorExpr)
	if !ok || method.Sel.Name != "Run" || !x86SDKCRC32OwnerIdent(method.X, "t") || !x86SDKCRC32OwnerString(run.Args[0], profile) {
		return fmt.Errorf("%s does not own literal profile %s", name, profile)
	}
	callback, ok := run.Args[1].(*ast.FuncLit)
	if !ok || callback.Body == nil || len(callback.Body.List) != 1 {
		return fmt.Errorf("%s must run the complete-source helper once", name)
	}
	helperStatement, ok := callback.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return fmt.Errorf("%s must delegate directly to the complete-source helper", name)
	}
	helper, ok := helperStatement.X.(*ast.CallExpr)
	if !ok || !x86SDKCRC32OwnerIdent(helper.Fun, "compileX86SDKOriginalCRC32NumericalDataJoin") ||
		len(helper.Args) != 2 || !x86SDKCRC32OwnerIdent(helper.Args[0], "t") || !x86SDKCRC32OwnerString(helper.Args[1], profile) {
		return fmt.Errorf("%s changed or duplicated its complete-source profile", name)
	}
	return nil
}

func x86SDKCRC32OwnerIdent(expression ast.Expr, name string) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == name
}

func x86SDKCRC32OwnerString(expression ast.Expr, value string) bool {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return false
	}
	actual, err := strconv.Unquote(literal.Value)
	return err == nil && actual == value
}
