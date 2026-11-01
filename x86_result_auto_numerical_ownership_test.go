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

const numericalJoinOwnerPrefix = "TestGoX86ResultAUTOCompleteActualFixedLocalNumericalJoin"
const numericalJoinOwnerHelper = "numericalResultAUTOCompleteActualFixedLocalJoin"

func numericalJoinOwners(source []byte) error {
	file, err := parser.ParseFile(token.NewFileSet(), "owners.go", source, 0)
	if err != nil {
		return err
	}
	owners := map[string]string{
		numericalJoinOwnerPrefix + "OriginalSourceShape": "original-source-shape",
		numericalJoinOwnerPrefix + "Text":                "text",
		numericalJoinOwnerPrefix + "Context":             "context",
		numericalJoinOwnerPrefix + "GoModule":            "go-module",
	}
	seen := make(map[string]bool)
	var helper *ast.FuncDecl
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Name.Name == numericalJoinOwnerHelper {
			if helper != nil {
				return fmt.Errorf("duplicate complete fixture helper")
			}
			helper = fn
		}
		if !strings.HasPrefix(fn.Name.Name, numericalJoinOwnerPrefix) {
			continue
		}
		axis, required := owners[fn.Name.Name]
		if !required || seen[fn.Name.Name] || fn.Body == nil || len(fn.Body.List) != 1 {
			return fmt.Errorf("missing/duplicate/aggregated numerical owner: %s", fn.Name.Name)
		}
		expression, ok := fn.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return fmt.Errorf("conditional or shared numerical owner: %s", fn.Name.Name)
		}
		call, ok := expression.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return fmt.Errorf("complete fixture call missing: %s", fn.Name.Name)
		}
		name, named := call.Fun.(*ast.Ident)
		literal, literalOK := call.Args[1].(*ast.BasicLit)
		parameter, parameterOK := call.Args[0].(*ast.Ident)
		if !named || name.Name != numericalJoinOwnerHelper || !literalOK || literal.Value != strconv.Quote(axis) ||
			!parameterOK || parameter.Name != "t" {
			return fmt.Errorf("numerical owner changed its complete exact axis: %s", fn.Name.Name)
		}
		seen[fn.Name.Name] = true
	}
	if len(seen) != len(owners) || helper == nil || helper.Body == nil {
		return fmt.Errorf("independent numerical deadline owners/helper missing")
	}
	factories, fingerprints, sourceGuards, frameGuards, translations := 0, []token.Pos{}, []token.Pos{}, []token.Pos{}, []token.Pos{}
	var factory *ast.CallExpr
	var forbidden string
	ast.Inspect(helper.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if name, ok := call.Fun.(*ast.Ident); ok {
			switch name.Name {
			case "numericalLocalJoinedFactory":
				factories++
				factory = call
			case "x86CallerSourceFingerprint":
				fingerprints = append(fingerprints, call.Pos())
			case "numericalFamilyTranslate":
				translations = append(translations, call.Pos())
			}
		}
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
			if strings.HasPrefix(selector.Sel.Name, "Skip") || selector.Sel.Name == "Run" {
				forbidden = selector.Sel.Name
			}
			if receiver, ok := selector.X.(*ast.Ident); ok && selector.Sel.Name == "Verify" {
				if receiver.Name == "source" {
					sourceGuards = append(sourceGuards, call.Pos())
				}
				if receiver.Name == "frame" {
					frameGuards = append(frameGuards, call.Pos())
				}
			}
		}
		return true
	})
	if forbidden != "" || factories != 1 || len(fingerprints) != 2 || len(sourceGuards) != 1 || len(frameGuards) != 1 || len(translations) != 1 {
		return fmt.Errorf("complete fresh producer/original-source/final-owner guards changed")
	}
	direct := false
	for _, statement := range helper.Body.List {
		if assignment, ok := statement.(*ast.AssignStmt); ok && len(assignment.Rhs) == 1 && assignment.Rhs[0] == factory {
			direct = true
		}
	}
	if !direct || fingerprints[0] <= factory.Pos() || fingerprints[0] >= translations[0] ||
		sourceGuards[0] <= translations[0] || frameGuards[0] <= translations[0] ||
		fingerprints[1] <= sourceGuards[0] || fingerprints[1] <= frameGuards[0] {
		return fmt.Errorf("fresh producer or final guards moved into a shared/partial lifecycle")
	}
	return nil
}

func TestX86ResultAUTONumericalJoinHasIndependentCompleteOwners(t *testing.T) {
	source, err := os.ReadFile("x86_result_auto_numerical_join_go127_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if err := numericalJoinOwners(source); err != nil {
		t.Fatal(err)
	}
}

func TestX86ResultAUTONumericalJoinOwnerPolicyRejectsMissingOrSharedAxes(t *testing.T) {
	var source strings.Builder
	source.WriteString("package model\n")
	for suffix, axis := range map[string]string{"OriginalSourceShape": "original-source-shape", "Text": "text", "Context": "context", "GoModule": "go-module"} {
		fmt.Fprintf(&source, "func %s%s(t *testing.T) { %s(t,%q) }\n", numericalJoinOwnerPrefix, suffix, numericalJoinOwnerHelper, axis)
	}
	source.WriteString("func " + numericalJoinOwnerHelper + `(t *testing.T, api string) {
_,pkg,file,bound,source,frame := numericalLocalJoinedFactory(t)
x86CallerSourceFingerprint(file)
numericalFamilyTranslate(t,api,pkg,file,bound)
source.Verify(bound.context)
frame.Verify(bound.context)
x86CallerSourceFingerprint(file)
}
`)
	model := source.String()
	if err := numericalJoinOwners([]byte(model)); err != nil {
		t.Fatal("valid ownership-only AST model", err)
	}
	for name, mutate := range map[string]func(string) string{
		"missing owner": func(s string) string { return strings.Replace(s, numericalJoinOwnerPrefix+"Text", "NotAnOwner", 1) },
		"duplicate owner": func(s string) string {
			return s + "func " + numericalJoinOwnerPrefix + "Text(t *testing.T) { " + numericalJoinOwnerHelper + "(t,\"text\") }"
		},
		"wrong axis": func(s string) string { return strings.Replace(s, `"go-module"`, `"context"`, 1) },
		"root shared loop": func(s string) string {
			return strings.Replace(s, numericalJoinOwnerHelper+`(t,"text")`, "for _,api:=range axes { "+numericalJoinOwnerHelper+"(t,api) }", 1)
		},
		"shared subtest": func(s string) string {
			return strings.Replace(s, numericalJoinOwnerHelper+`(t,"text")`, `t.Run("text",func(t *testing.T){ `+numericalJoinOwnerHelper+`(t,"text") })`, 1)
		},
		"missing fresh factory": func(s string) string {
			return strings.Replace(s, "numericalLocalJoinedFactory(t)", "cachedFactory(t)", 1)
		},
		"factory inside loop": func(s string) string {
			return strings.Replace(s, "_,pkg,file,bound,source,frame := numericalLocalJoinedFactory(t)", "for range axes { _,pkg,file,bound,source,frame := numericalLocalJoinedFactory(t) }", 1)
		},
		"duplicate fresh factory": func(s string) string {
			return strings.Replace(s, "numericalLocalJoinedFactory(t)", "numericalLocalJoinedFactory(t); numericalLocalJoinedFactory(t)", 1)
		},
		"missing source guard": func(s string) string {
			return strings.Replace(s, "source.Verify(bound.context)", "source.Unchecked(bound.context)", 1)
		},
		"missing frame guard": func(s string) string {
			return strings.Replace(s, "frame.Verify(bound.context)", "frame.Unchecked(bound.context)", 1)
		},
		"missing source fingerprint": func(s string) string {
			return strings.Replace(s, "x86CallerSourceFingerprint(file)", "unverifiedFingerprint(file)", 1)
		},
		"early final guards": func(s string) string {
			return strings.Replace(s, "numericalFamilyTranslate(t,api,pkg,file,bound)\nsource.Verify(bound.context)\nframe.Verify(bound.context)", "source.Verify(bound.context)\nframe.Verify(bound.context)\nnumericalFamilyTranslate(t,api,pkg,file,bound)", 1)
		},
		"final fingerprint before source guard": func(s string) string {
			return strings.Replace(s, "source.Verify(bound.context)\nframe.Verify(bound.context)\nx86CallerSourceFingerprint(file)", "frame.Verify(bound.context)\nx86CallerSourceFingerprint(file)\nsource.Verify(bound.context)", 1)
		},
		"skip": func(s string) string {
			return strings.Replace(s, "source.Verify(bound.context)", "t.Skip(\"missing tools\")", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := numericalJoinOwners([]byte(mutate(model))); err == nil {
				t.Fatal("incomplete/shared deadline owner passed")
			}
		})
	}
}
