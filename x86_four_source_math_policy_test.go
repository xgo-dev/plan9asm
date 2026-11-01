package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func x86FourSourceMathDriverPolicy(function *ast.FuncDecl) bool {
	if function.Body == nil {
		return false
	}
	calls := 0
	for _, statement := range function.Body.List {
		if declaration, ok := statement.(*ast.DeclStmt); ok {
			constants, ok := declaration.Decl.(*ast.GenDecl)
			if !ok || constants.Tok != token.CONST {
				return false
			}
			continue // Literal identity has its independent complete SHA contract.
		}
		expression, ok := statement.(*ast.ExprStmt)
		if !ok {
			return false // Conditional, deferred and asynchronous paths are not execution evidence.
		}
		call, ok := expression.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		callee, ok := call.Fun.(*ast.Ident)
		if !ok || callee.Name != "x86FourSourceOriginalMathCompanion" || len(call.Args) != 3 {
			return false
		}
		for index, expected := range []string{"t", "source", "mainC"} {
			argument, ok := call.Args[index].(*ast.Ident)
			if !ok || argument.Name != expected {
				return false
			}
		}
		calls++
	}
	return calls == 1
}

func TestX86FourSourceOriginalMathDriverIsExplicitAndMandatory(t *testing.T) {
	x86FourSourceOriginalProgram(t)
	syntax, err := parser.ParseFile(token.NewFileSet(), "amd64_lower_four_source_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "TestAMD64FourSourceRuntimeSemantics" {
			if !x86FourSourceMathDriverPolicy(function) {
				t.Fatal("the original runtime driver must invoke its explicit mathematical companion with unchanged complete ASM/C, without a native claim or optional skip")
			}
			return
		}
	}
	t.Fatal("the original four-source runtime driver is absent")
}

func TestX86FourSourceMathDriverPolicyRejectsFalseExecution(t *testing.T) {
	for _, scenario := range []struct {
		name, body string
		valid      bool
	}{
		{"actual", "x86FourSourceOriginalMathCompanion(t,source,mainC)", true},
		{"absent", "", false},
		{"conditioned", "if false { x86FourSourceOriginalMathCompanion(t,source,mainC) }", false},
		{"deferred", "defer x86FourSourceOriginalMathCompanion(t,source,mainC)", false},
		{"asynchronous", "go x86FourSourceOriginalMathCompanion(t,source,mainC)", false},
		{"twice", "x86FourSourceOriginalMathCompanion(t,source,mainC);x86FourSourceOriginalMathCompanion(t,source,mainC)", false},
		{"wrong ASM", "x86FourSourceOriginalMathCompanion(t,mainC,mainC)", false},
		{"wrong C", "x86FourSourceOriginalMathCompanion(t,source,source)", false},
		{"literal replacement", `x86FourSourceOriginalMathCompanion(t,"other",mainC)`, false},
		{"native claim", "compileAndRunRuntimeTest(t,source,mainC)", false},
		{"skip", "t.Skip(\"rare ISA absent\");x86FourSourceOriginalMathCompanion(t,source,mainC)", false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			input := "package fixture\nfunc Observe(){const source=\"source\";const mainC=\"C\";" + scenario.body + "}"
			syntax, err := parser.ParseFile(token.NewFileSet(), "driver.go", strings.NewReader(input), 0)
			if err != nil {
				t.Fatal(err)
			}
			function, ok := syntax.Decls[0].(*ast.FuncDecl)
			if !ok || x86FourSourceMathDriverPolicy(function) != scenario.valid {
				t.Fatal("an independent false-execution policy control changed", scenario.valid)
			}
		})
	}
}

func TestX86FourSourceOriginalMathProjectionBindsAllSourceAndOracleBytes(t *testing.T) {
	source, oracle := x86FourSourceOriginalProgram(t)
	if file, err := x86FourSourceOriginalMathSource(source, oracle); err != nil || file == nil || len(file.Funcs) != 2 {
		t.Fatal("the actual complete original mathematics projector lost its positive control", err)
	}
	for _, mutation := range []struct{ name, source, oracle string }{
		{"source truncation", strings.TrimSuffix(source, "\n"), oracle},
		{"source append", source + "\n", oracle},
		{"first missing", source[strings.Index(source, "\nTEXT foursourcefaultsuppression"):], oracle},
		{"second missing", strings.Split(source, "\nTEXT foursourcefaultsuppression")[0], oracle},
		{"opcode", strings.Replace(source, "V4FMADDPS", "V4FNMADDPS", 1), oracle},
		{"mask", strings.Replace(source, "K1, Z5", "K2, Z5", 1), oracle},
		{"memory", strings.Replace(source, "128(AX)", "124(AX)", 1), oracle},
		{"source block", strings.Replace(source, "[Z2-Z5]", "[Z4-Z7]", 1), oracle},
		{"accumulator", strings.Replace(source, "[Z2-Z5], Z4", "[Z2-Z5], Z5", 1), oracle},
		{"fault producer", strings.Replace(source, "\tKMOVQ CX, K1\n\tV4FMADDPS.Z (AX)", "\tV4FMADDPS.Z (AX)", 1), oracle},
		{"C replacement", source, "int main(void){return 0;}"},
		{"C observation", source, strings.Replace(oracle, "return 10", "return 0", 1)},
		{"C missing fault", source, strings.Replace(oracle, "  foursourcefaultsuppression(0, faultOut, 0);", "", 1)},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			if mutation.source == source && mutation.oracle == oracle {
				t.Fatal("an independent mutation did not change the actual original input")
			}
			file, err := x86FourSourceOriginalMathSource(mutation.source, mutation.oracle)
			if err == nil || file != nil {
				t.Fatal("the actual projector consumed changed original source/C or leaked a partial derived program", err)
			}
		})
	}
}
