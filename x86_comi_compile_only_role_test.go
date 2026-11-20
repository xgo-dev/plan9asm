package plan9asm

import (
	"go/ast"
	"go/token"
	"testing"
)

func TestX86COMICompileOnlyOwnerDoesNotRequireRuntimeTransport(t *testing.T) {
	functions := fixedLocalLeaseFunctions(t, "amd64_comi_fixture_compile_unix_test.go")
	owner := functions["TestX86COMINativeRuntimeFixturesCompileOnly"]
	if owner == nil {
		t.Fatal("missing original complete COMI object/link owner")
	}
	calls := fixedLocalLeaseCalls(owner.Body)
	if calls["fixedLocalPackedCompileOnlyTools"] != 1 || calls["x86FloatCompareExecutionTools"] != 0 {
		t.Error("complete COMI compilation/linking must reuse the object-only selector, not CPU/emulator execution tools")
	}
	for _, function := range []string{"TestX86COMINativeRuntimeFixturesCompileOnly", "x86COMICompileFixture", "x86COMICompileOriginalGo"} {
		body := functions[function]
		if body == nil {
			t.Fatal("missing original object/Go/C compile chain", function)
		}
		for name, count := range fixedLocalLeaseCalls(body.Body) {
			if count != 0 && (name == "t.Skip" || name == "t.Skipf" || name == "execution.run" || name == "execution.compileAndRunLLVM") {
				t.Error("compile/link-only owner gained a skip or executable claim", function, name)
			}
		}
	}
}

func TestX86COMICompileOnlyOwnerRetainsAll252OriginalFixtures(t *testing.T) {
	functions := fixedLocalLeaseFunctions(t, "amd64_comi_fixture_compile_unix_test.go")
	owner := functions["TestX86COMINativeRuntimeFixturesCompileOnly"]
	if owner == nil {
		t.Fatal("missing original complete COMI object/link owner")
	}
	calls := fixedLocalLeaseCalls(owner.Body)
	for name, count := range map[string]int{
		"x86COMIRawNativeFixture": 1, "x86COMIDeadFaultFixture": 1,
		"x86ScalarCompareAFRuntimeCases": 1, "x86ScalarCompareAFOriginalFiles": 1,
		"x86COMIConstantOracle": 1, "x86COMICompileOriginalGo": 2,
		"x86COMICompileFixture": 4,
	} {
		if calls[name] != count {
			t.Error("original six-fixture/Go-prior inventory changed", name, calls[name], count)
		}
	}
	integers := make(map[string]int)
	axes := make(map[string]int)
	ast.Inspect(owner.Body, func(node ast.Node) bool {
		if value, ok := node.(*ast.BasicLit); ok && value.Kind == token.INT {
			integers[value.Value]++
		}
		if value, ok := node.(*ast.Ident); ok && (value.Name == "x86FloatCompareVEX" || value.Name == "x86FloatCompareEVEX") {
			axes[value.Name]++
		}
		return true
	})
	for number, count := range map[string]int{"12": 1, "24": 2, "48": 1, "96": 1, "252": 1} {
		if integers[number] != count {
			t.Error("24 raw +12 dead +2x48 FLAGS +24/96 MXCSR original kernels changed", number, integers[number])
		}
	}
	if axes["x86FloatCompareVEX"] != 1 || axes["x86FloatCompareEVEX"] != 2 {
		t.Error("complete two-generation FLAGS/MXCSR loop was reduced", axes)
	}
	fixture := functions["x86COMICompileFixture"]
	if fixture == nil {
		t.Fatal("missing complete original fixture compile/link implementation")
	}
	for name, count := range map[string]int{
		"goAssemblerOracleOutput": 1, "x86ScalarFPBitViewAPI": 2,
		"compileLLVMToObject": 1, "x86FloatCompareCaptureCommand": 2,
	} {
		if observed := fixedLocalLeaseCalls(fixture.Body)[name]; observed != count {
			t.Error("original three-API Linux objects or host C link attachment was reduced", name, observed)
		}
	}
}
