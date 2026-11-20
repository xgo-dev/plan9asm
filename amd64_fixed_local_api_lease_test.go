package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// These are scheduling checks, not fabricated source observations. Every API
// still has to capture and consume its complete actual Go package independently.
func TestFixedLocalAPIsHaveIndependentBoundedCaptureLeases(t *testing.T) {
	functions := fixedLocalLeaseFunctions(t, "amd64_fixed_local_frame_test.go")
	helper := functions["fixedLocalFreshAPIs"]
	if helper == nil {
		t.Fatal("three sequential APIs still share one source/binding lease; missing per-API capture owner")
	}
	var scopes []*ast.FuncLit
	ast.Inspect(helper.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || fixedLocalLeaseCallName(call) != "t.Run" || len(call.Args) != 2 {
			return true
		}
		if scope, ok := call.Args[1].(*ast.FuncLit); ok {
			scopes = append(scopes, scope)
		}
		return true
	})
	if len(scopes) != 1 {
		t.Fatalf("each selected API needs one independent synchronous owner, got %d", len(scopes))
	}
	scope := scopes[0]
	counts := fixedLocalLeaseCalls(scope.Body)
	for _, name := range []string{"runtimeOracleStageContext", "CaptureGoAMD64FrameSource", "source.preprocess", "Parse", "source.BindFixedLocal", "fixedLocalAPI"} {
		if counts[name] != 1 {
			t.Errorf("per-API owner must retain exactly one %s, got %d", name, counts[name])
		}
	}
	for _, name := range []string{"runtimeOracleProofContext", "requireGoAMD64FrameCapture", "fixedLocalAPIs", "t.Parallel"} {
		if counts[name] != 0 {
			t.Errorf("per-API owner cannot extend, prematurely cancel, share or overlap its lease: %s", name)
		}
	}
	all := fixedLocalLeaseCalls(helper.Body)
	for _, name := range []string{"runtimeOracleStageContext", "CaptureGoAMD64FrameSource", "source.BindFixedLocal"} {
		if all[name] != counts[name] {
			t.Errorf("%s escaped the API lifetime", name)
		}
	}
	if all["runtimeOracleProofContext"] != 0 {
		t.Error("an outer proof context cannot extend the independent five-minute API stage")
	}

	var stage, capture, bind, consume token.Pos
	var cancel, close bool
	ast.Inspect(scope.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fixedLocalLeaseCallName(call) {
		case "runtimeOracleStageContext":
			stage = call.Pos()
			fixedLocalLeaseRequireArguments(t, call, "t")
		case "CaptureGoAMD64FrameSource":
			capture = call.Pos()
			fixedLocalLeaseRequireArguments(t, call, "ctx", "pkg", "request")
		case "source.BindFixedLocal":
			bind = call.Pos()
			fixedLocalLeaseRequireArguments(t, call, "ctx", "pkg", "file", "options")
		case "fixedLocalAPI":
			consume = call.Pos()
			fixedLocalLeaseRequireArguments(t, call, "t", "pkg", "file", "bound", "api", "check", "expanded")
		}
		return true
	})
	for _, statement := range scope.Body.List {
		deferred, ok := statement.(*ast.DeferStmt)
		if !ok {
			continue
		}
		if fixedLocalLeaseCallName(deferred.Call) == "cancel" {
			cancel = true
		}
		if closure, ok := deferred.Call.Fun.(*ast.FuncLit); ok {
			close = close || fixedLocalLeaseCalls(closure.Body)["source.Close"] == 1
		}
	}
	if !cancel || !close {
		t.Error("each API must cancel and close its own source before the next API starts, including fatal paths")
	}
	if !(stage < capture && capture < bind && bind < consume) {
		t.Error("each complete source capture and binding must precede only that API's consumption")
	}
}

func TestFixedLocalCompleteConsumersDoNotShareAPILease(t *testing.T) {
	for _, owner := range []struct{ filename, helper string }{
		{"amd64_fixed_local_conversion_test.go", "fixedLocalConversionActualObjects"},
		{"amd64_fixed_local_packed_matrix_test.go", "fixedLocalPackedActualObjects"},
		{"amd64_cmov_fixed_local_test.go", "x86CMOVFixedLocalActualObjects"},
		{"amd64_fixed_local_conversion_runtime_unix_test.go", "fixedLocalConversionRuntimeBatch"},
		{"amd64_fixed_local_packed_runtime_test.go", "fixedLocalPackedRuntimeAPIs"},
		{"amd64_fixed_local_data_matrix_go127_test.go", "fixedLocalDataTargetConsumers"},
		{"amd64_fixed_local_data_go127_test.go", "TestGoAMD64FixedLocalReadonlyDataThreeTargetObjects"},
		{"amd64_fixed_local_data_runtime_go127_test.go", "TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalReadonlyData"},
		{"amd64_fixed_local_transport_runtime_test.go", "TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalTransportByteValues"},
		{"amd64_fixed_local_transport_test.go", "TestGoAMD64FixedLocalTransportActualObjects"},
		{"amd64_fixed_local_nontemporal_test.go", "fixedLocalNonTemporalActualObjects"},
		{"amd64_aes_family_fixed_local_test.go", "TestX86AESFamilyActualBoundFixedLocalConsumers"},
	} {
		t.Run(owner.helper, func(t *testing.T) {
			function := fixedLocalLeaseFunctions(t, owner.filename)[owner.helper]
			if function == nil {
				t.Fatal("missing complete independently scheduled source owner", owner.helper)
			}
			calls := fixedLocalLeaseCalls(function.Body)
			if calls["fixedLocalFreshAPIs"] != 1 {
				t.Error("complete source must use the shared fresh-capture API owner exactly once")
			}
			for _, name := range []string{"fixedLocalAPIs", "requireGoAMD64FrameCapture", "runtimeOracleStageContext", "runtimeOracleProofContext"} {
				if calls[name] != 0 {
					t.Errorf("outer %s would start or share a lease before the current API", name)
				}
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if ok {
					if name := fixedLocalLeaseCallName(call); name == "source.BindFixedLocal" || name == "observer.BindFixedLocal" {
						t.Error("complete source must not transport an outer API's bound options")
					}
				}
				return true
			})
		})
	}

	// CMOV runtime currently owns one public API. Do not silently multiply its
	// expensive execution matrix while repairing the three-API object owners.
	function := fixedLocalLeaseFunctions(t, "amd64_cmov_fixed_local_runtime_test.go")["x86CMOVFixedLocalRuntimeBatch"]
	if function == nil || fixedLocalLeaseCalls(function.Body)["Translate"] != 1 || fixedLocalLeaseCalls(function.Body)["fixedLocalFreshAPIs"] != 0 {
		t.Fatal("single-API CMOV runtime ownership changed")
	}
}

func TestFixedLocalWideCompileOnlyHasThreeCompleteAPIOwners(t *testing.T) {
	functions := fixedLocalLeaseFunctions(t, "amd64_fixed_local_packed_runtime_test.go")
	owners := []struct{ root, api string }{
		{"TestGoAMD64FixedLocalPackedWideRuntimeOracleCompileOnly", "Translate"},
		{"TestGoAMD64FixedLocalPackedWideRuntimeOracleModuleCompileOnly", "Module"},
		{"TestGoAMD64FixedLocalPackedWideRuntimeOracleGoModuleCompileOnly", "GoModule"},
	}
	want := make(map[string]bool)
	for _, owner := range owners {
		want[owner.root] = true
	}
	for name := range functions {
		if strings.HasPrefix(name, "TestGoAMD64FixedLocalPackedWideRuntimeOracle") && !want[name] {
			t.Error("unknown or duplicated complete-wide API owner", name)
		}
	}
	for _, owner := range owners {
		t.Run(owner.api, func(t *testing.T) {
			function := functions[owner.root]
			if function == nil {
				t.Fatal("missing independent complete 340-kernel API owner", owner.root)
			}
			var calls []*ast.CallExpr
			ast.Inspect(function.Body, func(node ast.Node) bool {
				if call, ok := node.(*ast.CallExpr); ok && fixedLocalLeaseCallName(call) == "fixedLocalPackedRuntimeAPIs" {
					calls = append(calls, call)
				}
				return true
			})
			if len(calls) != 1 || len(calls[0].Args) != 5 {
				t.Fatal("API owner must call the unchanged full wide program once, without three-API accumulation")
			}
			call := calls[0]
			for index, name := range []string{"t", "execution", "true", "false"} {
				identifier, ok := call.Args[index].(*ast.Ident)
				if !ok || identifier.Name != name {
					t.Fatal("wide compile-only owner lost its original complete-source/execute=false role")
				}
			}
			apis, ok := call.Args[4].(*ast.CompositeLit)
			if !ok || len(apis.Elts) != 1 {
				t.Fatal("one top-level owner must execute exactly one API, not crop the source")
			}
			literal, ok := apis.Elts[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatal("API owner must retain an explicit API identity")
			}
			api, err := strconv.Unquote(literal.Value)
			if err != nil || api != owner.api {
				t.Fatal("substituted or duplicated complete-source API", api, err)
			}
		})
	}
	runtime := functions["fixedLocalPackedRuntime"]
	if runtime == nil || fixedLocalLeaseCalls(runtime.Body)["fixedLocalPackedRuntimeAPIs"] != 1 {
		t.Error("original native runtime must still execute its complete three-API plan")
	} else {
		apis := make(map[string]int)
		ast.Inspect(runtime.Body, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if ok && literal.Kind == token.STRING {
				value, err := strconv.Unquote(literal.Value)
				if err == nil {
					apis[value]++
				}
			}
			return true
		})
		for _, api := range []string{"Translate", "Module", "GoModule"} {
			if apis[api] != 1 {
				t.Error("original runtime lost one complete public API", api)
			}
		}
	}
	helper := functions["fixedLocalPackedRuntimeAPIs"]
	if helper != nil {
		calls := fixedLocalLeaseCalls(helper.Body)
		for _, name := range []string{"fixedLocalPackedLeaseBatches", "fixedLocalFreshAPIs"} {
			if calls[name] != 1 {
				t.Errorf("each API must own complete <=64-function source batches: %s count %d", name, calls[name])
			}
		}
		if calls["fixedLocalPackedRunOriginal"] != 1 {
			t.Error("the complete original Go oracle must remain independently compiled/executed once")
		}
		pipelines := make(map[string]int)
		ast.Inspect(helper.Body, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if ok && literal.Kind == token.STRING {
				value, err := strconv.Unquote(literal.Value)
				if err == nil {
					pipelines[value]++
				}
			}
			return true
		})
		for _, name := range []string{"backend_O0", "backend_O2", "IR_O2/backend_O2"} {
			if pipelines[name] != 1 {
				t.Error("every complete source batch must retain the three independent LLVM pipelines", name)
			}
		}
	}

	fixedLocalPackedRequireNativeBatchOwners(t)
}

func fixedLocalLeaseFunctions(t *testing.T, filename string) map[string]*ast.FuncDecl {
	t.Helper()
	syntax, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := make(map[string]*ast.FuncDecl)
	for _, declaration := range syntax.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			functions[function.Name.Name] = function
		}
	}
	return functions
}

func fixedLocalLeaseCalls(node ast.Node) map[string]int {
	counts := make(map[string]int)
	ast.Inspect(node, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			counts[fixedLocalLeaseCallName(call)]++
		}
		return true
	})
	return counts
}

func fixedLocalLeaseCallName(call *ast.CallExpr) string {
	if name, ok := call.Fun.(*ast.Ident); ok {
		return name.Name
	}
	if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
		if receiver, ok := selector.X.(*ast.Ident); ok {
			return receiver.Name + "." + selector.Sel.Name
		}
	}
	return ""
}

func fixedLocalLeaseRequireArguments(t *testing.T, call *ast.CallExpr, names ...string) {
	t.Helper()
	if len(call.Args) != len(names) {
		t.Errorf("%s changed complete source/binding arguments", fixedLocalLeaseCallName(call))
		return
	}
	for index, name := range names {
		identifier, ok := call.Args[index].(*ast.Ident)
		if !ok || identifier.Name != name {
			t.Errorf("%s substituted argument %d: want %s", fixedLocalLeaseCallName(call), index, name)
		}
	}
}
