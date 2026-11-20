package plan9asm

import (
	"go/ast"
	"go/token"
	"strconv"
	"testing"
)

func TestFixedLocalWideCompileOnlyOwnersDoNotRequireRuntimeTransport(t *testing.T) {
	functions := fixedLocalLeaseFunctions(t, "amd64_fixed_local_packed_runtime_test.go")
	for _, name := range []string{
		"TestGoAMD64FixedLocalPackedWideRuntimeOracleCompileOnly",
		"TestGoAMD64FixedLocalPackedWideRuntimeOracleModuleCompileOnly",
		"TestGoAMD64FixedLocalPackedWideRuntimeOracleGoModuleCompileOnly",
	} {
		t.Run(name, func(t *testing.T) {
			function := functions[name]
			if function == nil {
				t.Fatal("missing complete 340-kernel object owner", name)
			}
			calls := fixedLocalLeaseCalls(function.Body)
			if calls["fixedLocalPackedCompileOnlyTools"] != 1 || calls["x86FloatCompareExecutionTools"] != 0 {
				t.Error("object-only source/LLVM/C compilation must not depend on a CPU or emulator execution route")
			}
		})
	}
	t.Run("whole-vector move", func(t *testing.T) {
		move := fixedLocalLeaseFunctions(t, "amd64_packed_vector_move_aligned_oracle_unix_test.go")["TestX86PackedMoveAlignedOriginalGoOracleCompileOnly"]
		if move == nil {
			t.Fatal("missing original-Go aligned move object owner")
		}
		calls := fixedLocalLeaseCalls(move.Body)
		if calls["fixedLocalPackedCompileOnlyTools"] != 1 || calls["x86FloatCompareExecutionTools"] != 0 {
			t.Error("move object compilation must select LLVM22/SDK without execution capability")
		}
	})
	// Keep the actual execution roles separate, including their real CPU/OS
	// checks. Object compilation cannot certify the original native programs.
	sse := functions["TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPackedSSE"]
	if sse == nil || fixedLocalLeaseCalls(sse.Body)["x86FloatCompareRuntimeTools"] != 1 {
		t.Error("actual SSE execution tools were weakened")
	}
	fixedLocalPackedRequireNativeBatchOwners(t)
}

func TestFixedLocalCompileOnlyToolsRetainExactLLVMAndSDKWithoutExecution(t *testing.T) {
	functions := fixedLocalLeaseFunctions(t, "amd64_fixed_local_packed_runtime_test.go")
	helper := functions["fixedLocalPackedCompileOnlyTools"]
	if helper == nil {
		t.Fatal("missing LLVM22 object-only tool selector independent of execution capability")
	}
	calls := fixedLocalLeaseCalls(helper.Body)
	for _, name := range []string{"findLlcAndClang", "testTargetTriple", "runtimeOracleStageContext", "nativeoracle.DarwinClangFlags"} {
		if calls[name] != 1 {
			t.Error("object-only tool selection lost its exact LLVM22/target/bounded real SDK selection", name, calls[name])
		}
	}
	for _, name := range []string{
		"x86FloatCompareExecutionTools", "x86FloatAddSubRuntimeTools", "x86FloatCompareRuntimeTools",
		"x86PackedDoubleDwordNativeTools", "rosettaAvailable", "exec.LookPath", "t.Skip", "t.Skipf", "execution.run",
	} {
		if calls[name] != 0 {
			t.Error("compile-only tools gained a CPU, transport or skip dependency", name)
		}
	}
	ast.Inspect(helper.Body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && fixedLocalLeaseCallName(call) == "testTargetTriple" {
			if len(call.Args) != 2 {
				t.Error("object-only target lost its actual host OS and original AMD64 ABI")
				return true
			}
			os, ok := call.Args[0].(*ast.SelectorExpr)
			if !ok || !fixedLocalLeaseIdent(os.X, "runtime") || os.Sel.Name != "GOOS" {
				t.Error("object-only target substituted its actual host OS")
			}
			arch, ok := call.Args[1].(*ast.BasicLit)
			if !ok || arch.Kind != token.STRING {
				t.Error("object-only target lost its explicit original AMD64 ABI")
			} else if value, err := strconv.Unquote(arch.Value); err != nil || value != "amd64" {
				t.Error("object-only target changed its original AMD64 ABI", value, err)
			}
		}
		if literal, ok := node.(*ast.CompositeLit); ok && fixedLocalLeaseIdent(literal.Type, "x86FloatCompareExecution") {
			for _, field := range literal.Elts {
				if entry, ok := field.(*ast.KeyValueExpr); ok &&
					(fixedLocalLeaseIdent(entry.Key, "prefix") || fixedLocalLeaseIdent(entry.Key, "preserveArgv0")) {
					t.Error("object-only tool selection must not configure any executable transport")
				}
			}
		}
		return true
	})
}

func fixedLocalLeaseIdent(expression ast.Expr, name string) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == name
}
