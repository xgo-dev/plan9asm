package plan9asm

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestLLVMObjectHelperRetainsIndependentStageContexts(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "stdlib_arm64_test_helpers_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"testGoEnv", "compileLLVMToObject"} {
		t.Run(name, func(t *testing.T) {
			var function *ast.FuncDecl
			for _, decl := range file.Decls {
				if candidate, ok := decl.(*ast.FuncDecl); ok && candidate.Name.Name == name {
					function = candidate
				}
			}
			if function == nil {
				t.Fatal("bounded object helper missing")
			}
			contexts, commands, consumers, cancellations := 0, 0, 0, 0
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				if ident, ok := call.Fun.(*ast.Ident); ok {
					switch ident.Name {
					case "runtimeOracleStageContext":
						contexts++
					case "runtimeOracleCombinedOutput":
						consumers++
					case "cancel":
						cancellations++
					}
				}
				if method, ok := call.Fun.(*ast.SelectorExpr); ok {
					if receiver, ok := method.X.(*ast.Ident); ok && receiver.Name == "exec" {
						if method.Sel.Name != "CommandContext" {
							t.Errorf("helper lost its stage context: exec.%s", method.Sel.Name)
						}
						commands++
					}
				}
				return true
			})
			if contexts != 1 || commands != 1 || consumers != 1 || cancellations != 1 {
				t.Fatalf("independent stage lifecycle required: context=%d command=%d consumer=%d cancel=%d",
					contexts, commands, consumers, cancellations)
			}
		})
	}
}

func TestLLVMObjectHelperActualLLVM22Objects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	const ir = "define i32 @bounded_object(i32 %x) { %r = add i32 %x, 7 ret i32 %r }\n"
	for _, triple := range []string{
		"i386-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf",
		"aarch64-unknown-linux-gnu", "wasm32-unknown-unknown",
	} {
		t.Run(triple, func(t *testing.T) {
			compileLLVMToObject(t, llc, triple, "bounded.ll", "bounded.o", ir)
		})
	}
}

func TestLLVMObjectHelperActualGoEnv(t *testing.T) {
	value, err := testGoEnv(t, "GOROOT")
	if err != nil || value == "" {
		t.Fatalf("actual go env failed: %v\n%s", err, value)
	}
	if info, err := os.Stat(value); err != nil || !info.IsDir() {
		t.Fatalf("actual GOROOT is not a directory: %q: %v", value, err)
	}
}

func TestLLVMObjectHelperGoEnvRetainsActualExitAndOutput(t *testing.T) {
	output, err := testGoEnv(t, "-definitely-not-a-valid-go-flag")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(output, "flag provided but not defined: -definitely-not-a-valid-go-flag") {
		t.Fatalf("actual go env exit/output was lost: %v\n%s", err, output)
	}
}
