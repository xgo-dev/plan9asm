package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// These two consumers contain no command constructor. Their precise roots
// delegate to existing bounded owners, whose direct exec checks stay intact.
func TestX86MoveHalfIndirectRuntimeCommandsRetainOwnedHelpers(t *testing.T) {
	for _, spec := range []struct {
		file, root string
		calls      map[string]int
	}{
		{"x86_move_half_runtime_test.go", "TestX86MoveHalfCompleteBytesFlagsAndUpperAliases", map[string]int{
			"x86MoveHalfValueProgram": 1, "x86LEAActualTargetGoObject": 1,
			"x86ScalarFPBitViewAPI": 1, "x86ConflictFunnelPortableRuntime": 1,
		}},
		{"x86_move_half_native_linux_amd64_test.go", "TestCrossLinuxRuntimeMatrixX86MoveHalfOriginalGoFlagsDFAliases", map[string]int{
			"x87IA32RequireNativeHost": 2, "x86FloatCompareExecutionTools": 1,
			"execution.compileC": 1, "execution.run": 1, "execution.compileAndRunLLVM": 1,
			"x86MoveHalfValueProgram": 1, "x86LEAActualTargetGoObject": 1,
			"x86ScalarFPBitViewAPI": 1, "x86DwordProductIROptimize": 1, "x86RunOriginalGoNativeSource": 1,
		}},
	} {
		t.Run(spec.file, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), spec.file, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := x86CheckHalfIndirectCommandOwner(file, spec.root, spec.calls); err != nil {
				t.Fatal(err)
			}
			for call := range spec.calls {
				missing := make(map[string]int)
				for name, count := range spec.calls {
					missing[name] = count
				}
				missing[call]++
				if err := x86CheckHalfIndirectCommandOwner(file, spec.root, missing); err == nil {
					t.Fatal("policy accepted a missing or duplicate indirect owner", call)
				}
			}
		})
	}
	// Check the extra delegation edge, not only its caller's printed name.
	// runtime_exec_test.go remains in the unchanged direct-command owner list.
	file, err := parser.ParseFile(token.NewFileSet(), "amd64_conflict_funnel_runtime_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := x86CheckHalfIndirectCommandOwner(file, "x86ConflictFunnelPortableRuntime",
		map[string]int{"compileAndRunRuntimeTestWithCompiler": 1, "x86DwordProductIROptimize": 1}); err != nil {
		t.Fatal(err)
	}
}

func x86CheckHalfIndirectCommandOwner(file *ast.File, root string, required map[string]int) error {
	for _, imported := range file.Imports {
		name, err := strconv.Unquote(imported.Path.Value)
		if err != nil || name == "os/exec" || name == "syscall" {
			return fmt.Errorf("indirect owner introduced a direct process package: %s", imported.Path.Value)
		}
	}
	var owner *ast.FuncDecl
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == root {
			if owner != nil || function.Recv != nil || function.Body == nil {
				return fmt.Errorf("duplicate or unbound indirect root %s", root)
			}
			owner = function
		}
	}
	if owner == nil {
		return fmt.Errorf("missing indirect root %s", root)
	}
	var invalid error
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		method, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := method.Sel.Name
		if name == "Command" || name == "CommandContext" || name == "StartProcess" || name == "ForkExec" ||
			name == "CombinedOutput" || name == "Output" || name == "Start" || name == "Wait" || name == "Run" {
			if receiver, ok := method.X.(*ast.Ident); !ok || receiver.Name != "t" || name != "Run" {
				invalid = fmt.Errorf("indirect owner bypassed its bounded command chain: %s", name)
			}
		}
		return true
	})
	if invalid != nil {
		return invalid
	}
	observed := make(map[string]int)
	ast.Inspect(owner.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		if function, ok := call.Fun.(*ast.Ident); ok {
			name = function.Name
		} else if method, ok := call.Fun.(*ast.SelectorExpr); ok {
			if receiver, ok := method.X.(*ast.Ident); ok {
				name = receiver.Name + "." + method.Sel.Name
			}
		}
		if strings.HasPrefix(name, "execution.") && required[name] == 0 {
			invalid = fmt.Errorf("unregistered execution route in %s: %s", root, name)
		}
		if required[name] != 0 {
			observed[name]++
		}
		return true
	})
	if invalid != nil {
		return invalid
	}
	if !reflect.DeepEqual(observed, required) {
		return fmt.Errorf("indirect root %s lost exact bounded helper edges: got %v want %v", root, observed, required)
	}
	return nil
}

func TestX86MoveHalfIndirectCommandPolicyRejectsRawProcesses(t *testing.T) {
	for _, body := range []string{
		`import "os/exec"; func Owner(){Bounded();exec.Command("tool")}`,
		`func Owner(){Bounded();process.Run()}`,
		`func Owner(){Bounded();os.StartProcess("tool",nil,nil)}`,
		`func Owner(){Bounded();execution.unowned()}`,
		`func Owner(){Bounded();Bounded()}`,
		`func Owner(){}`,
	} {
		file, err := parser.ParseFile(token.NewFileSet(), "mutation.go", "package oracle\n"+body, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := x86CheckHalfIndirectCommandOwner(file, "Owner", map[string]int{"Bounded": 1}); err == nil {
			t.Fatal("indirect policy accepted an unowned or incomplete command chain", body)
		}
	}
}
