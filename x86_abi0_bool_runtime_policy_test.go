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

const x86ABI0BoolNativeOwnerPath = "x86_abi0_bool_runtime_linux_amd64_test.go"

// This portable policy checks the required owner's routes, not its executed
// semantics or a new native-host certificate on the current test machine.
func x86ABI0BoolNativeOwnerPolicy(source []byte) error {
	source = normalizeNativeOwnerPolicySource(source)
	if !strings.HasPrefix(string(source), "//go:build linux && amd64\n") {
		return fmt.Errorf("required bool oracle lost its native Linux AMD64 owner")
	}
	file, err := parser.ParseFile(token.NewFileSet(), x86ABI0BoolNativeOwnerPath, source, 0)
	if err != nil {
		return err
	}
	var body *ast.BlockStmt
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "TestCrossLinuxRuntimeMatrixX86ABI0Mode32CanonicalBoolOriginalGoAndLLVM" {
			if body != nil {
				return fmt.Errorf("duplicate native bool owner")
			}
			body = function.Body
		}
	}
	ident := func(node ast.Node, name string) bool {
		value, ok := node.(*ast.Ident)
		return ok && value.Name == name
	}
	gate := func(statement ast.Stmt) bool {
		expression, ok := statement.(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := expression.X.(*ast.CallExpr)
		return ok && ident(call.Fun, "x87IA32RequireNativeHost") && len(call.Args) == 1 && ident(call.Args[0], "t")
	}
	if body == nil || len(body.List) < 2 || !gate(body.List[0]) || !gate(body.List[len(body.List)-1]) {
		return fmt.Errorf("native bool owner needs exact before/after host observations")
	}
	seals, runs := make(map[string]int), make(map[string]int)
	gates, compiles := 0, 0
	var failure error
	ast.Inspect(body, func(node ast.Node) bool {
		if failure != nil {
			return false
		}
		switch value := node.(type) {
		case *ast.ReturnStmt:
			failure = fmt.Errorf("required native owner inserted a success early return")
		case *ast.AssignStmt:
			if len(value.Rhs) != 1 {
				break
			}
			call, ok := value.Rhs[0].(*ast.CallExpr)
			if !ok || !ident(call.Fun, "x87IA32StaticExecutable") {
				break
			}
			if len(value.Lhs) != 2 || !ident(value.Lhs[1], "err") || len(call.Args) != 1 {
				failure = fmt.Errorf("static executable seal lost its error or actual artifact")
				break
			}
			program, ok := value.Lhs[0].(*ast.Ident)
			if !ok || program.Name != "originalProgram" && program.Name != "translatedProgram" ||
				program.Name == "originalProgram" && !ident(call.Args[0], "original") ||
				program.Name == "translatedProgram" && !ident(call.Args[0], "executable") {
				failure = fmt.Errorf("static seal is not bound to its actual original/LLVM artifact")
				break
			}
			seals[program.Name]++
		case *ast.CallExpr:
			if ident(value.Fun, "x87IA32RequireNativeHost") {
				gates++
			}
			if ident(value.Fun, "x87IA32RunDirect") {
				if len(value.Args) != 4 || !ident(value.Args[0], "t") || !ident(value.Args[2], "nil") {
					failure = fmt.Errorf("direct execution has an unbound argument transport")
					break
				}
				program, ok := value.Args[1].(*ast.Ident)
				environment, envOK := value.Args[3].(*ast.CallExpr)
				if !ok || program.Name != "originalProgram" && program.Name != "translatedProgram" || !envOK || len(environment.Args) != 0 {
					failure = fmt.Errorf("direct execution lost the static artifact/environment")
					break
				}
				method, ok := environment.Fun.(*ast.SelectorExpr)
				if !ok || !ident(method.X, "os") || method.Sel.Name != "Environ" {
					failure = fmt.Errorf("direct execution changed the native environment route")
					break
				}
				runs[program.Name]++
			}
			if method, ok := value.Fun.(*ast.SelectorExpr); ok {
				if strings.HasPrefix(method.Sel.Name, "Skip") || method.Sel.Name == "run" || method.Sel.Name == "compileAndRunLLVM" {
					failure = fmt.Errorf("native owner inserted a skip or general execution transport")
				}
				if method.Sel.Name == "compileLLVM" {
					compiles++
				}
			}
		case *ast.KeyValueExpr:
			if ident(value.Key, "prefix") || ident(value.Key, "preserveArgv0") {
				failure = fmt.Errorf("native owner inserted a guest execution transport")
			}
		case *ast.BasicLit:
			if value.Kind == token.STRING {
				literal, err := strconv.Unquote(value.Value)
				if err != nil || strings.Contains(literal, "qemu") || literal == "-exec" {
					failure = fmt.Errorf("native owner inserted an execution fallback")
				}
			}
		}
		return true
	})
	if failure != nil {
		return failure
	}
	if gates != 2 || compiles != 1 || seals["originalProgram"] != 1 || seals["translatedProgram"] != 1 ||
		runs["originalProgram"] != 1 || runs["translatedProgram"] != 1 {
		return fmt.Errorf("incomplete actual original/LLVM static direct routes: gates=%d compiles=%d seals=%v runs=%v", gates, compiles, seals, runs)
	}
	return nil
}

func TestX86ABI0Mode32BoolRuntimeNativeOwnerCannotEmulateOrSkip(t *testing.T) {
	source, err := os.ReadFile(x86ABI0BoolNativeOwnerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := x86ABI0BoolNativeOwnerPolicy(source); err != nil {
		t.Fatal(err)
	}
}

func TestX86ABI0Mode32BoolRuntimeNativePolicyRejectsMutation(t *testing.T) {
	source, err := os.ReadFile(x86ABI0BoolNativeOwnerPath)
	if err != nil {
		t.Fatal(err)
	}
	source = normalizeNativeOwnerPolicySource(source)
	if err := x86ABI0BoolNativeOwnerPolicy(source); err != nil {
		t.Fatal("actual owner baseline", err)
	}
	const host = "\tx87IA32RequireNativeHost(t)"
	for name, change := range map[string]struct {
		old, new string
		last     bool
	}{
		"missing-before":        {host, "\tt.Log(\"missing host\")", false},
		"missing-after":         {host, "\tt.Log(\"missing host\")", true},
		"conditional-before":    {host, "\tif true { x87IA32RequireNativeHost(t) }", false},
		"conditional-after":     {host, "\tif true { x87IA32RequireNativeHost(t) }", true},
		"early-return":          {host, host + "\n\treturn", false},
		"skip":                  {host, host + "\n\tt.Skip(\"missing tools\")", false},
		"guest-prefix":          {"execution := x86FloatCompareExecution{", "execution := x86FloatCompareExecution{prefix: []string{\"guest\"},", false},
		"emulator":              {host, host + "\n\tt.Log(\"qemu-i386\")", false},
		"exec-fallback":         {host, host + "\n\tt.Log(\"-exec\")", false},
		"original-other-seal":   {"x87IA32StaticExecutable(original)", "x87IA32StaticExecutable(executable)", false},
		"original-other-run":    {"x87IA32RunDirect(t, originalProgram, nil, os.Environ())", "x87IA32RunDirect(t, translatedProgram, nil, os.Environ())", false},
		"LLVM-general-runner":   {"x87IA32RunDirect(t, translatedProgram, nil, os.Environ())", "execution.run(t, executable)", false},
		"duplicate-observation": {host, host + "\n" + host, false},
	} {
		t.Run(name, func(t *testing.T) {
			text := string(source)
			index := strings.Index(text, change.old)
			if change.last {
				index = strings.LastIndex(text, change.old)
			}
			if index < 0 {
				t.Fatal("mutation did not match the complete actual owner")
			}
			changed := text[:index] + change.new + text[index+len(change.old):]
			if err := x86ABI0BoolNativeOwnerPolicy([]byte(changed)); err == nil {
				t.Fatal("native owner policy accepted changed execution/host routes")
			}
		})
	}
}
