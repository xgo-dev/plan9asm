package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestTranslateTextOwnsRequestLLVMContext(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "translate.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Translate" {
			continue
		}
		var create, translate, disposeContext, disposeModule token.Pos
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
					if selector.Sel.Name == "GlobalContext" {
						t.Error("text-only translation must not use shared LLVM GlobalContext")
					}
					if selector.Sel.Name == "NewContext" {
						create = call.Pos()
					}
				}
				if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "TranslateModuleInContext" {
					translate = call.Pos()
					if len(call.Args) != 3 {
						t.Error("text translation lost its complete explicit context request")
					} else if context, ok := call.Args[0].(*ast.Ident); !ok || context.Name != "ctx" {
						t.Error("text translation does not use its request-owned context")
					}
				}
			}
			if deferred, ok := node.(*ast.DeferStmt); ok {
				if selector, ok := deferred.Call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Dispose" {
					if owner, ok := selector.X.(*ast.Ident); ok {
						switch owner.Name {
						case "ctx":
							disposeContext = deferred.Pos()
						case "mod":
							disposeModule = deferred.Pos()
						}
					}
				}
			}
			return true
		})
		if !(create != 0 && create < disposeContext && disposeContext < translate && translate < disposeModule) {
			t.Fatal("text translation must release its module before its owned context, including error paths")
		}
		return
	}
	t.Fatal("public text translation entry is missing")
}

func TestTranslateTextConcurrentRequestsKeepOriginalFile(t *testing.T) {
	const childKey = "PLAN9ASM_TRANSLATE_TEXT_CONTEXT_CHILD"
	if os.Getenv(childKey) != "1" {
		// A native LLVM race may crash rather than return a Go error. Keep that
		// failure in a bounded owned child, never an unsafe in-process probe.
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.Command(executable, "-test.run=^TestTranslateTextConcurrentRequestsKeepOriginalFile$", "-test.count=1")
		command.Env = append(os.Environ(), childKey+"=1")
		x86FloatCompareCaptureCommand(t, command)
		return
	}
	file, err := Parse(ArchAMD64, "TEXT ·f(SB),4,$0-0\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	original := x86DirectTailSnapshot(file)
	options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") },
		Sigs:       map[string]FuncSig{"f": {Name: "f", Ret: Void}}}
	const workers, iterations = 8, 32
	start := make(chan struct{})
	failures := make(chan error, workers)
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				ir, err := Translate(file, options)
				if err != nil || !strings.Contains(ir, "define void @f(") {
					failures <- fmt.Errorf("concurrent text request failed: %v", err)
					return
				}
				if ir, err := Translate(nil, options); err == nil || ir != "" {
					failures <- fmt.Errorf("failed text request published an artifact")
					return
				}
			}
		}()
	}
	close(start)
	group.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if !reflect.DeepEqual(original, x86DirectTailSnapshot(file)) {
		t.Fatal("concurrent text requests mutated their shared original source")
	}
}
