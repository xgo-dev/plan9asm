package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"
)

// This is an ordering invariant, not a mnemonic allowlist. A newly added
// family cannot precede either complete-source owner, even when its own
// operand grammar would accept the same numerical bytes or native pointer.
func TestX86ExistingSDKOwnersAreFirstNativeTransferConsumers(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "amd64_scalar_fp_native_read.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var found int
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "checkLoweredScalarFPResultInitialization" {
			continue
		}
		for _, statement := range function.Body.List {
			assignment, ok := statement.(*ast.AssignStmt)
			if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				continue
			}
			name, ok := assignment.Lhs[0].(*ast.Ident)
			transfer, literal := assignment.Rhs[0].(*ast.FuncLit)
			if !ok || name.Name != "transfer" || !literal {
				continue
			}
			found++
			var consumers []string
			for _, statement := range transfer.Body.List {
				conditional, ok := statement.(*ast.IfStmt)
				if !ok {
					continue
				}
				assignment, ok := conditional.Init.(*ast.AssignStmt)
				if !ok || len(assignment.Rhs) != 1 {
					t.Fatal("native transfer acquired an unmodeled conditional before its owner invariant")
				}
				call, ok := assignment.Rhs[0].(*ast.CallExpr)
				if !ok {
					t.Fatal("native transfer consumer lost its direct owned call")
				}
				callee, ok := call.Fun.(*ast.Ident)
				if !ok {
					t.Fatal("native transfer acquired an unmodeled owner/receiver")
				}
				consumers = append(consumers, callee.Name)
				if len(consumers) == 2 {
					break
				}
			}
			if !reflect.DeepEqual(consumers, []string{"x86ResultSDKLiteralStep", "x86ResultNumericalReadStep"}) {
				t.Fatal("native family preempted the complete original source owners", consumers)
			}
		}
	}
	if found != 1 {
		t.Fatal("missing or duplicate actual private native transfer source", found)
	}
}
