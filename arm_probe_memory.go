package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// A standalone probe has no generated go_asm.h layout constants. This is
// distinct from a concrete register shift or a descriptive C_AUTO stack name.
// Translation still rejects unresolved offsets; the full corpus must supply
// the definitions and compile the resulting instruction with LLVM.
func armMemoryOffsetNeedsContext(memory MemRef) bool {
	raw := memory.OffRaw
	if raw == "" || armNamedStackOffset(memory) {
		return false
	}
	if _, concreteShift := armMemoryShift(memory); concreteShift {
		return false
	}
	for _, shift := range []ShiftOp{ShiftRotate, ShiftArith, ShiftLeft, ShiftRight} {
		if i := strings.Index(raw, string(shift)); i >= 0 {
			if reg, ok := parseReg(strings.TrimSpace(raw[:i])); ok && isARMGeneralReg(reg) {
				raw = raw[i+len(shift):]
				break
			}
		}
	}
	return memoryOffsetExpressionNeedsContext(raw)
}

func memoryOffsetExpressionNeedsContext(raw string) bool {
	expr, err := parser.ParseExpr(strings.ReplaceAll(strings.TrimSpace(raw), "~", "^"))
	if err != nil {
		return false
	}
	symbolic := false
	var valid func(ast.Expr) bool
	valid = func(expr ast.Expr) bool {
		switch expr := expr.(type) {
		case *ast.Ident:
			if _, register := parseReg(expr.Name); register || expr.Name == "g" {
				return false
			}
			symbolic = true
			return true
		case *ast.BasicLit:
			_, ok := evalImmExpr(expr)
			return ok
		case *ast.ParenExpr:
			return valid(expr.X)
		case *ast.UnaryExpr:
			return (expr.Op == token.ADD || expr.Op == token.SUB || expr.Op == token.XOR) && valid(expr.X)
		case *ast.BinaryExpr:
			switch expr.Op {
			case token.ADD, token.SUB, token.MUL, token.QUO, token.REM, token.SHL, token.SHR, token.AND, token.OR, token.XOR:
				return valid(expr.X) && valid(expr.Y)
			}
		}
		return false
	}
	return valid(expr) && symbolic
}
