package gotoolprofile

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strconv"
)

// go/constant keeps string concatenations as lazy DAGs. Neither the original
// source byte bound nor the AST node bound limits materializing that DAG in
// go/types (for example len) or ExactString. This is a conservative resource
// precheck, not another Go constant evaluator. It may refuse a query domain,
// but cannot supply definitions, source acceptance or omission authority.
type nativeHeaderStringBudget struct {
	limit       uint64
	work        int
	bindings    map[string]ast.Expr
	memo        map[string]uint64
	active      map[string]bool
	unpublished []ast.Expr
	selector    func(*ast.SelectorExpr) (uint64, error)
}

func boundNativeHeaderStrings(files []*ast.File) error {
	budget, err := newNativeHeaderStringBudget(files)
	if err != nil {
		return err
	}
	return budget.check(files)
}

func newNativeHeaderStringBudget(files []*ast.File) (*nativeHeaderStringBudget, error) {
	budget := &nativeHeaderStringBudget{
		limit: generatedHeaderByteLimit, bindings: make(map[string]ast.Expr),
		memo: make(map[string]uint64), active: make(map[string]bool),
	}
	for _, file := range files {
		for _, declaration := range file.Decls {
			group, ok := declaration.(*ast.GenDecl)
			if !ok || group.Tok != token.CONST {
				continue
			}
			var previous []ast.Expr
			for _, item := range group.Specs {
				spec := item.(*ast.ValueSpec)
				if len(spec.Values) != 0 {
					previous = spec.Values
				}
				for index, name := range spec.Names {
					if index >= len(previous) {
						continue // The unchanged typechecker diagnoses invalid arity.
					}
					if name.Name == "_" {
						budget.unpublished = append(budget.unpublished, previous[index])
						continue
					}
					if _, duplicate := budget.bindings[name.Name]; duplicate {
						return nil, fmt.Errorf("native header original constant declaration is duplicated")
					}
					budget.bindings[name.Name] = previous[index]
				}
				if len(previous) > len(spec.Names) {
					budget.unpublished = append(budget.unpublished, previous[len(spec.Names):]...)
				}
			}
		}
	}
	return budget, nil
}

func (budget *nativeHeaderStringBudget) check(files []*ast.File) error {
	var names []string
	for name := range budget.bindings {
		names = append(names, name)
	}
	sort.Strings(names)
	var total uint64
	addExpression := func(expression ast.Expr) error {
		width, err := budget.expression(expression, 0)
		if err != nil {
			return err
		}
		total, err = budget.add(total, width)
		return err
	}
	for _, name := range names {
		if err := addExpression(&ast.Ident{Name: name}); err != nil {
			return err
		}
	}
	for _, expression := range budget.unpublished {
		if err := addExpression(expression); err != nil {
			return err
		}
	}
	for _, file := range files {
		for _, declaration := range file.Decls {
			if group, ok := declaration.(*ast.GenDecl); ok && group.Tok == token.CONST {
				continue // Complete constant bindings were already charged above.
			}
			var failure error
			ast.Inspect(declaration, func(node ast.Node) bool {
				if node == nil || failure != nil {
					return false
				}
				if _, body := node.(*ast.BlockStmt); body {
					return false // Matches IgnoreFuncBodies; signatures remain checked.
				}
				if expression, ok := node.(ast.Expr); ok {
					failure = addExpression(expression)
					return false
				}
				return true
			})
			if failure != nil {
				return failure
			}
		}
	}
	return nil
}

func (budget *nativeHeaderStringBudget) add(left, right uint64) (uint64, error) {
	if left > budget.limit || right > budget.limit-left {
		return 0, &nativeHeaderUnsupportedDomain{"native header string expansion exceeds its bounded query domain"}
	}
	return left + right, nil
}

func (budget *nativeHeaderStringBudget) expression(expression ast.Expr, depth int) (uint64, error) {
	budget.work++
	if depth > 128 || budget.work > 100000 {
		return 0, &nativeHeaderUnsupportedDomain{"native header string expansion exceeds its bounded query work"}
	}
	switch expression := expression.(type) {
	case *ast.SelectorExpr:
		if budget.selector != nil {
			return budget.selector(expression)
		}
		// Ordinary field receivers may contain original literals and calls.
		// Observe those costs without evaluating the receiver or granting an
		// imported string definition. A builtin package qualifier costs zero.
		return budget.expression(expression.X, depth+1)
	case *ast.BasicLit:
		if expression.Kind != token.STRING {
			return 0, nil
		}
		value, err := strconv.Unquote(expression.Value)
		if err != nil {
			return 0, fmt.Errorf("native header original string literal is invalid: %w", err)
		}
		// Six output bytes per original byte bounds Quote's Unicode/control
		// escaping, including invalid UTF-8 and concatenation across literals.
		width := uint64(len(value)) * 6
		return budget.add(0, width)
	case *ast.Ident:
		definition, found := budget.bindings[expression.Name]
		if !found {
			return 0, nil // Names/types are resolved by the unchanged typechecker.
		}
		if width, found := budget.memo[expression.Name]; found {
			return width, nil
		}
		if budget.active[expression.Name] {
			return 0, fmt.Errorf("native header original constant declaration is recursive")
		}
		budget.active[expression.Name] = true
		width, err := budget.expression(definition, depth+1)
		delete(budget.active, expression.Name)
		if err == nil {
			budget.memo[expression.Name] = width
		}
		return width, err
	default:
		var width uint64
		// A constant rune-to-string conversion produces at most four UTF-8
		// bytes. Other calls/operations conservatively retain all operand
		// expansion costs; this cannot evaluate or authorize an unknown call.
		if _, call := expression.(*ast.CallExpr); call {
			width = 4 * 6
		}
		var failure error
		ast.Inspect(expression, func(node ast.Node) bool {
			if node == nil || node == expression {
				return node != nil
			}
			if failure != nil {
				return false
			}
			if _, body := node.(*ast.BlockStmt); body {
				return false
			}
			if child, ok := node.(ast.Expr); ok {
				var operand uint64
				operand, failure = budget.expression(child, depth+1)
				if failure == nil {
					width, failure = budget.add(width, operand)
				}
				return false
			}
			return true
		})
		return width, failure
	}
}
