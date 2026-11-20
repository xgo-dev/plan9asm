package goasmrules

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
)

func x86TableVariables(file *ast.File) (map[string]*ast.CompositeLit, error) {
	variables := map[string]*ast.CompositeLit{}
	seen := map[string]bool{}
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.VAR {
			continue
		}
		for _, spec := range general.Specs {
			value := spec.(*ast.ValueSpec)
			for i, name := range value.Names {
				if name.Name != "_" && seen[name.Name] {
					return nil, fmt.Errorf("duplicate source variable %s", name.Name)
				}
				seen[name.Name] = true
				if i < len(value.Values) {
					if literal, ok := value.Values[i].(*ast.CompositeLit); ok {
						variables[name.Name] = literal
					}
				}
			}
		}
	}
	return variables, nil
}

// Require the complete known schema. Missing, duplicate, mixed or additional
// fields must not silently disappear from an independent rule inventory.
func x86Fields(row *ast.CompositeLit, names ...string) ([]ast.Expr, error) {
	if len(row.Elts) != len(names) {
		return nil, fmt.Errorf("expected %d fields, found %d", len(names), len(row.Elts))
	}
	values := make([]ast.Expr, len(names))
	_, keyed := row.Elts[0].(*ast.KeyValueExpr)
	for index, entry := range row.Elts {
		pair, isKeyed := entry.(*ast.KeyValueExpr)
		if keyed != isKeyed {
			return nil, fmt.Errorf("mixed named and positional fields")
		}
		if !keyed {
			values[index] = entry
			continue
		}
		found := false
		for i, name := range names {
			if expression(pair.Key) == name {
				if values[i] != nil {
					return nil, fmt.Errorf("duplicate field %s", name)
				}
				values[i], found = pair.Value, true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown field %s", expression(pair.Key))
		}
	}
	return values, nil
}

type x86OperandRule struct {
	classes []string
	zcase   string
	zoffset int
}

func x86OperandRules(literal *ast.CompositeLit) ([]x86OperandRule, error) {
	if literal == nil || expression(literal.Type) != "[]ytab" || len(literal.Elts) == 0 {
		return nil, fmt.Errorf("no nonempty literal []ytab")
	}
	var rows []x86OperandRule
	for index, entry := range literal.Elts {
		row, ok := entry.(*ast.CompositeLit)
		if !ok {
			return nil, fmt.Errorf("ytab row %d is not literal", index)
		}
		values, err := x86Fields(row, "zcase", "zoffset", "args")
		if err != nil {
			return nil, fmt.Errorf("ytab row %d: %w", index, err)
		}
		zcase, named := values[0].(*ast.Ident)
		advance, err := strconv.ParseUint(expression(values[1]), 0, 8)
		args, ok := values[2].(*ast.CompositeLit)
		if !named || err != nil || !ok || expression(args.Type) != "argList" {
			return nil, fmt.Errorf("ytab row %d has unrecognized rules", index)
		}
		classes := make([]string, 0, len(args.Elts))
		for _, arg := range args.Elts {
			name, ok := arg.(*ast.Ident)
			if !ok {
				return nil, fmt.Errorf("ytab row %d has non-identifier operand class", index)
			}
			classes = append(classes, name.Name)
		}
		rows = append(rows, x86OperandRule{classes, zcase.Name, int(advance)})
	}
	return rows, nil
}

func x86EncodingBytes(literal *ast.CompositeLit) ([]string, error) {
	data := make([]string, 0, len(literal.Elts))
	for _, value := range literal.Elts {
		if !encodingExpression(value) {
			return nil, fmt.Errorf("unsupported encoding expression %q", expression(value))
		}
		data = append(data, expression(value))
	}
	return data, nil
}
