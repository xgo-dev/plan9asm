package plan9asm

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
)

type arm64MOVGoRow struct {
	fields  []string
	ordinal int
	line    int
}

// Independently transcribed from Go asm7's memory rows, not from the
// production grammar. code size is not the memory width. Go 1.20/1.21 lack
// a5 and separate pool classes; their ordinary long rows carry pool flags.
func arm64MOVExpectedGoRows(op, auto, oreg string, columns int) [][]string {
	var rows [][]string
	add := func(from, to, kind, size, param, flag, suffix string) {
		row := []string{op, from, "C_NONE", "C_NONE", to}
		if columns == 11 {
			row = append(row, "C_NONE")
		}
		rows = append(rows, append(row, kind, size, param, flag, suffix))
	}
	add("C_ZREG", "C_ADDR", "64", "12", "0", "0", "0")
	add("C_ADDR", "C_ZREG", "65", "12", "0", "0", "0")
	for _, memory := range []struct{ class, param string }{
		{auto, "REGSP"}, {oreg, "0"}, {"C_NSAUTO", "REGSP"}, {"C_NSOREG", "0"},
	} {
		add("C_ZREG", memory.class, "20", "4", memory.param, "0", "0")
	}
	for _, memory := range []struct{ class, param string }{
		{auto, "REGSP"}, {oreg, "0"}, {"C_NSAUTO", "REGSP"}, {"C_NSOREG", "0"},
	} {
		add(memory.class, "C_ZREG", "21", "4", memory.param, "0", "0")
	}
	for _, store := range []bool{true, false} {
		kind, pool := "31", "LFROM"
		if store {
			kind, pool = "30", "LTO"
		}
		for _, memory := range []struct{ class, param string }{
			{"C_LAUTO", "REGSP"}, {"C_LOREG", "0"},
		} {
			flag := "0"
			if columns == 10 {
				flag = pool
			}
			from, to := memory.class, "C_ZREG"
			if store {
				from, to = to, from
			}
			add(from, to, kind, "8", memory.param, flag, "0")
			if columns == 11 {
				if store {
					to += "POOL"
				} else {
					from += "POOL"
				}
				add(from, to, kind, "8", memory.param, pool, "0")
			}
		}
	}
	for _, suffix := range []string{"C_XPOST", "C_XPRE"} {
		add("C_LOREG", "C_ZREG", "22", "4", "0", "0", suffix)
	}
	for _, suffix := range []string{"C_XPOST", "C_XPRE"} {
		add("C_ZREG", "C_LOREG", "23", "4", "0", "0", suffix)
	}
	add("C_ROFF", "C_ZREG", "98", "4", "0", "0", "0")
	add("C_ZREG", "C_ROFF", "99", "4", "0", "0", "0")
	return rows
}

func arm64MOVGoExpr(expr ast.Expr) string {
	var out bytes.Buffer
	if err := format.Node(&out, token.NewFileSet(), expr); err != nil {
		return ""
	}
	return out.String()
}

func arm64MOVReadGoRows(source, version string) (map[string][]arm64MOVGoRow, int, error) {
	if len(source) == 0 || len(source) > 8<<20 {
		return nil, 0, fmt.Errorf("unknown or oversized SDK source")
	}
	columns, err := arm64CarryProbeGoOptabColumns(source, version)
	if err != nil {
		return nil, 0, err
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "asm7.go", source, parser.SkipObjectResolution)
	if err != nil {
		return nil, 0, err
	}
	bases := map[string]bool{"AMOVB": true, "AMOVH": true, "AMOVW": true, "AMOVD": true}
	memoryCases := map[string]bool{"20": true, "21": true, "22": true, "23": true, "30": true, "31": true, "64": true, "65": true, "98": true, "99": true}
	// These are the separate GP/literal/address/system-register cases, not
	// additional memory forms or grammar authority. A new case fails closed.
	otherCases := map[string]bool{
		"4": true, "12": true, "24": true, "32": true, "34": true,
		"35": true, "36": true, "37": true, "45": true,
		"68": true, "69": true, "70": true, "71": true,
	}
	memoryClass := func(class string) bool {
		for _, prefix := range []string{"C_UAUTO", "C_UOREG", "C_NSAUTO", "C_NSOREG", "C_LAUTO", "C_LOREG", "C_ADDR", "C_ROFF"} {
			if strings.HasPrefix(class, prefix) {
				return true
			}
		}
		return false
	}
	rows := make(map[string][]arm64MOVGoRow)
	tables, builders, aliasCalls := 0, 0, 0
	aliases := map[string]string{"AMOVB": "AMOVBU", "AMOVH": "AMOVHU", "AMOVW": "AMOVWU"}
	seenAliases := make(map[string]bool)
	for _, declaration := range file.Decls {
		if group, ok := declaration.(*ast.GenDecl); ok && group.Tok == token.VAR {
			for _, spec := range group.Specs {
				value := spec.(*ast.ValueSpec)
				for index, name := range value.Names {
					if name.Name != "optab" {
						continue
					}
					tables++
					if index >= len(value.Values) {
						return nil, 0, fmt.Errorf("missing actual optab literal")
					}
					table, ok := value.Values[index].(*ast.CompositeLit)
					if !ok {
						return nil, 0, fmt.Errorf("actual optab is not a literal")
					}
					array, ok := table.Type.(*ast.ArrayType)
					if !ok || array.Len != nil || arm64MOVGoExpr(array.Elt) != "Optab" {
						return nil, 0, fmt.Errorf("unknown original optab type")
					}
					for ordinal, element := range table.Elts {
						row, ok := element.(*ast.CompositeLit)
						if !ok || len(row.Elts) == 0 {
							return nil, 0, fmt.Errorf("unknown actual optab row")
						}
						op := arm64MOVGoExpr(row.Elts[0])
						if op == "AMOVBU" || op == "AMOVHU" || op == "AMOVWU" {
							return nil, 0, fmt.Errorf("unsigned MOV acquired a direct row")
						}
						if !bases[op] {
							continue
						}
						if len(row.Elts) != columns {
							return nil, 0, fmt.Errorf("MOV row does not match full SDK schema")
						}
						fields := make([]string, columns)
						for field, expr := range row.Elts {
							if _, keyed := expr.(*ast.KeyValueExpr); keyed {
								return nil, 0, fmt.Errorf("unknown keyed MOV row")
							}
							fields[field] = arm64MOVGoExpr(expr)
						}
						kind := fields[columns-5]
						if _, err := strconv.ParseInt(kind, 10, 8); err != nil {
							return nil, 0, fmt.Errorf("unknown MOV encoder type: %q", kind)
						}
						memory := memoryCases[kind]
						for _, class := range fields[1 : columns-5] {
							memory = memory || memoryClass(class)
						}
						if memory {
							rows[op] = append(rows[op], arm64MOVGoRow{fields, ordinal, fset.Position(row.Pos()).Line})
						} else if !otherCases[kind] {
							return nil, 0, fmt.Errorf("unregistered MOV table case %s", kind)
						}
					}
				}
			}
		}
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "buildop" || function.Body == nil {
			continue
		}
		builders++
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if ok && arm64MOVGoExpr(call.Fun) == "oprangeset" && len(call.Args) != 0 {
				switch arm64MOVGoExpr(call.Args[0]) {
				case "AMOVBU", "AMOVHU", "AMOVWU":
					aliasCalls++
				}
			}
			return true
		})
		var aliasErr error
		ast.Inspect(function.Body, func(node ast.Node) bool {
			clause, ok := node.(*ast.CaseClause)
			if !ok || len(clause.List) != 1 {
				return true
			}
			base := arm64MOVGoExpr(clause.List[0])
			alias, selected := aliases[base]
			if !selected {
				return true
			}
			if seenAliases[base] || len(clause.Body) != 1 {
				aliasErr = fmt.Errorf("unknown or repeated MOV alias base %s", base)
				return false
			}
			statement, ok := clause.Body[0].(*ast.ExprStmt)
			if !ok {
				aliasErr = fmt.Errorf("unknown MOV alias statement")
				return false
			}
			call, ok := statement.X.(*ast.CallExpr)
			if !ok || arm64MOVGoExpr(call.Fun) != "oprangeset" || len(call.Args) != 2 ||
				arm64MOVGoExpr(call.Args[0]) != alias || arm64MOVGoExpr(call.Args[1]) != "t" {
				aliasErr = fmt.Errorf("changed exact MOV alias %s -> %s", base, alias)
				return false
			}
			seenAliases[base] = true
			return false
		})
		if aliasErr != nil {
			return nil, 0, aliasErr
		}
	}
	if tables != 1 || builders != 1 || len(seenAliases) != 3 || aliasCalls != 3 {
		return nil, 0, fmt.Errorf("incomplete original MOV table/alias inventory")
	}
	return rows, columns, nil
}

func arm64MOVCheckCompleteGoRows(source, version string) (map[string][]arm64MOVGoRow, int, error) {
	rows, columns, err := arm64MOVReadGoRows(source, version)
	if err != nil {
		return nil, 0, err
	}
	for _, family := range []struct{ op, auto, oreg string }{
		{"AMOVB", "C_UAUTO4K", "C_UOREG4K"},
		{"AMOVH", "C_UAUTO8K", "C_UOREG8K"},
		{"AMOVW", "C_UAUTO16K", "C_UOREG16K"},
		{"AMOVD", "C_UAUTO32K", "C_UOREG32K"},
	} {
		var fields [][]string
		for _, row := range rows[family.op] {
			fields = append(fields, row.fields)
		}
		want := arm64MOVExpectedGoRows(family.op, family.auto, family.oreg, columns)
		if !reflect.DeepEqual(fields, want) {
			return nil, 0, fmt.Errorf("complete Go %s %s memory rows changed: got %v want %v", version, family.op, fields, want)
		}
	}
	return rows, columns, nil
}
