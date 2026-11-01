package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Go's arch constructors and RegisterOpcode calls consume the exported Anames
// array for x86, ARM, ARM64 and wasm. ARM64 additionally appends sveAnames to
// Anames in anames_gen.go. The similarly generated cnames5/cnames7 arrays name
// operand classes, not instructions. Do not select arrays by a name substring
// or scan every quoted string in anames*.go.
func loadOfficialOpcodeNames(goroot, goarch string) ([]string, error) {
	var dir string
	arrays := map[string]bool{"Anames": true}
	switch goarch {
	case "386", "amd64":
		dir = "x86"
	case "arm":
		dir = "arm"
	case "arm64":
		dir = "arm64"
		// Absent before Go introduced the generated SVE namespace.
		arrays["sveAnames"] = false
	case "wasm":
		dir = "wasm"
	default:
		return nil, fmt.Errorf("unsupported opcode architecture %q", goarch)
	}
	pattern := filepath.Join(goroot, "src", "cmd", "internal", "obj", dir, "anames*.go")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no official opcode tables match %s", pattern)
	}
	sort.Strings(paths)
	seenArrays := map[string]bool{}
	names := map[string]bool{}
	sveAppended := false
	for _, path := range paths {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parse official opcode table %s: %w", path, err)
		}
		if goarch == "arm64" && appendsSVEOpcodeNames(file) {
			sveAppended = true
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				value := spec.(*ast.ValueSpec)
				for index, name := range value.Names {
					if _, selected := arrays[name.Name]; !selected {
						continue
					}
					if seenArrays[name.Name] {
						return nil, fmt.Errorf("duplicate official opcode array %s in %s", name.Name, path)
					}
					seenArrays[name.Name] = true
					if index >= len(value.Values) {
						return nil, fmt.Errorf("official opcode array %s in %s has no literal initializer", name.Name, path)
					}
					entries, err := opcodeStringArray(value.Values[index])
					if err != nil {
						return nil, fmt.Errorf("official opcode array %s in %s: %w", name.Name, path, err)
					}
					for _, entry := range entries {
						op := normalizeOp(entry)
						if op != "" && op != "LAST" && !strings.HasPrefix(op, "RESERVED") {
							names[op] = true
						}
					}
				}
			}
		}
	}
	for name, required := range arrays {
		if required && !seenArrays[name] {
			return nil, fmt.Errorf("missing official opcode array %s under %s", name, pattern)
		}
	}
	if seenArrays["sveAnames"] != sveAppended {
		return nil, fmt.Errorf("ARM64 SVE opcode array and Anames registration disagree under %s", pattern)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("empty official opcode namespace under %s", pattern)
	}
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

func appendsSVEOpcodeNames(file *ast.File) bool {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "init" || fn.Body == nil {
			continue
		}
		for _, stmt := range fn.Body.List {
			assign, ok := stmt.(*ast.AssignStmt)
			if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				continue
			}
			lhs, ok := assign.Lhs[0].(*ast.Ident)
			if !ok || lhs.Name != "Anames" {
				continue
			}
			call, ok := assign.Rhs[0].(*ast.CallExpr)
			if !ok || len(call.Args) != 2 || !call.Ellipsis.IsValid() {
				continue
			}
			fun, ok := call.Fun.(*ast.Ident)
			base, baseOK := call.Args[0].(*ast.Ident)
			supplement, supplementOK := call.Args[1].(*ast.Ident)
			if ok && fun.Name == "append" && baseOK && base.Name == "Anames" &&
				supplementOK && supplement.Name == "sveAnames" {
				return true
			}
		}
	}
	return false
}

func opcodeStringArray(expr ast.Expr) ([]string, error) {
	literal, ok := expr.(*ast.CompositeLit)
	if !ok {
		return nil, fmt.Errorf("expected a literal string array")
	}
	array, ok := literal.Type.(*ast.ArrayType)
	if !ok {
		return nil, fmt.Errorf("expected a literal string array")
	}
	element, ok := array.Elt.(*ast.Ident)
	if !ok || element.Name != "string" {
		return nil, fmt.Errorf("expected string array elements")
	}
	entries := make([]string, 0, len(literal.Elts))
	for _, entry := range literal.Elts {
		if keyed, ok := entry.(*ast.KeyValueExpr); ok {
			entry = keyed.Value
		}
		value, ok := entry.(*ast.BasicLit)
		if !ok || value.Kind != token.STRING {
			return nil, fmt.Errorf("expected a literal opcode string")
		}
		name, err := strconv.Unquote(value.Value)
		if err != nil {
			return nil, fmt.Errorf("decode opcode string: %w", err)
		}
		entries = append(entries, name)
	}
	return entries, nil
}
