package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
)

type sharedX86OpcodeRole uint8

const (
	sharedX86NoOpcodeRole sharedX86OpcodeRole = iota
	sharedX86OpcodeValue
	sharedX86InstructionValue
)

// The inputs are the repository's actual Op and Instr, not every local type,
// variable or field with the same spelling. This is diagnostic inventory only.
type sharedX86OpcodeTypes struct {
	packageName  string
	op, instr    *ast.Object
	packageNames map[string][]*ast.Object
}

func loadSharedX86OpcodeTypes(root string, files []*ast.File) (*sharedX86OpcodeTypes, error) {
	index := &sharedX86OpcodeTypes{packageNames: make(map[string][]*ast.Object)}
	filename := filepath.Join(root, "types.go")
	source, err := os.ReadFile(filename)
	if errors.Is(err, os.ErrNotExist) {
		return index, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read shared x86 types: %w", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), filename, source, 0)
	if err != nil {
		return nil, fmt.Errorf("parse shared x86 types: %w", err)
	}
	index.packageName = file.Name.Name
	for _, current := range append(files, file) {
		if current.Name.Name == index.packageName {
			for name, object := range current.Scope.Objects {
				index.packageNames[name] = append(index.packageNames[name], object)
			}
		}
	}
	op := file.Scope.Lookup("Op")
	declaration, ok := sharedX86TypeDeclaration(op)
	if !ok || declaration.Assign.IsValid() || len(index.packageNames["Op"]) != 1 ||
		!sharedX86BuiltinType(declaration.Type, "string", index.packageNames) {
		return index, nil
	}
	index.op = op
	instr := file.Scope.Lookup("Instr")
	declaration, ok = sharedX86TypeDeclaration(instr)
	if !ok || declaration.Assign.IsValid() || len(index.packageNames["Instr"]) != 1 {
		return index, nil
	}
	structure, ok := declaration.Type.(*ast.StructType)
	if !ok {
		return index, nil
	}
	fields := 0
	for _, field := range structure.Fields.List {
		for _, name := range field.Names {
			if name.Name == "Op" {
				fields++
				identifier, valid := field.Type.(*ast.Ident)
				if !valid || identifier.Obj != op {
					return index, nil
				}
			}
		}
	}
	if fields == 1 {
		index.instr = instr
	}
	return index, nil
}

func sharedX86TypeDeclaration(object *ast.Object) (*ast.TypeSpec, bool) {
	if object == nil || object.Kind != ast.Typ {
		return nil, false
	}
	declaration, ok := object.Decl.(*ast.TypeSpec)
	return declaration, ok
}

func sharedX86BuiltinType(expression ast.Expr, name string, packageNames map[string][]*ast.Object) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == name && identifier.Obj == nil && len(packageNames[name]) == 0
}

type sharedX86OpcodeBindings struct {
	types   *sharedX86OpcodeTypes
	imports map[string]string
	mutable map[*ast.Object]bool
}

func newSharedX86OpcodeBindings(file *ast.File, types *sharedX86OpcodeTypes) *sharedX86OpcodeBindings {
	bindings := &sharedX86OpcodeBindings{types: types,
		imports: make(map[string]string), mutable: make(map[*ast.Object]bool)}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		name := filepath.Base(path)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		bindings.imports[name] = path
	}
	// An initializer cannot establish a later mutable value. Reject the whole
	// alias rather than inventing a compiler CFG or following stale initializers.
	mark := func(expression ast.Expr, declaration ast.Node) {
		if name, ok := expression.(*ast.Ident); ok && name.Obj != nil && name.Obj.Decl != declaration {
			bindings.mutable[name.Obj] = true
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch statement := node.(type) {
		case *ast.AssignStmt:
			for _, expression := range statement.Lhs {
				mark(expression, statement)
			}
		case *ast.RangeStmt:
			mark(statement.Key, statement)
			mark(statement.Value, statement)
		case *ast.IncDecStmt:
			mark(statement.X, nil)
		}
		return true
	})
	return bindings
}

func (bindings *sharedX86OpcodeBindings) typeRole(expression ast.Expr, depth int) sharedX86OpcodeRole {
	if depth > 8 {
		return sharedX86NoOpcodeRole
	}
	switch value := expression.(type) {
	case *ast.ParenExpr:
		return bindings.typeRole(value.X, depth+1)
	case *ast.StarExpr:
		if bindings.typeRole(value.X, depth+1) == sharedX86InstructionValue {
			return sharedX86InstructionValue
		}
	case *ast.Ident:
		object := value.Obj
		if object == nil {
			objects := bindings.types.packageNames[value.Name]
			if len(objects) != 1 || bindings.imports[value.Name] != "" {
				return sharedX86NoOpcodeRole
			}
			object = objects[0]
		}
		if object == bindings.types.op && object != nil {
			return sharedX86OpcodeValue
		}
		if object == bindings.types.instr && object != nil {
			return sharedX86InstructionValue
		}
		if declaration, ok := sharedX86TypeDeclaration(object); ok && declaration.Assign.IsValid() {
			return bindings.typeRole(declaration.Type, depth+1)
		}
	}
	return sharedX86NoOpcodeRole
}

func (bindings *sharedX86OpcodeBindings) builtin(expression ast.Expr, name string) bool {
	return sharedX86BuiltinType(expression, name, bindings.types.packageNames) && bindings.imports[name] == ""
}

func (bindings *sharedX86OpcodeBindings) stringsCall(call *ast.CallExpr) (string, bool) {
	function, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := function.X.(*ast.Ident)
	return function.Sel.Name, ok && pkg.Obj == nil && bindings.imports[pkg.Name] == "strings"
}

func (bindings *sharedX86OpcodeBindings) cutInput(call *ast.CallExpr) (ast.Expr, bool) {
	name, imported := bindings.stringsCall(call)
	if !imported || name != "Cut" || len(call.Args) != 2 {
		return nil, false
	}
	separator, ok := call.Args[1].(*ast.BasicLit)
	if !ok || separator.Kind != token.STRING {
		return nil, false
	}
	text, err := strconv.Unquote(separator.Value)
	return call.Args[0], err == nil && text == "."
}

// Match the initializer to its exact declaration slot. For strings.Cut, only
// the first of three results preserves the opcode; suffix/found do not.
func (bindings *sharedX86OpcodeBindings) initializer(object *ast.Object) ast.Expr {
	if object == nil || bindings.mutable[object] {
		return nil
	}
	var names []*ast.Ident
	var values []ast.Expr
	switch declaration := object.Decl.(type) {
	case *ast.ValueSpec:
		names, values = declaration.Names, declaration.Values
	case *ast.AssignStmt:
		values = declaration.Rhs
		for _, expression := range declaration.Lhs {
			name, ok := expression.(*ast.Ident)
			if !ok {
				return nil
			}
			names = append(names, name)
		}
	default:
		return nil
	}
	for index, name := range names {
		if name.Obj != object {
			continue
		}
		if len(values) == len(names) {
			return values[index]
		}
		if index == 0 && len(names) == 3 && len(values) == 1 {
			if call, ok := values[0].(*ast.CallExpr); ok {
				if input, valid := bindings.cutInput(call); valid {
					return input
				}
			}
		}
	}
	return nil
}

func (bindings *sharedX86OpcodeBindings) expressionRole(expression ast.Expr, depth int) sharedX86OpcodeRole {
	if depth > 8 {
		return sharedX86NoOpcodeRole
	}
	switch value := expression.(type) {
	case *ast.Ident:
		if value.Obj == nil || bindings.mutable[value.Obj] {
			return sharedX86NoOpcodeRole
		}
		if field, ok := value.Obj.Decl.(*ast.Field); ok {
			return bindings.typeRole(field.Type, depth+1)
		}
		if declaration, ok := value.Obj.Decl.(*ast.ValueSpec); ok &&
			bindings.typeRole(declaration.Type, depth+1) == sharedX86InstructionValue {
			return sharedX86InstructionValue
		}
		return bindings.expressionRole(bindings.initializer(value.Obj), depth+1)
	case *ast.ParenExpr:
		return bindings.expressionRole(value.X, depth+1)
	case *ast.SelectorExpr:
		if value.Sel.Name == "Op" && bindings.expressionRole(value.X, depth+1) == sharedX86InstructionValue {
			return sharedX86OpcodeValue
		}
	case *ast.CallExpr:
		if len(value.Args) == 1 && (bindings.builtin(value.Fun, "string") ||
			bindings.typeRole(value.Fun, depth+1) == sharedX86OpcodeValue) &&
			bindings.expressionRole(value.Args[0], depth+1) == sharedX86OpcodeValue {
			return sharedX86OpcodeValue
		}
		if name, imported := bindings.stringsCall(value); imported && len(value.Args) == 1 {
			switch name {
			case "ToUpper", "ToLower", "TrimSpace":
				if bindings.expressionRole(value.Args[0], depth+1) == sharedX86OpcodeValue {
					return sharedX86OpcodeValue
				}
			}
		}
	}
	return sharedX86NoOpcodeRole
}

func (bindings *sharedX86OpcodeBindings) opcodeMap(expression ast.Expr, depth int) *ast.CompositeLit {
	if depth > 8 {
		return nil
	}
	switch value := expression.(type) {
	case *ast.ParenExpr:
		return bindings.opcodeMap(value.X, depth+1)
	case *ast.Ident:
		return bindings.opcodeMap(bindings.initializer(value.Obj), depth+1)
	case *ast.CompositeLit:
		if typ, ok := value.Type.(*ast.MapType); ok && (bindings.builtin(typ.Key, "string") ||
			bindings.typeRole(typ.Key, depth+1) == sharedX86OpcodeValue) {
			return value
		}
	}
	return nil
}

// Shared effects also contain operand/condition switches. Only actual typed
// opcode dispatch can advertise names; unrelated maps and suffixes cannot.
func collectSharedX86OpcodeDispatch(supported map[string]struct{}, file *ast.File, types *sharedX86OpcodeTypes) {
	if types.op == nil || file.Name.Name != types.packageName {
		return
	}
	bindings := newSharedX86OpcodeBindings(file, types)
	add := func(expression ast.Expr) {
		literal, ok := expression.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return
		}
		name, err := strconv.Unquote(literal.Value)
		if err == nil {
			if name = normalizeOp(name); name != "" {
				supported[name] = struct{}{}
			}
		}
	}
	addMap := func(literal *ast.CompositeLit) {
		if literal != nil {
			for _, element := range literal.Elts {
				if entry, ok := element.(*ast.KeyValueExpr); ok {
					add(entry.Key)
				}
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.SwitchStmt:
			if bindings.expressionRole(value.Tag, 0) == sharedX86OpcodeValue {
				for _, statement := range value.Body.List {
					for _, expression := range statement.(*ast.CaseClause).List {
						add(expression)
					}
				}
			}
		case *ast.BinaryExpr:
			if value.Op == token.EQL || value.Op == token.NEQ {
				if bindings.expressionRole(value.X, 0) == sharedX86OpcodeValue {
					add(value.Y)
				} else if bindings.expressionRole(value.Y, 0) == sharedX86OpcodeValue {
					add(value.X)
				}
			}
		case *ast.CompositeLit:
			if typ, ok := value.Type.(*ast.MapType); ok && bindings.typeRole(typ.Key, 0) == sharedX86OpcodeValue {
				addMap(value)
			}
		case *ast.IndexExpr:
			if bindings.expressionRole(value.Index, 0) == sharedX86OpcodeValue {
				addMap(bindings.opcodeMap(value.X, 0))
			}
		}
		return true
	})
}
