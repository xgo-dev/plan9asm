package main

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// This inventory describes source registration, not operand legality, lowering,
// LLVM compilation, linking or runtime proof. Sentinels remain explicit entries.
type frontendInventory struct {
	SchemaVersion int                   `json:"schema_version"`
	Scope         string                `json:"scope"`
	Entries       []frontendName        `json:"entries"`
	Sources       []frontendSourceProof `json:"sources"`
}

type frontendName struct {
	Spelling           string           `json:"spelling"`
	AsID               *int64           `json:"as_id"`
	Canonical          string           `json:"canonical"`
	CanonicalNamespace string           `json:"canonical_namespace"`
	Sentinel           bool             `json:"sentinel"`
	Origins            []frontendOrigin `json:"origins"`
}

type frontendOrigin struct {
	Role   string `json:"role"`
	Source string `json:"source"`
	Line   int    `json:"line"`
}

type frontendSourceProof struct {
	Source string `json:"source"`
	SHA256 string `json:"sha256"`
}

type frontendConst struct {
	Expr      ast.Expr
	Namespace string
	Iota      int64
}

type frontendReader struct {
	Root      string
	Fset      *token.FileSet
	Files     map[string]*ast.File
	Proofs    map[string]string
	Constants map[string]frontendConst
	Resolving map[string]bool
}

func (r *frontendReader) read(relative string, namespace string) (*ast.File, error) {
	if file := r.Files[relative]; file != nil {
		return file, nil
	}
	data, err := os.ReadFile(filepath.Join(r.Root, filepath.FromSlash(relative)))
	if err != nil {
		return nil, err
	}
	file, err := parser.ParseFile(r.Fset, relative, data, 0)
	if err != nil {
		return nil, err
	}
	expectedPackage := namespace
	if namespace == "asm" {
		expectedPackage = "arch"
	} else if namespace == "asmparser" {
		expectedPackage = "asm"
	}
	if file.Name.Name != expectedPackage {
		return nil, fmt.Errorf("unexpected source package %s in %s", file.Name.Name, relative)
	}
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			return nil, err
		}
		name := filepath.Base(path)
		if imported.Name != nil {
			name = imported.Name.Name
		}
		if name == "obj" || name == "x86" || name == "arm" || name == "arm64" || name == "wasm" {
			expectedPath := "cmd/internal/obj"
			if name != "obj" {
				expectedPath += "/" + name
			}
			if path != expectedPath {
				return nil, fmt.Errorf("opcode namespace %s has unexpected import %s", name, path)
			}
		}
	}
	r.Files[relative] = file
	r.Proofs[relative] = fmt.Sprintf("%x", sha256.Sum256(data))
	for _, decl := range file.Decls {
		group, ok := decl.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		var previous []ast.Expr
		for index, spec := range group.Specs {
			value := spec.(*ast.ValueSpec)
			if len(value.Values) != 0 {
				previous = value.Values
			}
			for n, name := range value.Names {
				if name.Name == "_" {
					continue
				}
				if n >= len(previous) {
					return nil, fmt.Errorf("unsupported constant declaration %s:%s", relative, name.Name)
				}
				key := namespace + "." + name.Name
				if _, duplicate := r.Constants[key]; duplicate {
					return nil, fmt.Errorf("duplicate constant %s", key)
				}
				r.Constants[key] = frontendConst{previous[n], namespace, int64(index)}
			}
		}
	}
	return file, nil
}

func (r *frontendReader) integer(expr ast.Expr, namespace string, iotaValue int64) (int64, error) {
	value, err := r.eval(expr, namespace, iotaValue)
	if err != nil {
		return 0, err
	}
	number, ok := constant.Int64Val(constant.ToInt(value))
	if !ok {
		return 0, fmt.Errorf("constant %s is not an int64", exprText(expr))
	}
	return number, nil
}

func (r *frontendReader) eval(expr ast.Expr, namespace string, iotaValue int64) (constant.Value, error) {
	var key string
	switch value := expr.(type) {
	case *ast.BasicLit:
		if value.Kind != token.INT {
			break
		}
		parsed := constant.MakeFromLiteral(value.Value, token.INT, 0)
		if parsed.Kind() != constant.Unknown {
			return parsed, nil
		}
	case *ast.Ident:
		if value.Name == "iota" {
			return constant.MakeInt64(iotaValue), nil
		}
		if value.Obj != nil && value.Obj.Kind != ast.Con {
			break
		}
		key = namespace + "." + value.Name
	case *ast.SelectorExpr:
		if base, ok := value.X.(*ast.Ident); ok && (base.Obj == nil || base.Obj.Kind == ast.Pkg) {
			key = base.Name + "." + value.Sel.Name
		}
	case *ast.ParenExpr:
		return r.eval(value.X, namespace, iotaValue)
	case *ast.UnaryExpr:
		operand, err := r.eval(value.X, namespace, iotaValue)
		if err != nil {
			return nil, err
		}
		if value.Op == token.ADD || value.Op == token.SUB || value.Op == token.XOR {
			return constant.UnaryOp(value.Op, operand, 0), nil
		}
	case *ast.BinaryExpr:
		left, err := r.eval(value.X, namespace, iotaValue)
		if err != nil {
			return nil, err
		}
		right, err := r.eval(value.Y, namespace, iotaValue)
		if err != nil {
			return nil, err
		}
		if value.Op == token.SHL || value.Op == token.SHR {
			shift, ok := constant.Uint64Val(right)
			if !ok || shift > 63 {
				return nil, fmt.Errorf("invalid constant shift %s", exprText(expr))
			}
			return constant.Shift(left, value.Op, uint(shift)), nil
		}
		switch value.Op {
		case token.ADD, token.SUB, token.MUL, token.AND, token.OR, token.XOR, token.AND_NOT:
			return constant.BinaryOp(left, value.Op, right), nil
		}
	}
	if key != "" {
		definition, ok := r.Constants[key]
		if !ok || r.Resolving[key] {
			return nil, fmt.Errorf("unknown/cyclic opcode constant %s", key)
		}
		r.Resolving[key] = true
		defer delete(r.Resolving, key)
		return r.eval(definition.Expr, definition.Namespace, definition.Iota)
	}
	return nil, fmt.Errorf("unsupported opcode constant expression %s", exprText(expr))
}

type frontendTableEntry struct {
	Name     string
	Position token.Pos
}

func (r *frontendReader) table(file *ast.File, name, namespace string) ([]frontendTableEntry, bool, error) {
	var result []frontendTableEntry
	found := false
	for _, decl := range file.Decls {
		group, ok := decl.(*ast.GenDecl)
		if !ok || group.Tok != token.VAR {
			continue
		}
		for _, spec := range group.Specs {
			value := spec.(*ast.ValueSpec)
			for n, ident := range value.Names {
				if ident.Name != name {
					continue
				}
				if found || n >= len(value.Values) {
					return nil, false, fmt.Errorf("duplicate/missing initializer for %s", name)
				}
				found = true
				literal, ok := value.Values[n].(*ast.CompositeLit)
				if !ok {
					return nil, false, fmt.Errorf("%s is not a literal array", name)
				}
				if _, err := opcodeStringArray(literal); err != nil {
					return nil, false, err
				}
				next := int64(0)
				for _, element := range literal.Elts {
					if keyed, ok := element.(*ast.KeyValueExpr); ok {
						var err error
						next, err = r.integer(keyed.Key, namespace, 0)
						if err != nil {
							return nil, false, err
						}
						element = keyed.Value
					}
					if next < 0 || next > 32767 {
						return nil, false, fmt.Errorf("invalid %s array index %d", name, next)
					}
					for int64(len(result)) <= next {
						result = append(result, frontendTableEntry{})
					}
					if result[next].Position.IsValid() {
						return nil, false, fmt.Errorf("duplicate %s array index %d", name, next)
					}
					text := element.(*ast.BasicLit)
					spelling, err := strconv.Unquote(text.Value)
					if err != nil {
						return nil, false, err
					}
					result[next] = frontendTableEntry{spelling, text.Pos()}
					next++
				}
			}
		}
	}
	return result, found, nil
}

func frontendSentinel(spelling string) bool {
	upper := strings.ToUpper(spelling)
	return upper == "XXX" || upper == "LAST" || upper == "SVESTART" || strings.HasPrefix(upper, "RESERVED")
}

func (r *frontendReader) origin(role string, position token.Pos) frontendOrigin {
	location := r.Fset.Position(position)
	return frontendOrigin{role, filepath.ToSlash(location.Filename), location.Line}
}

func frontendNodeText(node ast.Node) string {
	var text strings.Builder
	if err := printer.Fprint(&text, token.NewFileSet(), node); err != nil {
		return ""
	}
	return strings.Join(strings.Fields(text.String()), " ")
}

func loadFrontendInventory(goroot, goarch string) (*frontendInventory, error) {
	dir, base, constructor := goarch, "ARM", "archArm"
	switch goarch {
	case "386", "amd64":
		dir, base, constructor = "x86", "AMD64", "archX86"
	case "arm":
	case "arm64":
		base, constructor = "ARM64", "archArm64"
	case "wasm":
		base, constructor = "Wasm", "archWasm"
	default:
		return nil, fmt.Errorf("unsupported frontend architecture %q", goarch)
	}
	r := &frontendReader{
		Root:      goroot,
		Fset:      token.NewFileSet(),
		Files:     map[string]*ast.File{},
		Proofs:    map[string]string{},
		Constants: map[string]frontendConst{},
		Resolving: map[string]bool{},
	}
	enumFile := "a.out.go"
	if dir == "x86" {
		enumFile = "aenum.go"
	}
	sources := []struct{ path, namespace string }{
		{"src/cmd/internal/obj/link.go", "obj"},
		{"src/cmd/internal/obj/" + dir + "/" + enumFile, dir},
		{"src/cmd/asm/internal/arch/arch.go", "asm"},
	}
	for _, source := range sources {
		if _, err := r.read(source.path, source.namespace); err != nil {
			return nil, err
		}
	}
	if goarch == "arm" {
		if _, err := r.read("src/cmd/asm/internal/arch/arm.go", "asm"); err != nil {
			return nil, err
		}
	}
	commonFile, err := r.read("src/cmd/internal/obj/util.go", "obj")
	if err != nil {
		return nil, err
	}
	common, found, err := r.table(commonFile, "Anames", "obj")
	if err != nil || !found || len(common) == 0 {
		return nil, fmt.Errorf("missing/invalid obj.Anames: %v", err)
	}
	minimum, err := r.integer(&ast.Ident{Name: "A_ARCHSPECIFIC"}, "obj", 0)
	if err != nil {
		return nil, err
	}
	archBase, err := r.integer(&ast.Ident{Name: "ABase" + base}, "obj", 0)
	if err != nil {
		return nil, err
	}
	paths, err := filepath.Glob(filepath.Join(goroot, "src/cmd/internal/obj", dir, "anames*.go"))
	if err != nil {
		return nil, err
	}
	var archNames, sveNames []frontendTableEntry
	baseFound, sveFound, appendCount := false, false, 0
	for _, path := range paths {
		relative, err := filepath.Rel(goroot, path)
		if err != nil {
			return nil, err
		}
		file, err := r.read(filepath.ToSlash(relative), dir)
		if err != nil {
			return nil, err
		}
		for _, name := range []string{"Anames", "sveAnames"} {
			if name == "sveAnames" && goarch != "arm64" {
				continue
			}
			table, found, err := r.table(file, name, dir)
			if err != nil {
				return nil, err
			}
			if !found {
				continue
			}
			if name == "Anames" {
				if baseFound {
					return nil, fmt.Errorf("duplicate arch.Anames")
				}
				baseFound = true
				archNames = table
			} else {
				if sveFound {
					return nil, fmt.Errorf("duplicate sveAnames")
				}
				sveFound = true
				sveNames = table
			}
		}
		if goarch == "arm64" && appendsSVEOpcodeNames(file) {
			appendCount++
		}
	}
	if !baseFound || len(archNames) <= int(minimum) || (sveFound && appendCount != 1) || (!sveFound && appendCount != 0) {
		return nil, fmt.Errorf("missing/unregistered architecture opcode arrays")
	}
	if err := r.verifyArrayUses("src/cmd/internal/obj", "obj", "", false); err != nil {
		return nil, err
	}
	if err := r.verifyArrayUses("src/cmd/internal/obj/"+dir, dir, base, sveFound); err != nil {
		return nil, err
	}
	archNames = append(archNames, sveNames...)
	entries := map[string]*frontendName{}
	canonical := map[int64]frontendName{}
	addTable := func(table []frontendTableEntry, start, offset int64, namespace, role string) error {
		for index := start; index < int64(len(table)); index++ {
			item := table[index]
			if item.Name == "" {
				return fmt.Errorf("unregistered empty %s namespace slot %d", namespace, index)
			}
			id := index + offset
			if id < 0 || id > 32767 {
				return fmt.Errorf("obj.As overflow %d", id)
			}
			if entries[item.Name] != nil {
				return fmt.Errorf("duplicate registered spelling %s", item.Name)
			}
			entry := &frontendName{Spelling: item.Name, AsID: &id, Canonical: item.Name, CanonicalNamespace: namespace, Sentinel: frontendSentinel(item.Name), Origins: []frontendOrigin{r.origin(role, item.Position)}}
			if entry.Sentinel {
				entry.Origins = append(entry.Origins, r.origin("sentinel", item.Position))
			}
			entries[item.Name] = entry
			canonical[id] = *entry
		}
		return nil
	}
	if err := addTable(common, 0, 0, "obj", "common"); err != nil {
		return nil, err
	}
	if err := addTable(archNames, minimum, archBase, dir, "arch"); err != nil {
		return nil, err
	}
	file := r.Files["src/cmd/asm/internal/arch/arch.go"]
	if err := validateFrontendDispatch(file, goarch, constructor); err != nil {
		return nil, err
	}
	if err := r.constructor(file, constructor, dir, base, goarch, entries, canonical); err != nil {
		return nil, err
	}
	if err := r.pseudos(entries); err != nil {
		return nil, err
	}
	inventory := &frontendInventory{SchemaVersion: 1, Scope: "go_assembler_frontend_source_registration"}
	for _, entry := range entries {
		inventory.Entries = append(inventory.Entries, *entry)
	}
	sort.Slice(inventory.Entries, func(i, j int) bool { return inventory.Entries[i].Spelling < inventory.Entries[j].Spelling })
	for path, hash := range r.Proofs {
		inventory.Sources = append(inventory.Sources, frontendSourceProof{path, hash})
	}
	sort.Slice(inventory.Sources, func(i, j int) bool { return inventory.Sources[i].Source < inventory.Sources[j].Source })
	return inventory, nil
}

func validateFrontendDispatch(file *ast.File, goarch, constructor string) error {
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if candidate, ok := decl.(*ast.FuncDecl); ok && candidate.Name.Name == "Set" {
			if fn != nil {
				return fmt.Errorf("duplicate arch.Set")
			}
			fn = candidate
		}
	}
	if fn == nil || fn.Body == nil || len(fn.Body.List) != 2 || frontendNodeText(fn.Body.List[1]) != "return nil" {
		return fmt.Errorf("missing/unknown arch.Set dispatch")
	}
	selection, ok := fn.Body.List[0].(*ast.SwitchStmt)
	if !ok || selection.Init != nil || exprText(selection.Tag) != "GOARCH" {
		return fmt.Errorf("unknown arch.Set selector")
	}
	expected := constructor + "()"
	if goarch == "386" || goarch == "amd64" {
		expected = constructor + "(&x86.Link" + goarch + ")"
	}
	found := 0
	for _, statement := range selection.Body.List {
		clause, ok := statement.(*ast.CaseClause)
		if !ok {
			return fmt.Errorf("unknown arch.Set branch")
		}
		for _, label := range clause.List {
			literal, ok := label.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return fmt.Errorf("dynamic arch.Set label")
			}
			name, err := strconv.Unquote(literal.Value)
			if err != nil {
				return err
			}
			if name != goarch {
				continue
			}
			if len(clause.List) != 1 || len(clause.Body) != 1 || frontendNodeText(clause.Body[0]) != "return "+expected {
				return fmt.Errorf("unrecognized %s frontend constructor dispatch", goarch)
			}
			found++
		}
	}
	if found != 1 {
		return fmt.Errorf("missing/duplicate %s frontend dispatch", goarch)
	}
	return nil
}

func (r *frontendReader) constructor(file *ast.File, name, dir, base, goarch string, entries map[string]*frontendName, canonical map[int64]frontendName) error {
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if candidate, ok := decl.(*ast.FuncDecl); ok && candidate.Name.Name == name {
			if fn != nil {
				return fmt.Errorf("duplicate constructor %s", name)
			}
			fn = candidate
		}
	}
	if fn == nil || fn.Body == nil {
		return fmt.Errorf("missing constructor %s", name)
	}
	allowed := map[token.Pos]bool{}
	aliasNames := map[string]bool{}
	initialized, common, arch, returned := 0, 0, 0, 0
	allow := func(node ast.Node) {
		ast.Inspect(node, func(node ast.Node) bool {
			if ident, ok := node.(*ast.Ident); ok && ident.Name == "instructions" {
				allowed[ident.Pos()] = true
			}
			return true
		})
	}
	for _, stmt := range fn.Body.List {
		switch value := stmt.(type) {
		case *ast.AssignStmt:
			if len(value.Lhs) != 1 || len(value.Rhs) != 1 {
				continue
			}
			if ident, ok := value.Lhs[0].(*ast.Ident); ok && ident.Name == "instructions" {
				if initialized != 0 || common != 0 || arch != 0 || returned != 0 {
					return fmt.Errorf("out-of-order instruction map initialization")
				}
				if value.Tok != token.DEFINE || exprText(value.Rhs[0]) != "make(map[string]obj.As)" {
					return fmt.Errorf("unknown instruction map initialization")
				}
				initialized++
				allow(value)
				continue
			}
			index, ok := value.Lhs[0].(*ast.IndexExpr)
			if !ok || exprText(index.X) != "instructions" {
				continue
			}
			if arch != 1 || returned != 0 {
				return fmt.Errorf("instruction alias outside post-registration phase")
			}
			key, ok := index.Index.(*ast.BasicLit)
			if !ok || key.Kind != token.STRING || value.Tok != token.ASSIGN {
				return fmt.Errorf("dynamic instruction alias")
			}
			spelling, err := strconv.Unquote(key.Value)
			if err != nil {
				return err
			}
			if spelling == "" || aliasNames[spelling] {
				return fmt.Errorf("empty/duplicate explicit alias %q", spelling)
			}
			aliasNames[spelling] = true
			_, selector := value.Rhs[0].(*ast.SelectorExpr)
			if !selector && !(goarch == "arm" && exprText(value.Rhs[0]) == "aMCR") {
				return fmt.Errorf("unrecognized alias binding %s", exprText(value.Rhs[0]))
			}
			id, err := r.integer(value.Rhs[0], "asm", 0)
			if err != nil {
				return err
			}
			binding, found := canonical[id]
			if !found && goarch == "arm" && exprText(value.Rhs[0]) == "aMCR" {
				last, err := r.integer(&ast.SelectorExpr{X: &ast.Ident{Name: "arm"}, Sel: &ast.Ident{Name: "ALAST"}}, "asm", 0)
				if err != nil || id != last+1 {
					return fmt.Errorf("invalid private ARM MCR mapping")
				}
				binding = frontendName{Canonical: "MCR", CanonicalNamespace: "asm"}
				found = true
			}
			if !found {
				return fmt.Errorf("alias %s targets unregistered obj.As %d", spelling, id)
			}
			entry := entries[spelling]
			if entry == nil {
				entry = &frontendName{Spelling: spelling}
				entries[spelling] = entry
			}
			entry.AsID = &id
			entry.Canonical = binding.Canonical
			entry.CanonicalNamespace = binding.CanonicalNamespace
			entry.Sentinel = binding.Sentinel
			entry.Origins = append(entry.Origins, r.origin("alias", key.Pos()))
			if entry.Sentinel {
				entry.Origins = append(entry.Origins, r.origin("sentinel", key.Pos()))
			}
			allow(value)
		case *ast.RangeStmt:
			if exprText(value.X) != "obj.Anames" && exprText(value.X) != dir+".Anames" {
				continue
			}
			if value.Tok != token.DEFINE || exprText(value.Key) != "i" || exprText(value.Value) != "s" || len(value.Body.List) != 1 {
				return fmt.Errorf("unknown opcode registration range")
			}
			assignment := value.Body.List[0]
			if exprText(value.X) == "obj.Anames" {
				if initialized != 1 || common != 0 || arch != 0 || returned != 0 {
					return fmt.Errorf("out-of-order common opcode registration")
				}
				if frontendNodeText(assignment) != "instructions[s] = obj.As(i)" {
					return fmt.Errorf("unknown common opcode registration")
				}
				common++
			} else {
				if initialized != 1 || common != 1 || arch != 0 || returned != 0 {
					return fmt.Errorf("out-of-order arch opcode registration")
				}
				guard, ok := assignment.(*ast.IfStmt)
				if !ok || guard.Init != nil || guard.Else != nil || exprText(guard.Cond) != "obj.As(i) >= obj.A_ARCHSPECIFIC" || len(guard.Body.List) != 1 || frontendNodeText(guard.Body.List[0]) != "instructions[s] = obj.As(i) + obj.ABase"+base {
					return fmt.Errorf("unknown arch opcode registration")
				}
				arch++
			}
			allow(value)
		case *ast.ReturnStmt:
			if initialized != 1 || common != 1 || arch != 1 || returned != 0 {
				return fmt.Errorf("return outside completed registration phase")
			}
			ast.Inspect(value, func(node ast.Node) bool {
				if pair, ok := node.(*ast.KeyValueExpr); ok && exprText(pair.Key) == "Instructions" && exprText(pair.Value) == "instructions" {
					returned++
					allow(pair.Value)
				}
				return true
			})
		}
	}
	if initialized != 1 || common != 1 || arch != 1 || returned != 1 {
		return fmt.Errorf("incomplete constructor registration: map=%d common=%d arch=%d result=%d", initialized, common, arch, returned)
	}
	var unknown token.Pos
	var shadowedNamespace token.Pos
	returnStatements := 0
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if _, ok := node.(*ast.ReturnStmt); ok {
			returnStatements++
		}
		if ident, ok := node.(*ast.Ident); ok && ident.Name == "instructions" && !allowed[ident.Pos()] {
			unknown = ident.Pos()
		}
		if selector, ok := node.(*ast.SelectorExpr); ok {
			if ident, ok := selector.X.(*ast.Ident); ok && (ident.Name == "obj" || ident.Name == dir) && ident.Obj != nil && ident.Obj.Kind != ast.Pkg {
				shadowedNamespace = ident.Pos()
			}
		}
		return true
	})
	if returnStatements != 1 {
		return fmt.Errorf("unrecognized constructor return flow")
	}
	if shadowedNamespace.IsValid() {
		return fmt.Errorf("shadowed opcode namespace at %s", r.Fset.Position(shadowedNamespace))
	}
	if unknown.IsValid() {
		return fmt.Errorf("unrecognized instruction map use at %s", r.Fset.Position(unknown))
	}
	return nil
}

func (r *frontendReader) pseudos(entries map[string]*frontendName) error {
	file, err := r.read("src/cmd/asm/internal/asm/parse.go", "asmparser")
	if err != nil {
		return err
	}
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if candidate, ok := decl.(*ast.FuncDecl); ok && candidate.Name.Name == "pseudo" {
			if fn != nil {
				return fmt.Errorf("duplicate Parser.pseudo")
			}
			fn = candidate
		}
	}
	if fn == nil || fn.Body == nil || len(fn.Body.List) != 2 {
		return fmt.Errorf("missing/unknown Parser.pseudo")
	}
	selection, ok := fn.Body.List[0].(*ast.SwitchStmt)
	if !ok || selection.Init != nil || exprText(selection.Tag) != "word" || frontendNodeText(fn.Body.List[1]) != "return true" {
		return fmt.Errorf("unknown Parser.pseudo dispatch")
	}
	seen := map[string]bool{}
	defaults := 0
	for _, stmt := range selection.Body.List {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok || len(clause.Body) != 1 {
			return fmt.Errorf("unknown pseudo case")
		}
		if len(clause.List) == 0 {
			defaults++
			if frontendNodeText(clause.Body[0]) != "return false" {
				return fmt.Errorf("unknown pseudo default")
			}
			continue
		}
		if len(clause.List) != 1 {
			return fmt.Errorf("unknown grouped pseudo case")
		}
		literal, ok := clause.List[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return fmt.Errorf("dynamic pseudo name")
		}
		spelling, err := strconv.Unquote(literal.Value)
		if err != nil {
			return err
		}
		if seen[spelling] {
			return fmt.Errorf("duplicate pseudo %s", spelling)
		}
		seen[spelling] = true
		handler := map[string]string{"DATA": "asmData", "FUNCDATA": "asmFuncData", "GLOBL": "asmGlobl", "PCDATA": "asmPCData", "PCALIGN": "asmPCAlign", "TEXT": "asmText"}[spelling]
		if handler == "" || frontendNodeText(clause.Body[0]) != "p."+handler+"(operands)" {
			return fmt.Errorf("unrecognized pseudo handler %s", spelling)
		}
		entry := entries[spelling]
		if entry == nil {
			entry = &frontendName{Spelling: spelling, Canonical: spelling, CanonicalNamespace: "pseudo"}
			entries[spelling] = entry
		}
		entry.Origins = append(entry.Origins, r.origin("pseudo", literal.Pos()))
	}
	if len(seen) != 6 || defaults != 1 {
		return fmt.Errorf("incomplete required parser pseudo family")
	}
	return nil
}

// Opcode tables are literal initializers with one recognized ARM64 append.
// Inspect every production file in the selected package, not just anames*.go,
// so an additional mutation or escaped slice cannot silently change the map.
func (r *frontendReader) verifyArrayUses(directory, namespace, base string, sve bool) error {
	paths, err := filepath.Glob(filepath.Join(r.Root, filepath.FromSlash(directory), "*.go"))
	if err != nil {
		return err
	}
	declarations := map[string]int{}
	appends := 0
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		relative, err := filepath.Rel(r.Root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		file := r.Files[relative]
		if file == nil {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			file, err = parser.ParseFile(r.Fset, relative, data, 0)
			if err != nil {
				return err
			}
			if file.Name.Name != namespace {
				continue
			}
			r.Files[relative] = file
			r.Proofs[relative] = fmt.Sprintf("%x", sha256.Sum256(data))
		}
		parents := map[ast.Node]ast.Node{}
		var stack []ast.Node
		ast.Inspect(file, func(node ast.Node) bool {
			if node == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			if len(stack) > 0 {
				parents[node] = stack[len(stack)-1]
			}
			stack = append(stack, node)
			return true
		})
		allowed := map[token.Pos]bool{}
		for _, decl := range file.Decls {
			group, ok := decl.(*ast.GenDecl)
			if !ok || group.Tok != token.VAR {
				continue
			}
			for _, spec := range group.Specs {
				for _, name := range spec.(*ast.ValueSpec).Names {
					if name.Name == "Anames" || (sve && name.Name == "sveAnames") {
						declarations[name.Name]++
						allowed[name.Pos()] = true
					}
				}
			}
		}
		if sve {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name.Name != "init" || fn.Body == nil {
					continue
				}
				for _, stmt := range fn.Body.List {
					assign, ok := stmt.(*ast.AssignStmt)
					if !ok || frontendNodeText(assign) != "Anames = append(Anames, sveAnames...)" {
						continue
					}
					appends++
					ast.Inspect(assign, func(node ast.Node) bool {
						if ident, ok := node.(*ast.Ident); ok {
							allowed[ident.Pos()] = true
						}
						return true
					})
				}
			}
		}
		var invalid token.Pos
		ast.Inspect(file, func(node ast.Node) bool {
			ident, ok := node.(*ast.Ident)
			if !ok || (ident.Name != "Anames" && !(sve && ident.Name == "sveAnames")) || allowed[ident.Pos()] {
				return true
			}
			if ident.Obj != nil {
				declaration, ok := ident.Obj.Decl.(ast.Node)
				if ok {
					group, global := parents[declaration].(*ast.GenDecl)
					if !global || parents[group] != file {
						return true
					} // Local shadow or parameter.
				}
			}
			parent := parents[ident]
			if index, ok := parent.(*ast.IndexExpr); ok && index.X == ident {
				grandparent := parents[index]
				if assignment, ok := grandparent.(*ast.AssignStmt); ok {
					for _, left := range assignment.Lhs {
						if left == index {
							invalid = ident.Pos()
							return true
						}
					}
				}
				if unary, ok := grandparent.(*ast.UnaryExpr); ok && unary.Op == token.AND {
					invalid = ident.Pos()
					return true
				}
				return true // Reading a string element cannot mutate the table.
			}
			if call, ok := parent.(*ast.CallExpr); ok {
				if exprText(call.Fun) == "len" && len(call.Args) == 1 {
					return true
				}
				if base != "" && exprText(call) == "obj.RegisterOpcode(obj.ABase"+base+", Anames)" {
					return true
				}
			}
			invalid = ident.Pos()
			return true
		})
		if invalid.IsValid() {
			return fmt.Errorf("unrecognized opcode array use at %s", r.Fset.Position(invalid))
		}
	}
	if declarations["Anames"] != 1 || (sve && (declarations["sveAnames"] != 1 || appends != 1)) {
		return fmt.Errorf("incomplete literal opcode array registration")
	}
	return nil
}
