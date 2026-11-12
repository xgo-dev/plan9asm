package gotoolprofile

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm"
)

// This is a closed declaration/type/constant replay over the independently
// supplied original compiled source, not a type parsed from metadata strings.
// Original AST nodes, including complete const groups and iota positions, are
// retained. No Go arguments or return slots are invented from assembly.
// Imported selectors additionally require the independently captured original
// type-source input; paired metadata alone cannot supply that authority.
type instrumentationDeclarationReplay struct {
	files     []*ast.File
	functions map[string]*ast.FuncDecl
	types     map[string]*ast.TypeSpec
	constants map[string]*ast.GenDecl
	other     map[string]bool
	needed    map[ast.Node]bool
	selector  func(*ast.SelectorExpr) error
}

func replayInstrumentationDeclarationLayouts(input *InstrumentationConsumerInput, pkg PackageProof, declarations []InstrumentationDeclarationProof) error {
	set := token.NewFileSet()
	replay := &instrumentationDeclarationReplay{
		functions: make(map[string]*ast.FuncDecl), types: make(map[string]*ast.TypeSpec),
		constants: make(map[string]*ast.GenDecl), other: make(map[string]bool),
		needed: make(map[ast.Node]bool),
	}
	for _, name := range pkg.CompiledGoFiles {
		file, err := parser.ParseFile(set, name, input.Sources.Contents[name], 0)
		if err != nil || file.Name.Name != input.Plan.PackageName {
			return fmt.Errorf("actual compiled Go declaration source changed: %v", err)
		}
		replay.files = append(replay.files, file)
		if err := replay.index(file); err != nil {
			return err
		}
	}
	imports, err := newInstrumentationTypeReplay(input, set, replay)
	if err != nil {
		return err
	}
	for _, declaration := range declarations {
		name := strings.TrimPrefix(declaration.Symbol, pkg.PackagePath+".")
		function := replay.functions[name]
		if function == nil || function.Body != nil || function.Recv != nil {
			return fmt.Errorf("actual compiled bodyless declaration disappeared")
		}
		replay.needed[function] = true
		if err := replay.requireType(function.Type); err != nil {
			return err
		}
	}
	if len(declarations) == 0 {
		return nil
	}
	selected := replay.selectedFiles()
	_, arch, _ := strings.Cut(input.Plan.Target, "/")
	sizes := types.SizesFor("gc", arch)
	if sizes == nil {
		return fmt.Errorf("actual target has no Go gc declaration layout")
	}
	minor, err := goMinor(input.Observation.Early.BaselineFeatures.GoVersion)
	if err != nil {
		return err
	}
	// Config.GoVersion is a language version. Go 1.20 panics for a patch
	// release string; the exact driver patch remains independently observed.
	config := &types.Config{Sizes: sizes, IgnoreFuncBodies: true, GoVersion: fmt.Sprintf("go1.%d", minor)}
	if imports != nil {
		config.Importer = instrumentationTypeImporter{graph: imports, importMap: imports.proof.RootImportMap}
	}
	typed, err := config.Check(pkg.PackagePath, set, selected, nil)
	if err != nil {
		return fmt.Errorf("original Go declaration type/constant closure is not independently closed: %w", err)
	}
	for _, declaration := range declarations {
		name := strings.TrimPrefix(declaration.Symbol, pkg.PackagePath+".")
		function, ok := typed.Scope().Lookup(name).(*types.Func)
		if !ok {
			return fmt.Errorf("actual original Go function type disappeared")
		}
		signature := function.Type().(*types.Signature)
		for i := 0; i < signature.Params().Len(); i++ {
			if sizes.Sizeof(signature.Params().At(i).Type()) == 0 {
				return fmt.Errorf("mode ABI0 replay has an unclosed root/CLI two-builder zero-sized parameter difference: %s", declaration.Symbol)
			}
		}
		if err := boundInstrumentationABI0Layout(signature); err != nil {
			return err
		}
		actualType := types.TypeString(function.Type(), func(pkg *types.Package) string { return pkg.Path() })
		layout, err := plan9asm.DeriveGoFuncABI0Signature(declaration.Symbol, function, arch, sizes)
		if err != nil {
			return err
		}
		var claimed plan9asm.FuncSig
		if err := decodeInstrumentationOriginalJSON(strings.NewReader(string(declaration.Layout)), 1<<20, &claimed); err != nil {
			return err
		}
		// The producer serializes a public layout observation. Independently
		// derived signatures may also hold private live declaration inputs,
		// which JSON cannot recreate and metadata must never authorize. Compare
		// exactly the same public fields; retain the actual source/type replay.
		encoded, err := json.Marshal(layout)
		if err != nil {
			return err
		}
		var observed plan9asm.FuncSig
		if err := decodeInstrumentationOriginalJSON(strings.NewReader(string(encoded)), 1<<20, &observed); err != nil {
			return err
		}
		if declaration.GoType != actualType || !reflect.DeepEqual(claimed, observed) {
			return fmt.Errorf("mode Go type/complete ABI0 layout differs from independent original AST replay: %s", declaration.Symbol)
		}
	}
	return nil
}

func (replay *instrumentationDeclarationReplay) selectedFiles() []*ast.File {
	var selected []*ast.File
	for _, original := range replay.files {
		copy := *original
		copy.Decls, copy.Imports = nil, nil
		for _, declaration := range original.Decls {
			if replay.needed[declaration] {
				copy.Decls = append(copy.Decls, declaration)
				continue
			}
			group, ok := declaration.(*ast.GenDecl)
			if !ok || group.Tok != token.TYPE && group.Tok != token.IMPORT {
				continue
			}
			filtered := *group
			filtered.Specs = nil
			for _, spec := range group.Specs {
				if replay.needed[spec] {
					filtered.Specs = append(filtered.Specs, spec)
					if imported, ok := spec.(*ast.ImportSpec); ok {
						copy.Imports = append(copy.Imports, imported)
					}
				}
			}
			if len(filtered.Specs) != 0 {
				copy.Decls = append(copy.Decls, &filtered)
			}
		}
		selected = append(selected, &copy)
	}
	return selected
}

// Bound aggregate expansion before the shared ABI0 builder allocates slots.
// Source bytes alone do not bound a constant array's declared length.
func boundInstrumentationABI0Layout(signature *types.Signature) error {
	var count func(types.Type, int) (int64, error)
	count = func(typ types.Type, depth int) (int64, error) {
		if depth > 128 {
			return 0, fmt.Errorf("original ABI0 type exceeds its nesting bound")
		}
		switch typ := typ.Underlying().(type) {
		case *types.Array:
			if typ.Len() > 4096 {
				return 0, fmt.Errorf("original ABI0 array exceeds its slot bound")
			}
			child, err := count(typ.Elem(), depth+1)
			if err != nil || child*typ.Len() > 4096 {
				return 0, fmt.Errorf("original ABI0 array expansion exceeds its slot bound: %v", err)
			}
			if typ.Len() == 0 {
				return 1, nil
			}
			return child * typ.Len(), nil
		case *types.Struct:
			if typ.NumFields() > 4096 {
				return 0, fmt.Errorf("original ABI0 struct exceeds its field bound")
			}
			var total int64
			for i := 0; i < typ.NumFields(); i++ {
				child, err := count(typ.Field(i).Type(), depth+1)
				if err != nil {
					return 0, err
				}
				total += child
				if total > 4096 {
					return 0, fmt.Errorf("original ABI0 struct expansion exceeds its slot bound")
				}
			}
			if total == 0 {
				return 1, nil
			}
			return total, nil
		case *types.Slice:
			return 3, nil
		case *types.Interface:
			return 2, nil
		case *types.Basic:
			if typ.Kind() == types.String || typ.Kind() == types.Complex64 || typ.Kind() == types.Complex128 {
				return 2, nil
			}
		}
		return 1, nil
	}
	var total int64
	for _, tuple := range []*types.Tuple{signature.Params(), signature.Results()} {
		for i := 0; i < tuple.Len(); i++ {
			parts, err := count(tuple.At(i).Type(), 0)
			if err != nil {
				return err
			}
			total += parts
			if total > 4096 {
				return fmt.Errorf("original ABI0 signature exceeds its total slot bound")
			}
		}
	}
	return nil
}

func (replay *instrumentationDeclarationReplay) index(file *ast.File) error {
	register := func(name string) error {
		if name == "_" {
			return nil
		}
		if replay.functions[name] != nil || replay.types[name] != nil || replay.constants[name] != nil || replay.other[name] {
			return fmt.Errorf("original Go declaration has a duplicate package name")
		}
		if len(replay.functions)+len(replay.types)+len(replay.constants)+len(replay.other) >= 32768 {
			return fmt.Errorf("original Go declaration replay exceeds its name bound")
		}
		return nil
	}
	for _, declaration := range file.Decls {
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			if declaration.Recv != nil || declaration.Name.Name == "init" {
				continue
			}
			if err := register(declaration.Name.Name); err != nil {
				return err
			}
			replay.functions[declaration.Name.Name] = declaration
		case *ast.GenDecl:
			for _, spec := range declaration.Specs {
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					if spec.Name.Name == "_" {
						continue
					}
					if err := register(spec.Name.Name); err != nil {
						return err
					}
					replay.types[spec.Name.Name] = spec
				case *ast.ValueSpec:
					for _, name := range spec.Names {
						if err := register(name.Name); err != nil {
							return err
						}
						if name.Name == "_" {
							continue
						}
						if declaration.Tok == token.CONST {
							replay.constants[name.Name] = declaration
						} else {
							replay.other[name.Name] = true
						}
					}
				}
			}
		}
	}
	return nil
}

func (replay *instrumentationDeclarationReplay) requireName(name string) error {
	if declaration := replay.types[name]; declaration != nil {
		if replay.needed[declaration] {
			return nil
		}
		if len(replay.needed) >= 4096 || declaration.TypeParams != nil && len(declaration.TypeParams.List) != 0 {
			return fmt.Errorf("original declaration needs an unclosed generic type or exceeds its bound")
		}
		replay.needed[declaration] = true // recursive pointer types are checked by go/types.
		return replay.requireType(declaration.Type)
	}
	if declaration := replay.constants[name]; declaration != nil {
		if replay.needed[declaration] {
			return nil
		}
		if len(replay.needed) >= 4096 {
			return fmt.Errorf("original constant replay exceeds its declaration bound")
		}
		replay.needed[declaration] = true
		for _, spec := range declaration.Specs {
			value := spec.(*ast.ValueSpec)
			if value.Type != nil {
				if err := replay.requireType(value.Type); err != nil {
					return err
				}
			}
			for _, expression := range value.Values {
				if err := replay.requireExpression(expression); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if replay.other[name] || replay.functions[name] != nil || types.Universe.Lookup(name) == nil {
		return fmt.Errorf("original declaration type/constant has an unclosed name: %s", name)
	}
	return nil
}

func (replay *instrumentationDeclarationReplay) requireExpression(expression ast.Expr) error {
	var failed error
	ast.Inspect(expression, func(node ast.Node) bool {
		if failed != nil {
			return false
		}
		switch node := node.(type) {
		case *ast.SelectorExpr:
			if replay.selector == nil {
				failed = fmt.Errorf("original declaration needs an authenticated imported type/constant closure")
			} else {
				failed = replay.selector(node)
			}
			return false
		case *ast.Ident:
			failed = replay.requireName(node.Name)
		}
		return true
	})
	return failed
}

func (replay *instrumentationDeclarationReplay) requireType(expression ast.Expr) error {
	fieldTypes := func(fields *ast.FieldList) error {
		if fields != nil {
			for _, field := range fields.List {
				if err := replay.requireType(field.Type); err != nil {
					return err
				}
			}
		}
		return nil
	}
	switch expression := expression.(type) {
	case *ast.Ident:
		return replay.requireName(expression.Name)
	case *ast.ParenExpr:
		return replay.requireType(expression.X)
	case *ast.StarExpr:
		return replay.requireType(expression.X)
	case *ast.ArrayType:
		if expression.Len != nil {
			if err := replay.requireExpression(expression.Len); err != nil {
				return err
			}
		}
		return replay.requireType(expression.Elt)
	case *ast.StructType:
		return fieldTypes(expression.Fields)
	case *ast.InterfaceType:
		return fieldTypes(expression.Methods)
	case *ast.FuncType:
		if expression.TypeParams != nil && len(expression.TypeParams.List) != 0 {
			return fmt.Errorf("generic function needs its separate source/type contract")
		}
		if err := fieldTypes(expression.Params); err != nil {
			return err
		}
		return fieldTypes(expression.Results)
	case *ast.MapType:
		if err := replay.requireType(expression.Key); err != nil {
			return err
		}
		return replay.requireType(expression.Value)
	case *ast.ChanType:
		return replay.requireType(expression.Value)
	case *ast.SelectorExpr:
		if replay.selector == nil {
			return fmt.Errorf("original declaration needs an authenticated imported type/constant closure")
		}
		return replay.selector(expression)
	default:
		return fmt.Errorf("original declaration has an unclosed type expression %T", expression)
	}
}
