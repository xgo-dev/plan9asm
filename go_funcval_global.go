package plan9asm

import (
	"go/ast"
	"go/types"
	"reflect"
	"strings"
)

// Positions are immutable original-source ordinals, not a register domain or
// callable ABI. No descriptor byte is added to numerical global spans.
type goFuncvalReadPlan struct {
	fingerprint [32]byte
	reads       map[int]goFuncvalRead
}

type goFuncvalRead struct {
	instruction Instr
	descriptor  bool
}

func goReadOnlyDeclarationLayout(typ types.Type, sizes types.Sizes) (size int64, spans [][2]int64, shape string, err error) {
	signature, function := typ.Underlying().(*types.Signature)
	if !function {
		return goReadOnlyLayout(typ, sizes)
	}
	defer func() {
		if recover() != nil {
			size, spans, shape, err = 0, nil, "", goReadOnlyContext("incomplete function-value target layout")
		}
	}()
	size = sizes.Sizeof(typ)
	if size != sizes.Sizeof(types.Typ[types.Uintptr]) || size != 4 && size != 8 {
		return 0, nil, "", goReadOnlyContext("function value is not one target word")
	}
	qualify := func(pkg *types.Package) string { return pkg.Path() }
	shape = "funcval:" + types.TypeString(typ, qualify) + "/" + types.TypeString(signature, qualify)
	if len(shape) > 64<<10 {
		return 0, nil, "", goReadOnlyContext("function-value type description exceeds its bound")
	}
	return size, nil, shape, nil
}

func (source *goReadOnlyStorage) funcvalGlobalRead(ins Instr, arch string) bool {
	if source == nil {
		return false
	}
	operand, _, candidate := goReadOnlyOperand(ins, arch)
	address, valid := x86StaticSBReadAddress(operand, arch)
	if !candidate || !valid {
		return false
	}
	object := source.object(address.symbol)
	if object.variable == nil || object.imported {
		return false
	}
	_, function := object.variable.Type().Underlying().(*types.Signature)
	return function
}

func (source *goReadOnlyStorage) bindFuncvalReads(file *File, arch string) error {
	if !goFuncvalObjects(source.objects) {
		return nil // Numerical-only declarations need no second instruction scan.
	}
	word := x86ResultPointerWord(arch)
	for _, fn := range file.Funcs {
		wanted := make(map[int]bool)
		for ordinal, ins := range fn.Instrs {
			if source.funcvalGlobalRead(ins, arch) {
				wanted[ordinal] = true
			}
		}
		if len(wanted) == 0 {
			continue
		}
		edges, positions, err := fixedLocalEdges(fn)
		if err != nil {
			return goReadOnlyContext("function-value read needs a closed ordinary source CFG: %v", err)
		}
		predecessors := make([]int, len(positions))
		for _, targets := range edges {
			for _, target := range targets {
				if target >= 0 && target < len(positions) {
					predecessors[target]++
				}
			}
		}
		plan := goFuncvalReadPlan{reads: make(map[int]goFuncvalRead)}
		for pc, ordinal := range positions {
			if !wanted[ordinal] {
				continue
			}
			first := fn.Instrs[ordinal]
			load, valid := x86ScalarStaticLoadProperties(first, arch)
			address, _ := x86StaticSBReadAddress(load.source, arch)
			if !valid || load.extension || load.bytes != word || address.offset != 0 || source.object(address.symbol).size != word ||
				pc+1 >= len(positions) || positions[pc+1] != ordinal+1 || predecessors[pc+1] != 1 ||
				!reflect.DeepEqual(edges[pc], []int{pc + 1}) {
				return goReadOnlyContext("function value requires an exact word/code-word read pair")
			}
			second := fn.Instrs[ordinal+1]
			code, known, err := x86ScalarRegisterLoadProperties(second.Op, second, arch)
			_, _, firstGP := x86ResultGP(load.destination, word, arch)
			_, _, secondGP := x86ResultGP(code.destination, word, arch)
			if !known || err != nil || !x86ResultNamedPredicateInstruction(second) || !firstGP || !secondGP ||
				code.bytes != word || !reflect.DeepEqual(code.source.Mem, MemRef{Base: load.destination}) {
				return goReadOnlyContext("function value supplies only its exact offset-zero code word")
			}
			plan.reads[ordinal] = goFuncvalRead{first, true}
			plan.reads[ordinal+1] = goFuncvalRead{second, false}
		}
		plan.fingerprint, err = x86CallerSourceFingerprint(fn)
		if err != nil {
			return err
		}
		if source.funcvalReads == nil {
			source.funcvalReads = make(map[string]goFuncvalReadPlan)
		}
		if _, duplicate := source.funcvalReads[fn.Sym]; duplicate {
			return goReadOnlyContext("duplicate function-value source owner")
		}
		source.funcvalReads[fn.Sym] = plan
	}
	return nil
}

func goFuncvalObjects(objects map[string]goReadOnlyObject) bool {
	for _, object := range objects {
		if _, function := object.variable.Type().Underlying().(*types.Signature); function {
			return true
		}
	}
	return false
}

// Only the callback's outer type supplies its representation. Parameter and
// result types do not change a Go function value into a native function pointer.
func goFuncvalCheckConvention(files []*ast.File, typed *types.Package, objects map[string]goReadOnlyObject) error {
	typesByName := make(map[*types.TypeName]*ast.TypeSpec)
	docs := make(map[*types.TypeName]*ast.CommentGroup)
	variableTypes := make(map[*types.Var]ast.Expr)
	functions := make(map[string]*ast.FuncDecl)
	for _, file := range files {
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil {
				functions[function.Name.Name] = function
			}
			group, ok := declaration.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range group.Specs {
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					name, _ := typed.Scope().Lookup(spec.Name.Name).(*types.TypeName)
					typesByName[name], docs[name] = spec, group.Doc
				case *ast.ValueSpec:
					for index, identifier := range spec.Names {
						variable, _ := typed.Scope().Lookup(identifier.Name).(*types.Var)
						variableTypes[variable] = spec.Type
						if spec.Type == nil && index < len(spec.Values) {
							variableTypes[variable] = spec.Values[index]
						}
					}
				}
			}
		}
	}
	var check func(*types.TypeName, ast.Expr, int) error
	check = func(name *types.TypeName, expr ast.Expr, depth int) error {
		if depth > 64 {
			return goReadOnlyContext("function-value type source exceeds its bound")
		}
		for {
			parentheses, ok := expr.(*ast.ParenExpr)
			if !ok {
				break
			}
			expr = parentheses.X
		}
		switch expr := expr.(type) {
		case nil:
			if name == nil {
				return goReadOnlyContext("function representation has no closed source type")
			}
		case *ast.Ident:
			if referenced, ok := typed.Scope().Lookup(expr.Name).(*types.TypeName); ok {
				name = referenced
			} else if name == nil && (functions[expr.Name] == nil || functions[expr.Name].Body == nil) {
				return goReadOnlyContext("inferred function representation needs its actual Go type source")
			}
		case *ast.SelectorExpr:
			return goReadOnlyContext("imported function convention needs its actual source owner")
		case *ast.CallExpr:
			if identifier, ok := expr.Fun.(*ast.Ident); ok {
				if converted, ok := typed.Scope().Lookup(identifier.Name).(*types.TypeName); ok {
					return check(converted, nil, depth+1)
				}
				function := functions[identifier.Name]
				if function != nil && function.Body != nil && function.Type.Results != nil && len(function.Type.Results.List) == 1 {
					if _, ordinary := function.Type.Results.List[0].Type.(*ast.FuncType); ordinary {
						return nil
					}
				}
			}
			return goReadOnlyContext("inferred call result needs an explicit ordinary Go function type")
		}
		if name == nil {
			return nil
		}
		spec := typesByName[name]
		if name.Pkg() != typed || spec == nil {
			return goReadOnlyContext("function-value type needs its actual local Go convention source")
		}
		for _, doc := range []*ast.CommentGroup{docs[name], spec.Doc} {
			if doc == nil {
				continue
			}
			for _, comment := range doc.List {
				text := comment.Text
				switch {
				case strings.HasPrefix(text, "//llgo:"):
					text = strings.TrimPrefix(text, "//llgo:")
				case strings.HasPrefix(text, "// llgo:"):
					text = strings.TrimPrefix(text, "// llgo:")
				default:
					continue
				}
				words := strings.Fields(text)
				if len(words) != 0 && (words[0] == "cdecl" || words[0] == "stdcall" ||
					words[0] == "type" && len(words) > 1 && (words[1] == "C" || words[1] == "stdcall")) {
					return goReadOnlyContext("native function type is not Go descriptor storage")
				}
			}
		}
		// Following only an outer type reference preserves Go1.20 aliases,
		// without walking a callback's unrelated parameter/result types.
		return check(nil, spec.Type, depth+1)
	}
	for name := range objects {
		variable := typed.Scope().Lookup(name).(*types.Var)
		if _, function := variable.Type().Underlying().(*types.Signature); function {
			var name *types.TypeName
			// Obj is shared by Named and newer Alias types, without needing
			// a newer SDK API in the Go1.20 translator build.
			if named, ok := variable.Type().(interface{ Obj() *types.TypeName }); ok {
				name = named.Obj()
			}
			if err := check(name, variableTypes[variable], 0); err != nil {
				return err
			}
		}
	}
	return nil
}

// Called once at the existing whole-function audit entry, not per instruction.
func (source *goReadOnlyStorage) funcvalReadsFor(fn Func) (map[int]goFuncvalRead, error) {
	if source == nil {
		return nil, nil
	}
	plan, known := source.funcvalReads[fn.Sym]
	if !known {
		return nil, nil
	}
	actual, err := x86CallerSourceFingerprint(fn)
	if err != nil || actual != plan.fingerprint || fn.x86DirectTailRoot != nil || fn.x86ContinuationFlow != nil {
		return nil, goReadOnlyContext("function-value source/CFG owner changed before consumption")
	}
	return plan.reads, nil
}

func goFuncvalReadTransfer(reads map[int]goFuncvalRead, ordinal int, ins Instr, state *x86ResultState, arch string) (bool, bool) {
	read, known := reads[ordinal]
	if !known {
		return false, false
	}
	if !reflect.DeepEqual(ins, read.instruction) {
		return false, true
	}
	index, _, valid := x86ResultGP(ins.Args[1].Reg, x86ResultPointerWord(arch), arch)
	if !valid {
		return false, true
	}
	state.gp[index], state.canonicalGP[index] = 0, 0
	state.pointerGP[index], state.callerAddressGP[index], state.callerAddressOrigin[index] = false, false, 0
	state.resultAddressGP[index] = x86ResultSlotAddress{}
	if state.boolFrameGP != nil {
		state.boolFrameGP[index] = x86ResultSlotAddress{}
	}
	if !read.descriptor {
		state.gp[index] = 0xff // The code word, never the descriptor/environment or a callable ABI.
	}
	return true, true
}
