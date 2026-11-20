package plan9asm

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"
)

// This pure typed-body observation is not a callee, object, native-entry or
// non-return capability. Only a separately authenticated actual source/compiler
// producer may join it to one original CALL and its later emitted operation.
func x86GoSinglePanicBodies(pkg GoPackage) (map[*types.Func]*ast.FuncDecl, error) {
	bodies := make(map[*types.Func]*ast.FuncDecl)
	selected := pkg.SourceSelection
	if pkg.Types == nil || pkg.Path == "" || pkg.Types.Path() != pkg.Path || selected == nil || selected.Fset == nil || selected.TypesInfo == nil || selected.Sizes == nil {
		return nil, fmt.Errorf("%w: panic body needs its complete selected typed source", ErrProbeNeedsContext)
	}
	if err := x86ValidateCallerSelection(pkg, *selected); err != nil {
		return nil, fmt.Errorf("%w: panic body selection changed: %v", ErrProbeNeedsContext, err)
	}
	for _, file := range pkg.Syntax {
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil || len(fn.Body.List) != 1 ||
				fn.Type.TypeParams != nil && len(fn.Type.TypeParams.List) != 0 {
				continue
			}
			object, valid := selected.TypesInfo.Defs[fn.Name].(*types.Func)
			if !valid || object.Pkg() != pkg.Types || pkg.Types.Scope().Lookup(fn.Name.Name) != object {
				return nil, fmt.Errorf("%w: panic body lost its exact selected function object", ErrProbeNeedsContext)
			}
			signature, valid := object.Type().(*types.Signature)
			if !valid || signature.Recv() != nil || signature.Params().Len() != 0 || signature.Results().Len() != 0 || signature.Variadic() {
				continue
			}
			redirected := false
			if fn.Doc != nil {
				for _, comment := range fn.Doc.List {
					redirected = redirected || strings.Contains(comment.Text, "go:linkname") || strings.Contains(comment.Text, "go:wasmimport")
				}
			}
			statement, valid := fn.Body.List[0].(*ast.ExprStmt)
			if !valid || redirected {
				continue
			}
			call, valid := statement.X.(*ast.CallExpr)
			if !valid || call.Ellipsis.IsValid() || len(call.Args) != 1 {
				continue
			}
			callee, valid := call.Fun.(*ast.Ident)
			if !valid || selected.TypesInfo.ObjectOf(callee) != types.Universe.Lookup("panic") {
				continue
			}
			recovers := false
			ast.Inspect(call, func(node ast.Node) bool {
				if identifier, ok := node.(*ast.Ident); ok && selected.TypesInfo.ObjectOf(identifier) == types.Universe.Lookup("recover") {
					recovers = true
				}
				return !recovers
			})
			if !recovers {
				bodies[object] = fn
			}
		}
	}
	return bodies, nil
}
