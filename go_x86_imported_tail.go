package plan9asm

import (
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/goabi"
)

// Ordinary Go declarations retain their source convention. A structurally
// identical C/custom function or a renamed entry cannot supply an ABI0 tail.
func goX86TailFunction(pkg GoPackage, name string, bodyless bool, sizes types.Sizes) (*types.Func, error) {
	if pkg.Types == nil || pkg.Types.Scope() == nil || pkg.Types.Name() == "C" {
		return nil, x86DirectTailContext("tail declaration lacks an ordinary Go package")
	}
	fn, ok := pkg.Types.Scope().Lookup(name).(*types.Func)
	if !ok || fn.Pkg() != pkg.Types || fn.Parent() != pkg.Types.Scope() {
		return nil, x86DirectTailContext("tail lacks its actual Go function declaration: %s", name)
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() != nil || sig.Variadic() || sig.TypeParams().Len() != 0 {
		return nil, x86DirectTailContext("tail excludes methods, variadic and generic declarations")
	}
	if len(pkg.Syntax) == 0 || len(pkg.Syntax) > 256 {
		return nil, x86DirectTailContext("tail lacks bounded selected declaration syntax")
	}
	found := false
	for _, file := range pkg.Syntax {
		if file == nil || file.Name == nil || file.Name.Name != pkg.Types.Name() {
			return nil, x86DirectTailContext("tail syntax differs from its actual package")
		}
		for _, node := range file.Decls {
			declaration, ok := node.(*ast.FuncDecl)
			if !ok || declaration == nil || declaration.Name == nil || declaration.Recv != nil || declaration.Name.Name != name {
				continue
			}
			if found {
				return nil, x86DirectTailContext("tail declaration is duplicated")
			}
			if bodyless && declaration.Body != nil {
				return nil, x86DirectTailContext("tail caller is not a bodyless assembly declaration")
			}
			if err := goX86TailSyntaxType(pkg, file, declaration, sig, sizes); err != nil {
				return nil, err
			}
			found = true
			if declaration.Doc != nil {
				for _, comment := range declaration.Doc.List {
					text := strings.TrimSpace(strings.TrimPrefix(comment.Text, "//"))
					if strings.HasPrefix(text, "llgo:") {
						return nil, x86DirectTailContext("tail cannot borrow a native/custom declaration")
					}
				}
			}
		}
	}
	for remote, local := range goLinknameRemoteToLocal(pkg.Syntax) {
		if local == name && remote != pkg.Types.Path()+"."+name {
			return nil, x86DirectTailContext("tail declaration has a renamed entry")
		}
	}
	if !found {
		return nil, x86DirectTailContext("tail lacks its selected declaration syntax: %s", name)
	}
	return fn, nil
}

// Recheck only the selected function type against its actual package objects
// and imports. This uses Go's type checker with the requested architecture's
// sizes; it neither rechecks bodies nor formats/reloads a complete package.
func goX86TailSyntaxType(pkg GoPackage, file *ast.File, declaration *ast.FuncDecl,
	expected *types.Signature, sizes types.Sizes) error {
	if declaration.Type == nil || sizes == nil {
		return x86DirectTailContext("tail lacks a target-sized declaration type")
	}
	owner := types.NewPackage(pkg.Types.Path(), pkg.Types.Name())
	referenced := make(map[string]bool)
	ast.Inspect(declaration.Type, func(node ast.Node) bool {
		if identifier, ok := node.(*ast.Ident); ok {
			referenced[identifier.Name] = true
			if object := pkg.Types.Scope().Lookup(identifier.Name); object != nil {
				owner.Scope().Insert(object)
			}
		}
		return true
	})
	for _, specification := range file.Imports {
		if specification == nil || specification.Path == nil {
			return x86DirectTailContext("tail declaration has an invalid import")
		}
		path, err := strconv.Unquote(specification.Path.Value)
		if err != nil {
			return x86DirectTailContext("tail declaration has an invalid import path")
		}
		var dependency *types.Package
		for _, imported := range pkg.Types.Imports() {
			if imported.Path() == path {
				dependency = imported
				break
			}
		}
		if dependency == nil {
			// Export data may omit imports used only by a function body.
			// Add no guessed object: a signature which actually needs this
			// import still fails the type check below as an unresolved name.
			continue
		}
		name := dependency.Name()
		if specification.Name != nil {
			name = specification.Name.Name
		}
		if name == "." {
			for identifier := range referenced {
				if object := dependency.Scope().Lookup(identifier); object != nil && object.Exported() {
					if previous := owner.Scope().Insert(object); previous != nil && previous != object {
						return x86DirectTailContext("tail declaration has ambiguous imported types")
					}
				}
			}
		} else if referenced[name] {
			if path == "C" || owner.Scope().Insert(types.NewPkgName(token.NoPos, owner, name, dependency)) != nil {
				return x86DirectTailContext("tail declaration has a native or ambiguous import")
			}
		}
	}
	information := &types.Info{Types: make(map[ast.Expr]types.TypeAndValue)}
	syntax := &ast.File{Name: ast.NewIdent(owner.Name()), Decls: []ast.Decl{
		&ast.GenDecl{Tok: token.VAR, Specs: []ast.Spec{
			&ast.ValueSpec{Names: []*ast.Ident{ast.NewIdent("_")}, Type: declaration.Type},
		}},
	}}
	checker := types.NewChecker(&types.Config{Sizes: sizes}, token.NewFileSet(), owner, information)
	if err := checker.Files([]*ast.File{syntax}); err != nil {
		return x86DirectTailContext("tail selected declaration cannot be checked: %v", err)
	}
	actual, ok := information.Types[declaration.Type].Type.(*types.Signature)
	if !ok || !types.Identical(actual, expected) {
		return x86DirectTailContext("tail selected declaration differs from its actual Go type")
	}
	for index, tuple := range []*types.Tuple{actual.Params(), actual.Results()} {
		wanted := []*types.Tuple{expected.Params(), expected.Results()}[index]
		for field := 0; field < tuple.Len(); field++ {
			if tuple.At(field).Name() != wanted.At(field).Name() {
				return x86DirectTailContext("tail selected declaration field names differ from its actual Go type")
			}
		}
	}
	return nil
}

func goX86ImportedTailSignature(pkg GoPackage, resolved, arch string, sizes, frames types.Sizes) (FuncSig, error) {
	path, name := goReadOnlyImportedName(resolved)
	if path == "" || path == "C" || path == pkg.Path || pkg.Types == nil {
		return FuncSig{}, x86DirectTailContext("tail needs its exact ordinary selected import: %s", resolved)
	}
	dependency := pkg.Imports[path]
	if dependency == nil || dependency == pkg.Types || dependency.Path() != path || !dependency.Complete() || dependency.Scope() == nil {
		return FuncSig{}, x86DirectTailContext("tail lacks its complete selected typed import: %s", path)
	}
	found := false
	for _, imported := range pkg.Types.Imports() {
		found = found || imported == dependency
	}
	if !found {
		return FuncSig{}, x86DirectTailContext("tail import differs from actual typed dependency: %s", path)
	}
	owner := GoPackage{Path: path, Types: dependency, Syntax: pkg.ImportSyntax[path]}
	if sizes == nil {
		sizes = types.SizesFor("gc", arch)
	}
	fn, err := goX86TailFunction(owner, name, false, sizes)
	if err != nil {
		return FuncSig{}, err
	}
	return goFuncSigForDeclaredFunc(resolved, fn, arch, sizes, frames, true)
}

// Only the newly admitted pure external stubs need this declaration join.
// Existing private continuation/CALL graphs keep their independent contracts.
func (graph *x86DirectTailGraph) verifyPureGoTails() error {
	for _, fn := range graph.original.Funcs {
		target, pure := x86OrdinaryExternalTailTarget(fn)
		if !pure || x86ABI0BoolResultNeedsProof(graph.signatures[graph.symbols[fn.Sym]], graph.goarch) {
			continue
		}
		if graph.goPackage == nil {
			return x86DirectTailContext("pure external tail needs its actual GoModule declaration source")
		}
		pkg := *graph.goPackage
		calleeName := graph.externalSymbols[target]
		if goReadOnlyLocalName(pkg, calleeName) != "" {
			continue // Same-package Go tails keep their pre-existing declaration path.
		}
		name := goReadOnlyLocalName(pkg, fn.Sym)
		declaration, err := goX86TailFunction(pkg, name, true, types.SizesFor("gc", graph.goarch))
		if err != nil {
			return err
		}
		resolved := graph.symbols[fn.Sym]
		if resolved != pkg.Path+"."+name {
			return x86DirectTailContext("tail caller resolver differs from its actual declaration")
		}
		caller, err := goFuncSigForDeclaredFunc(resolved, declaration, graph.goarch, nil, nil, true)
		if err != nil {
			return err
		}
		word := int64(8)
		if graph.goarch == "386" {
			word = 4
		}
		end := int64(0)
		for _, slots := range [][]FrameSlot{caller.Frame.Params, caller.Frame.Results} {
			for _, slot := range slots {
				if next := slot.Offset + frameTypeSize(slot.Type, word); next > end {
					end = next
				}
			}
		}
		op, rest := splitOpcode(fn.Instrs[0].Raw)
		frame, err := parseTEXTFrameSpec(strings.Split(rest, ","))
		if err != nil || !strings.EqualFold(op, "TEXT") || frame.frameSize != fn.FrameSize || frame.argSize != fn.ArgSize ||
			!x86ABI0FrameLayout(caller, end, graph.goarch) ||
			!x86TEXTArgumentsUnspecified(fn) && !goabi.MatchesABI0TextSize(graph.goarch, fn.ArgSize, end) {
			return x86DirectTailContext("tail TEXT extent differs from actual ordinary Go ABI0 declaration")
		}
		callee, err := goX86ImportedTailSignature(pkg, calleeName, graph.goarch, nil, nil)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(caller, graph.signatures[resolved]) || !reflect.DeepEqual(callee, graph.signatures[calleeName]) {
			return x86DirectTailContext("pure tail signatures differ from actual ordinary Go ABI0 declarations")
		}
	}
	return nil
}
