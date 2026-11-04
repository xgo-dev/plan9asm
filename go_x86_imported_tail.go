package plan9asm

import (
	"go/ast"
	"go/types"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/goabi"
)

// Ordinary Go declarations retain their source convention. A structurally
// identical C/custom function or a renamed entry cannot supply an ABI0 tail.
func goX86TailFunction(pkg GoPackage, name string, bodyless bool) (*types.Func, error) {
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
			if !ok || declaration.Recv != nil || declaration.Name.Name != name {
				continue
			}
			if found {
				return nil, x86DirectTailContext("tail declaration is duplicated")
			}
			if bodyless && declaration.Body != nil {
				return nil, x86DirectTailContext("tail caller is not a bodyless assembly declaration")
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
	fn, err := goX86TailFunction(owner, name, false)
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
		if !pure {
			continue
		}
		if graph.goPackage == nil {
			return x86DirectTailContext("pure external tail needs its actual GoModule declaration source")
		}
		pkg := *graph.goPackage
		name := goReadOnlyLocalName(pkg, fn.Sym)
		declaration, err := goX86TailFunction(pkg, name, true)
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
		calleeName := graph.externalSymbols[target]
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
