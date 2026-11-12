package plan9asm

import (
	"go/ast"
	"go/types"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gosym"
)

// Keep native addresses opaque through the existing CFG, affine and spill
// transfers. A Go variable is not an FP slot, numeric bits or private storage.
type x86FixedLocalOrigin struct {
	parameter int64
	global    string
	literal   x86StaticSBAddress
}

func fixedLocalGlobalSymbol(symbol string) string {
	if !strings.ContainsAny(symbol, "·./") {
		return "·" + symbol
	}
	return symbol
}

func fixedLocalStaticAddress(ins Instr) (x86StaticSBAddress, bool) {
	ins = x86SourceMoveInstruction(ins, "amd64")
	if ins.Op != "LEAQ" && x86RawReturnScalarMoveBytes(ins.Op) != 8 ||
		!x86ResultNamedPredicateInstruction(ins) || len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return x86StaticSBAddress{}, false
	}
	root, valid := x86CallerGP(ins.Args[1].Reg)
	if !valid || root != ins.Args[1].Reg || root == SP {
		return x86StaticSBAddress{}, false
	}
	if ins.Op == "LEAQ" {
		width, err := x86LEAOperandWidth(ins, "amd64")
		address, valid := x86StaticSBSourceAddress(ins.Args[0], "amd64")
		return address, err == nil && width == 8 && valid
	}
	address, immediate, valid := x86StaticAddressValueSource(ins.Args[0], "amd64")
	return address, valid && immediate
}

func fixedLocalGlobalSymbols(file *File) map[string]bool {
	var symbols map[string]bool
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			address, valid := fixedLocalStaticAddress(ins)
			if !valid || ins.Op == "LEAQ" {
				continue
			}
			if symbols == nil {
				symbols = make(map[string]bool)
			}
			symbols[fixedLocalGlobalSymbol(address.symbol)] = true
		}
	}
	return symbols
}

// Resolve only actual same-package variable candidates. The caller freezes
// callbacks outside its source lock; the same original typecheck below joins
// their complete numerical layout. No process, new source owner or initializer
// evaluation is needed, and no initializer bytes become LLVM constants.
func fixedLocalGlobalRequests(pkg GoPackage, file *File, resolve func(string) string) (map[string]goReadOnlyObject, error) {
	var objects map[string]goReadOnlyObject
	for symbol := range fixedLocalGlobalSymbols(file) {
		name := goReadOnlyLocalName(pkg, symbol)
		variable, exists := pkg.Types.Scope().Lookup(name).(*types.Var)
		if !exists || variable.IsField() || variable.Pkg() != pkg.Types {
			continue
		}
		native := gosym.PackagePrefix(pkg.Path) + "." + name
		if resolve(symbol) != native {
			return nil, goAMD64FrameContext("ordinary Go variable has a foreign native identity: %s", symbol)
		}
		if objects == nil {
			objects = make(map[string]goReadOnlyObject)
		}
		objects[symbol] = goReadOnlyObject{native: native}
	}
	return objects, nil
}

// Called inside the frame observer's one complete independent typecheck.
// Reuse the ordinary numerical-variable layout grammar, never just a name,
// supplied type, guessed extent, symbol address or the variable's initial value.
func joinFixedLocalGlobalDeclarations(actual, supplied *types.Package, syntax []*ast.File, sizes types.Sizes, objects map[string]goReadOnlyObject) error {
	if len(objects) == 0 {
		return nil
	}
	declarations := make(map[string]goReadOnlyObject, len(objects))
	for symbol, object := range objects {
		name := goReadOnlyName(actual.Path(), symbol)
		variable, found := actual.Scope().Lookup(name).(*types.Var)
		previous, provided := supplied.Scope().Lookup(name).(*types.Var)
		if !found || !provided || variable.IsField() || previous.IsField() || variable.Pkg() != actual {
			return goAMD64FrameContext("ordinary address lacks its original Go variable: %s", symbol)
		}
		size, spans, shape, err := goReadOnlyLayout(variable.Type(), sizes)
		priorSize, priorSpans, priorShape, priorErr := goReadOnlyLayout(previous.Type(), sizes)
		if err != nil || priorErr != nil || size != priorSize || shape != priorShape || !reflect.DeepEqual(spans, priorSpans) {
			return goAMD64FrameContext("ordinary Go variable differs from its complete original numerical type: %s", symbol)
		}
		object.variable, object.size, object.spans, object.shape = variable, size, spans, shape
		objects[symbol], declarations[name] = object, object
	}
	return goReadOnlyCheckAliases(syntax, actual, declarations)
}
