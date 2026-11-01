package plan9asm

import (
	"crypto/sha256"
	"go/types"
	"reflect"
	"strings"
)

// This call-local issuer binds LLVM values to virtual Go registers. It is not
// the stock compiler/archive issuer and supplies no native entry, stack home,
// closure, pointee extent or caller capability. Closing the GoModule call also
// closes every returned signature's private argument role.
type amd64GoVirtualArguments struct {
	pkg               GoPackage
	sizes, frameSizes types.Sizes
	syntax            []string
	imports           map[string]*types.Package
	file              *File
	fingerprint       [32]byte
	input             []byte
	inputSHA          [32]byte
	entries           map[string]*amd64GoArgumentBinding
	symbols           map[string]string
	resolve           func(string) string
	active            bool
	failure           error
}

func amd64VirtualArgumentDeclaration(pkg GoPackage, fn Func) *types.Func {
	symbol := goStripABISuffix(fn.Sym)
	name := goReadOnlyLocalName(pkg, symbol)
	if name == "" {
		name, _ = goDeclNameForSymbol(symbol, goLinknameRemoteToLocal(pkg.Syntax))
	}
	declaration, _ := pkg.Types.Scope().Lookup(name).(*types.Func)
	return declaration
}

func amd64VirtualArgumentsNeeded(fn *types.Func) bool {
	if fn == nil {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Params().Len() > 9 {
		return true
	}
	for index := 0; index < sig.Params().Len(); index++ {
		switch typ := sig.Params().At(index).Type().Underlying().(type) {
		case *types.Basic:
			if typ.Info()&types.IsInteger == 0 && typ.Kind() != types.UnsafePointer {
				return true
			}
		case *types.Pointer, *types.Map, *types.Chan:
		default:
			return true
		}
	}
	return false
}

func bindAMD64GoVirtualArguments(pkg GoPackage, file *File, input []byte, inputSHA [32]byte,
	opt GoModuleOptions, resolve func(string) string,
) (*amd64GoVirtualArguments, error) {
	if opt.GOARCH != "amd64" || opt.NumericalReads != nil || opt.X86TLSMoves != nil || opt.ARM64ByteCarrierSource != nil {
		return nil, nil
	}
	declarations := make(map[string]*types.Func)
	for _, fn := range file.Funcs {
		if strings.HasSuffix(fn.Sym, "<ABIInternal>") {
			if declaration := amd64VirtualArgumentDeclaration(pkg, fn); amd64VirtualArgumentsNeeded(declaration) {
				declarations[fn.Sym] = declaration
			}
		}
	}
	if len(declarations) == 0 {
		return nil, nil
	}
	owner := &amd64GoVirtualArguments{pkg: pkg, sizes: opt.Sizes, frameSizes: opt.FrameSizes,
		input: input, inputSHA: inputSHA, file: x86DirectTailSnapshot(file), resolve: resolve, active: true,
		entries: make(map[string]*amd64GoArgumentBinding), symbols: make(map[string]string), imports: make(map[string]*types.Package)}
	if owner.sizes == nil {
		owner.sizes = types.SizesFor("gc", "amd64")
	}
	if owner.frameSizes == nil {
		owner.frameSizes = owner.sizes
	}
	if !x86CallerTargetSizesValid(owner.sizes) || !x86CallerTargetSizesValid(owner.frameSizes) {
		return nil, amd64GoArgumentContext("virtual arguments need the actual AMD64 target value/frame widths")
	}
	var err error
	owner.syntax, err = goReadOnlySyntax(pkg)
	if err != nil {
		return nil, err
	}
	for path, dependency := range pkg.Imports {
		actual := false
		for _, imported := range pkg.Types.Imports() {
			actual = actual || imported == dependency
		}
		if dependency == nil || dependency.Path() != path || !dependency.Complete() || !actual {
			return nil, amd64GoArgumentContext("virtual declaration import is not the actual complete typed dependency")
		}
		owner.imports[path] = dependency
	}
	typed, err := goReadOnlyTypedSyntax(pkg, owner.syntax, owner.sizes, nil)
	if err != nil {
		return nil, err
	}
	owner.fingerprint, err = x86CallerSourceFingerprint(owner.file)
	if err != nil {
		return nil, err
	}
	for _, fn := range file.Funcs {
		name := resolve(goTextSymbolForResolution(fn.Sym))
		owner.symbols[goTextSymbolForResolution(fn.Sym)] = name
		declaration := declarations[fn.Sym]
		if declaration == nil {
			continue
		}
		actual, _ := typed.Scope().Lookup(declaration.Name()).(*types.Func)
		if actual == nil || name == "" || fn.FrameSize != 0 || len(fn.X86RawText) != 0 || owner.entries[name] != nil {
			return nil, amd64GoArgumentContext("virtual entry lacks one complete declaration and zero-frame source")
		}
		signature, err := goFuncSigForDeclaredFunc(name, declaration, "amd64", owner.sizes, owner.frameSizes, true)
		if err != nil {
			return nil, err
		}
		rechecked, err := goFuncSigForDeclaredFunc(name, actual, "amd64", owner.sizes, owner.frameSizes, true)
		if err != nil || !reflect.DeepEqual(signature, rechecked) {
			return nil, amd64GoArgumentContext("virtual signature differs from actual declaration syntax")
		}
		switch signature.Ret {
		case I1, I8, I16, I32, I64:
		default:
			return nil, amd64GoArgumentContext("virtual parameters require their independent scalar result contract")
		}
		plan, err := planAMD64GoArguments(declaration.Type().(*types.Signature))
		if err != nil {
			return nil, err
		}
		if err := plan.requireRegisters(); err != nil {
			return nil, err
		}
		entry := &amd64GoArgumentBinding{virtual: owner, declaration: declaration, symbol: fn.Sym, signature: signature, plan: plan}
		entry.identity = entry
		entry.seal, err = entry.digest()
		if err != nil {
			return nil, err
		}
		owner.entries[name] = entry
	}
	if err := owner.verify(); err != nil {
		return nil, err
	}
	return owner, nil
}

// Internal lowering consumes only the private plan/source copies. This check
// observes call lifetime and permanent revocation, not a cached successful
// source query. Complete attach/audit/publication boundaries call verify.
func (owner *amd64GoVirtualArguments) live() error {
	if owner == nil || !owner.active {
		return amd64GoArgumentContext("virtual argument call has ended")
	}
	return owner.failure
}

// Returned signatures keep only a closed tombstone, not the call's complete
// source/type graph or callbacks. Clearing private entries does not alter the
// separate public signature values or the caller-owned LLVM module.
func (owner *amd64GoVirtualArguments) close() {
	if owner == nil {
		return
	}
	owner.active = false
	for _, entry := range owner.entries {
		*entry = amd64GoArgumentBinding{identity: entry, virtual: owner}
	}
	*owner = amd64GoVirtualArguments{}
}

func (owner *amd64GoVirtualArguments) verify() (result error) {
	if err := owner.live(); err != nil {
		return err
	}
	defer func() {
		if result != nil {
			owner.failure = result
		}
	}()
	if err := owner.verifySource(); err != nil {
		return err
	}
	for _, entry := range owner.entries {
		actual, err := goFuncSigForDeclaredFunc(entry.signature.Name, entry.declaration, "amd64", owner.sizes, owner.frameSizes, true)
		if err != nil || !reflect.DeepEqual(actual, entry.signature) {
			return amd64GoArgumentContext("virtual declaration transport changed during consumption")
		}
	}
	// Sizes is caller supplied and may execute code even at this final query.
	// Recheck afterward using only concrete syntax/source/private-plan data.
	return owner.verifySource()
}

func (owner *amd64GoVirtualArguments) verifySource() error {
	fingerprint, err := x86CallerSourceFingerprint(owner.file)
	syntax, syntaxErr := goReadOnlySyntax(owner.pkg)
	if err != nil || syntaxErr != nil || fingerprint != owner.fingerprint ||
		sha256.Sum256(owner.input) != owner.inputSHA || !reflect.DeepEqual(syntax, owner.syntax) || len(owner.imports) != len(owner.pkg.Imports) {
		return amd64GoArgumentContext("virtual argument source changed during consumption")
	}
	for path, dependency := range owner.imports {
		if owner.pkg.Imports[path] != dependency {
			return amd64GoArgumentContext("virtual declaration import changed during consumption")
		}
	}
	for _, entry := range owner.entries {
		if owner.pkg.Types.Scope().Lookup(entry.declaration.Name()) != entry.declaration || !entry.matches(entry.signature) {
			return amd64GoArgumentContext("virtual declaration identity changed during consumption")
		}
	}
	return nil
}

func (owner *amd64GoVirtualArguments) resolveSymbol(symbol string) string {
	actual := owner.resolve(symbol)
	if expected, known := owner.symbols[goTextSymbolForResolution(symbol)]; known && actual != expected {
		owner.failure = amd64GoArgumentContext("virtual entry resolver changed during consumption")
	}
	return actual
}

func (owner *amd64GoVirtualArguments) attach(signatures map[string]FuncSig) error {
	if owner == nil {
		return nil
	}
	if err := owner.verify(); err != nil {
		return err
	}
	for name, entry := range owner.entries {
		sig, present := signatures[name]
		if !present || !reflect.DeepEqual(numericalSignatureShape(sig), entry.signature) || sig.amd64GoArguments != nil && sig.amd64GoArguments != entry {
			return amd64GoArgumentContext("virtual entry lost its complete actual signature")
		}
		sig.amd64GoArguments = entry
		signatures[name] = sig
	}
	return nil
}

func (owner *amd64GoVirtualArguments) audit(file *File, signatures map[string]FuncSig, opt GoModuleOptions, resolve func(string) string, storage *goReadOnlyStorage) error {
	if owner == nil || file.x86DirectTails != nil {
		return nil // The complete direct-tail producer already audited every root.
	}
	for _, fn := range file.Funcs {
		sig := signatures[resolve(goTextSymbolForResolution(fn.Sym))]
		if sig.amd64GoArguments == nil || sig.amd64GoArguments.virtual != owner {
			continue
		}
		c := newX86Ctx(new(strings.Builder), fn, sig, resolve, signatures, "amd64", opt.TargetTriple, false)
		c.goReadOnlyStorage = storage
		c.fpScalarData = x86LoweredScalarDataReads(file, resolve, signatures, "amd64")
		c.fpStaticAddressValues = x86LoweredStaticAddressValues(file, resolve, signatures, "amd64")
		c.fpShiftLiterals = x86LoweredShiftLiterals(file, resolve, c.fpStaticAddressValues, "amd64")
		if err := c.scalarFPResultInitialized(); err != nil {
			return err
		}
	}
	return owner.verify()
}
