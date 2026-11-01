package plan9asm

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"strings"
)

// GoSourceSelection carries a compiler's complete, actual selected package,
// not a user-supplied noalias assertion. The inventories must come from the
// same load/profile as Types, Syntax and TypesInfo. Every selected source is
// mandatory; a per-translation subset cannot establish a closed caller graph.
// Assembly contains the corresponding fully preprocessed source files.
type GoSourceSelection struct {
	Fset                  *token.FileSet
	TypesInfo             *types.Info
	Sizes                 types.Sizes
	SelectedGoFiles       []string
	GoSources             map[string][]byte
	SelectedAssemblyFiles []string
	Assembly              map[string]*File
}

type x86CallerRegionKind uint8

const (
	x86CallerSliceInput x86CallerRegionKind = iota + 1
	x86CallerFreshResult
	x86CallerLocalLength
)

type x86CallerArgumentRegion struct {
	kind  x86CallerRegionKind
	width int64
	slot  int64
}

// Only the actual Go producer can construct this private proof. It does not
// establish a source stack, an instruction effect or a return continuation.
// The subsequent whole-source CFG proof must consume the exact signature,
// parameter slots and output envelope before it can admit a raw return.
type x86GoCallerRegionProof struct {
	symbol    string
	arguments []x86CallerArgumentRegion
	calls     int
	goSources map[string][32]byte
	assembly  map[string][32]byte
	signature FuncSig
	source    [32]byte
}

func x86GoCallerRegionCandidate(fn Func, sig FuncSig) bool {
	if sig.Ret != Void || len(sig.Args) == 0 {
		return false
	}
	for _, argument := range sig.Args {
		if argument != Ptr {
			return false
		}
	}
	decoded, err := decodeX86RawDirectives(fn, "amd64")
	if err != nil {
		return false // The normal decoder still reports the actual failure.
	}
	for _, ins := range decoded.Instrs {
		if ins.x86RawNearReturn != nil {
			return true
		}
	}
	return false
}

func deriveX86GoCallerRegions(pkg GoPackage, selected GoSourceSelection, fn Func, sig FuncSig, arch string) (*x86GoCallerRegionProof, error) {
	fail := func(reason string) (*x86GoCallerRegionProof, error) {
		return nil, fmt.Errorf("%w: bounded raw-return caller source: %s", ErrProbeNeedsContext, reason)
	}
	if arch != "amd64" || pkg.Types == nil || selected.Fset == nil || selected.TypesInfo == nil || !x86CallerTargetSizesValid(selected.Sizes) ||
		len(sig.ArgRegs) != 0 || sig.Ret != Void || len(sig.Frame.Results) != 0 ||
		sig.ARMEntry != nil || sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil || sig.WASMNative || sig.WASMContext != "" ||
		fn.FrameSize != 0 || strings.Contains(fn.Sym, "<") || len(sig.Args) == 0 || len(sig.Args) > 16 {
		return fail("needs complete ordinary AMD64 ABI0 pointer/void types and source")
	}
	name := strings.TrimPrefix(sig.Name, pkg.Types.Path()+".")
	declaration, ok := pkg.Types.Scope().Lookup(name).(*types.Func)
	if !ok || name == sig.Name || declaration.Exported() {
		return fail("entry must be an unexported actual package declaration")
	}
	actual, ok := declaration.Type().(*types.Signature)
	if !ok || actual.Recv() != nil || actual.Variadic() || actual.TypeParams().Len() != 0 ||
		actual.Results().Len() != 0 || actual.Params().Len() != len(sig.Args) || len(sig.Frame.Params) != len(sig.Args) ||
		fn.ArgSize != int64(8*len(sig.Args)) {
		return fail("signature is not the complete pointer-only ABI0 declaration")
	}
	for index, argument := range sig.Args {
		bound := false
		for _, slot := range sig.Frame.Params {
			bound = bound || slot.Offset == int64(index*8) && slot.Index == index && slot.Type == Ptr && len(frameSlotFields(slot)) == 0
		}
		if argument != Ptr || !types.Identical(actual.Params().At(index).Type(), types.Typ[types.UnsafePointer]) ||
			!bound || !x86RawReturnFPBound(int64(index*8), 8, sig, arch) {
			return fail("parameter types or exact FP slots differ from the declaration")
		}
	}
	if err := x86ValidateCallerSelection(pkg, selected); err != nil {
		return fail(err.Error())
	}
	if err := x86RejectAssemblyCallers(selected, fn, name, sig.Name, arch); err != nil {
		return fail(err.Error())
	}

	proof := &x86GoCallerRegionProof{
		symbol: sig.Name, signature: sig,
		goSources: make(map[string][32]byte), assembly: make(map[string][32]byte),
	}
	// Slices and maps supplied by the compiler remain mutable. The producer
	// owns an independent signature and byte fingerprint, never an alias of
	// an operand or layout that a later normalization may change.
	proof.signature.Args = append([]LLVMType(nil), sig.Args...)
	proof.signature.Frame.Params = append([]FrameSlot(nil), sig.Frame.Params...)
	var err error
	proof.source, err = x86CallerSourceFingerprint(fn)
	if err != nil {
		return fail("translated source cannot be pinned: " + err.Error())
	}
	for file, source := range selected.GoSources {
		proof.goSources[file] = sha256.Sum256(source)
	}
	for file, assembly := range selected.Assembly {
		fingerprint, err := x86CallerSourceFingerprint(assembly)
		if err != nil {
			return fail("selected assembly cannot be pinned: " + err.Error())
		}
		proof.assembly[file] = fingerprint
	}
	allowedUses := map[*ast.Ident]bool{}
	declarations := 0
	for _, file := range pkg.Syntax {
		for _, group := range file.Comments {
			for _, comment := range group.List {
				if strings.Contains(comment.Text, "go:linkname") {
					for _, field := range strings.Fields(comment.Text) {
						if field == name || field == sig.Name {
							return fail("linkname prevents package-local caller closure")
						}
					}
				}
			}
		}
		for _, node := range file.Decls {
			function, ok := node.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if selected.TypesInfo.Defs[function.Name] == declaration {
				if function.Body != nil {
					return fail("assembly declaration has a Go body")
				}
				declarations++
				continue
			}
			if function.Body == nil {
				continue
			}
			for statementIndex, statement := range function.Body.List {
				expression, ok := statement.(*ast.ExprStmt)
				if !ok {
					continue
				}
				call, ok := expression.X.(*ast.CallExpr)
				if !ok {
					continue
				}
				identifier, ok := call.Fun.(*ast.Ident)
				if !ok || selected.TypesInfo.Uses[identifier] != declaration {
					continue
				}
				regions, err := x86DeriveCallerArguments(function, statementIndex, call, selected.TypesInfo)
				if err != nil {
					return fail(err.Error())
				}
				for index := range regions {
					regions[index].slot = int64(index * 8)
				}
				if proof.arguments != nil && !reflect.DeepEqual(proof.arguments, regions) {
					return fail("different callers do not share the same parameter/write envelope")
				}
				proof.arguments = regions
				proof.calls++
				allowedUses[identifier] = true
			}
		}
	}
	if declarations != 1 || proof.calls == 0 {
		return fail("missing bodyless declaration or closed direct caller")
	}
	closed := true
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if ok && selected.TypesInfo.Uses[identifier] == declaration && !allowedUses[identifier] {
				closed = false // Address-taking, indirect and nested calls never disappear.
			}
			return true
		})
	}
	if !closed {
		return fail("entry has a non-direct, nested or unregistered caller")
	}
	return proof, nil
}

func x86CallerTargetSizesValid(sizes types.Sizes) bool {
	if sizes == nil || sizes.Sizeof(types.Typ[types.UnsafePointer]) != 8 {
		return false
	}
	for _, kind := range []types.BasicKind{
		types.Int8, types.Uint8, types.Int16, types.Uint16, types.Int32, types.Uint32,
		types.Int64, types.Uint64, types.Int, types.Uint, types.Float32, types.Float64,
	} {
		object := types.NewVar(token.NoPos, nil, "", types.Typ[kind])
		if sizes.Sizeof(object.Type()) != x86CallerNumericWidth(object) {
			return false
		}
	}
	return true
}

func x86ValidateCallerSelection(pkg GoPackage, selected GoSourceSelection) error {
	if len(selected.SelectedGoFiles) == 0 || len(selected.SelectedGoFiles) != len(selected.GoSources) ||
		len(pkg.Syntax) != len(selected.SelectedGoFiles) || len(selected.SelectedAssemblyFiles) == 0 ||
		len(selected.SelectedAssemblyFiles) != len(selected.Assembly) {
		return fmt.Errorf("complete selected Go and assembly inventory is required")
	}
	seen := map[string]bool{}
	for _, name := range selected.SelectedGoFiles {
		source, ok := selected.GoSources[name]
		if name == "" || seen[name] || !ok {
			return fmt.Errorf("missing/duplicate selected Go source")
		}
		seen[name] = true
		var syntax *ast.File
		for _, file := range pkg.Syntax {
			if selected.Fset.Position(file.Pos()).Filename == name {
				if syntax != nil {
					return fmt.Errorf("duplicate selected Go syntax")
				}
				syntax = file
			}
		}
		if syntax == nil {
			return fmt.Errorf("selected Go source has no actual typed syntax")
		}
		identitiesMatch := true
		ast.Inspect(syntax, func(node ast.Node) bool {
			if identifier, ok := node.(*ast.Ident); ok {
				object := selected.TypesInfo.ObjectOf(identifier)
				if object != nil && object.Name() != identifier.Name {
					identitiesMatch = false
				}
			}
			return true
		})
		if !identitiesMatch {
			return fmt.Errorf("selected Go identifier differs from its actual typechecked identity")
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, name, source, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("selected Go source is not the typed source: %w", err)
		}
		var original, typed bytes.Buffer
		if err := format.Node(&original, fset, parsed); err != nil {
			return err
		}
		if err := format.Node(&typed, selected.Fset, syntax); err != nil {
			return err
		}
		if !bytes.Equal(original.Bytes(), typed.Bytes()) {
			return fmt.Errorf("selected Go bytes differ from the actual typed syntax")
		}
	}
	seen = map[string]bool{}
	for _, name := range selected.SelectedAssemblyFiles {
		if name == "" || seen[name] || selected.Assembly[name] == nil || selected.Assembly[name].Arch != ArchAMD64 {
			return fmt.Errorf("missing/duplicate selected assembly source")
		}
		seen[name] = true
	}
	return nil
}

func x86RejectAssemblyCallers(selected GoSourceSelection, target Func, localName, resolvedName, arch string) error {
	entries := 0
	for _, file := range selected.Assembly {
		if len(file.UnlinkedPrelude) != 0 {
			return fmt.Errorf("unregistered assembly prelude prevents caller closure")
		}
		for _, data := range file.Data {
			base, _, reference := parseSBRef(strings.TrimPrefix(data.Addr, "$"))
			if reference && (base == target.Sym || base == "·"+localName || base == resolvedName) {
				return fmt.Errorf("assembly DATA exposes the Go entry")
			}
		}
		for _, fn := range file.Funcs {
			if len(fn.X86RawText) != 0 {
				return fmt.Errorf("address-sensitive raw assembly prevents caller closure")
			}
			if fn.Sym == target.Sym {
				if !reflect.DeepEqual(fn, target) {
					return fmt.Errorf("selected assembly entry differs from the translated source")
				}
				entries++
			}
			decoded, err := decodeX86RawDirectives(fn, arch)
			if err != nil {
				return fmt.Errorf("selected assembly caller effects are not known: %w", err)
			}
			for _, ins := range decoded.Instrs {
				for _, argument := range ins.Args {
					symbol := argument.Sym
					if argument.Kind == OpMem {
						symbol = argument.Mem.Sym
					}
					symbol = strings.TrimPrefix(strings.TrimSpace(symbol), "$")
					base, _, reference := parseSBRef(symbol)
					if reference && (base == target.Sym || base == "·"+localName || base == resolvedName) && ins.Op != OpTEXT {
						return fmt.Errorf("selected assembly calls or exposes the Go entry")
					}
				}
				if ins.Op == OpCALL {
					return fmt.Errorf("unknown assembly call cannot close package-local callers")
				}
				if ins.Op == OpJMP {
					if len(ins.Args) != 1 {
						return fmt.Errorf("incomplete assembly branch prevents caller closure")
					}
					argument := ins.Args[0]
					if argument.Kind != OpLabel && argument.Kind != OpIdent &&
						!(argument.Kind == OpMem && argument.Mem.Base == PC && argument.Mem.Index == "" && argument.Mem.Sym == "") {
						return fmt.Errorf("indirect or external assembly branch prevents caller closure")
					}
				}
			}
		}
	}
	if entries != 1 {
		return fmt.Errorf("translated entry is not unique in the complete selected assembly")
	}
	return nil
}

func x86DeriveCallerArguments(function *ast.FuncDecl, index int, call *ast.CallExpr, info *types.Info) ([]x86CallerArgumentRegion, error) {
	if call.Ellipsis.IsValid() || len(call.Args) == 0 {
		return nil, fmt.Errorf("direct call has incomplete argument flow")
	}
	parameters := map[types.Object]bool{}
	if function.Type.Params != nil {
		for _, field := range function.Type.Params.List {
			for _, name := range field.Names {
				parameters[info.Defs[name]] = true
			}
		}
	}
	locals := map[types.Object]x86CallerArgumentRegion{}
	for _, statement := range function.Body.List[:index] {
		switch statement := statement.(type) {
		case *ast.DeclStmt:
			declaration, ok := statement.Decl.(*ast.GenDecl)
			if !ok || declaration.Tok != token.VAR {
				continue
			}
			for _, spec := range declaration.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok || len(value.Values) != 0 {
					continue
				}
				for _, name := range value.Names {
					object := info.Defs[name]
					if width := x86CallerNumericWidth(object); width != 0 {
						locals[object] = x86CallerArgumentRegion{kind: x86CallerFreshResult, width: width}
					}
				}
			}
		case *ast.AssignStmt:
			if statement.Tok != token.DEFINE || len(statement.Lhs) != 1 || len(statement.Rhs) != 1 {
				continue
			}
			name, ok := statement.Lhs[0].(*ast.Ident)
			length, call := statement.Rhs[0].(*ast.CallExpr)
			if !ok || !call || len(length.Args) != 1 {
				continue
			}
			builtin, ok := length.Fun.(*ast.Ident)
			slice, sliceOK := length.Args[0].(*ast.Ident)
			if ok && sliceOK && info.Uses[builtin] == types.Universe.Lookup("len") && parameters[info.Uses[slice]] {
				if _, ok := info.Uses[slice].Type().Underlying().(*types.Slice); ok {
					locals[info.Defs[name]] = x86CallerArgumentRegion{kind: x86CallerLocalLength, width: 8}
				}
			}
		}
	}
	var regions []x86CallerArgumentRegion
	allowedAddresses := map[*ast.Ident]bool{}
	localObjects := map[types.Object]bool{}
	results := 0
	for _, argument := range call.Args {
		conversion, ok := argument.(*ast.CallExpr)
		if !ok || len(conversion.Args) != 1 || conversion.Ellipsis.IsValid() ||
			!info.Types[conversion.Fun].IsType() || !types.Identical(info.TypeOf(conversion.Fun), types.Typ[types.UnsafePointer]) {
			return nil, fmt.Errorf("argument is not an actual unsafe.Pointer conversion")
		}
		switch value := conversion.Args[0].(type) {
		case *ast.UnaryExpr:
			identifier, ok := value.X.(*ast.Ident)
			if value.Op != token.AND || !ok {
				return nil, fmt.Errorf("result/length address is not a fresh direct local")
			}
			object := info.Uses[identifier]
			region, ok := locals[object]
			if !ok || localObjects[object] {
				return nil, fmt.Errorf("result/length local is missing, aliased or not fresh")
			}
			regions = append(regions, region)
			localObjects[object] = true
			allowedAddresses[identifier] = true
			if region.kind == x86CallerFreshResult {
				results++
			}
		case *ast.CallExpr:
			selector, ok := value.Fun.(*ast.SelectorExpr)
			if !ok || info.Uses[selector.Sel] != types.Unsafe.Scope().Lookup("SliceData") || len(value.Args) != 1 {
				return nil, fmt.Errorf("input is not actual unsafe.SliceData")
			}
			identifier, ok := value.Args[0].(*ast.Ident)
			if !ok || !parameters[info.Uses[identifier]] {
				return nil, fmt.Errorf("slice input is not an independent typed caller parameter")
			}
			slice, ok := info.Uses[identifier].Type().Underlying().(*types.Slice)
			if !ok {
				return nil, fmt.Errorf("input is not a typed slice")
			}
			width := x86CallerNumericWidth(types.NewVar(token.NoPos, nil, "", slice.Elem()))
			if width == 0 {
				return nil, fmt.Errorf("slice element layout is not a supported numerical input")
			}
			regions = append(regions, x86CallerArgumentRegion{kind: x86CallerSliceInput, width: width})
		default:
			return nil, fmt.Errorf("unsafe arithmetic or non-direct argument flow")
		}
	}
	if results == 0 {
		return nil, fmt.Errorf("caller has no independent fresh result envelope")
	}
	valid := true
	ast.Inspect(function.Body, func(node ast.Node) bool {
		if address, ok := node.(*ast.UnaryExpr); ok && address.Op == token.AND {
			if identifier, ok := address.X.(*ast.Ident); ok && localObjects[info.Uses[identifier]] && !allowedAddresses[identifier] {
				valid = false
			}
		}
		if assignment, ok := node.(*ast.AssignStmt); ok && assignment.Tok != token.DEFINE {
			for _, target := range assignment.Lhs {
				if identifier, ok := target.(*ast.Ident); ok && localObjects[info.Uses[identifier]] {
					valid = false
				}
			}
		}
		if increment, ok := node.(*ast.IncDecStmt); ok {
			if identifier, ok := increment.X.(*ast.Ident); ok && localObjects[info.Uses[identifier]] {
				valid = false
			}
		}
		return true
	})
	if !valid {
		return nil, fmt.Errorf("fresh local address escaped or its value was reassigned")
	}
	return regions, nil
}

func x86CallerSourceFingerprint(source any) ([32]byte, error) {
	// The parser's exported source operands/bytes contain only JSON-encodable
	// values. Private decoder certificates are deliberately not source input.
	encoded, err := json.Marshal(source)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func x86CallerNumericWidth(object types.Object) int64 {
	if object == nil {
		return 0
	}
	basic, ok := object.Type().(*types.Basic)
	if !ok {
		return 0
	}
	switch basic.Kind() {
	case types.Uint8, types.Int8:
		return 1
	case types.Uint16, types.Int16:
		return 2
	case types.Uint32, types.Int32, types.Float32:
		return 4
	case types.Uint64, types.Int64, types.Float64, types.Int, types.Uint:
		return 8
	default:
		return 0
	}
}
