package plan9asm

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"strings"
)

// This is a layout observation, not bodyless-source or memory permission.
// Only the explicit source binder below produces the separate source record.
type arm64ABI0Declaration struct {
	function  *types.Func
	signature FuncSig
	argsSize  int64
	types     string
}

func arm64ABI0SignatureSnapshot(sig FuncSig) FuncSig {
	sig.arm64ABI0Declaration, sig.arm64ABI0TailDeclaration = nil, nil
	sig.arm64NativeScratch = nil
	sig.Args = append([]LLVMType(nil), sig.Args...)
	sig.Frame.Params = arm64CopyFPSlots(sig.Frame.Params)
	sig.Frame.Results = arm64CopyFPSlots(sig.Frame.Results)
	return sig
}

func arm64ABI0DeclarationForGo(sig FuncSig, fn *types.Func, sizes, frameSizes types.Sizes) *arm64ABI0Declaration {
	decl, ok := fn.Type().(*types.Signature)
	if !ok || fn.Pkg() == nil || fn.Parent() != fn.Pkg().Scope() || decl.Recv() != nil || decl.Variadic() ||
		decl.Params().Len() > 64 || decl.Results().Len() == 0 || decl.Results().Len() > 16 {
		return nil
	}
	for _, layout := range []types.Sizes{sizes, frameSizes} {
		if layout == nil || !arm64PaddingDeclarationLayoutMatches(layout, decl) {
			return nil
		}
	}
	gc := types.SizesFor("gc", "arm64")
	args, params, end, err := goLLVMArgsAndFrameSlotsForTuple(decl.Params(), "arm64", gc, gc, 0, false)
	if err != nil {
		return nil
	}
	results, slots, end, err := goLLVMArgsAndFrameSlotsForTuple(decl.Results(), "arm64", gc, gc, goAlignOff(end, 8), true)
	if err != nil || end < 0 || end > 65536 || !reflect.DeepEqual(args, sig.Args) ||
		!reflect.DeepEqual(params, sig.Frame.Params) || !reflect.DeepEqual(slots, sig.Frame.Results) ||
		goTupleRetType(results) != sig.Ret || len(slots) != decl.Results().Len() {
		return nil
	}
	for i, slot := range slots {
		basic, ok := decl.Results().At(i).Type().Underlying().(*types.Basic)
		if !ok || basic.Info()&types.IsInteger == 0 || slot.Field != -1 || len(slot.Fields) != 0 ||
			(slot.Type != I8 && slot.Type != I16 && slot.Type != I32 && slot.Type != I64) {
			return nil // No aggregate interiors, floating/GC results or guessed layout.
		}
	}
	return &arm64ABI0Declaration{function: fn, signature: arm64ABI0SignatureSnapshot(sig), argsSize: end,
		types: arm64ABI0DeclarationTypes(decl)}
}

func arm64ABI0DeclarationTypes(decl *types.Signature) string {
	identity := types.TypeString(decl, func(pkg *types.Package) string { return pkg.Path() })
	for _, tuple := range []*types.Tuple{decl.Params(), decl.Results()} {
		for i := 0; i < tuple.Len(); i++ {
			identity += "|" + types.TypeString(tuple.At(i).Type().Underlying(), func(pkg *types.Package) string { return pkg.Path() })
		}
	}
	return identity
}

func (d *arm64ABI0Declaration) matches(sig FuncSig) bool {
	return d != nil && d.function != nil && d.function.Pkg() != nil &&
		d.function.Pkg().Scope().Lookup(d.function.Name()) == d.function &&
		arm64ABI0DeclarationTypes(d.function.Type().(*types.Signature)) == d.types &&
		reflect.DeepEqual(d.signature, arm64ABI0SignatureSnapshot(sig))
}

// Hold the actual typed selection as well as independent byte/AST snapshots.
// A public layout, JSON, or a name-equivalent declaration cannot recreate it.
type arm64ABI0TailDeclaration struct {
	declaration *arm64ABI0Declaration
	packageData GoPackage
	syntax      []string
	sources     map[string][]byte
	selected    []string
	fset        *token.FileSet
	file        *File
	original    File
	root        Func
	name        string
	symbolPath  string
	object      *ast.Ident
}

func arm64ABI0Syntax(file *ast.File, fset *token.FileSet) (string, error) {
	if file == nil || file.Name == nil || fset == nil {
		return "", fmt.Errorf("incomplete actual Go syntax")
	}
	for _, node := range file.Decls {
		if fn, ok := node.(*ast.FuncDecl); ok && (fn == nil || fn.Name == nil) {
			return "", fmt.Errorf("incomplete actual Go function declaration")
		}
	}
	var output bytes.Buffer
	err := format.Node(&output, fset, file)
	return output.String(), err
}

func arm64ABI0FileSnapshot(file *File) File {
	copyFile := *file
	copyFile.Funcs = append([]Func(nil), file.Funcs...)
	for i := range copyFile.Funcs {
		copyFile.Funcs[i] = arm64PrivateTailSnapshot(copyFile.Funcs[i])
	}
	copyFile.Data = append([]DataStmt(nil), file.Data...)
	for i := range copyFile.Data {
		copyFile.Data[i].Payload = append([]byte(nil), copyFile.Data[i].Payload...)
	}
	copyFile.Globl = append([]GloblStmt(nil), file.Globl...)
	copyFile.UnlinkedPrelude = append([]string(nil), file.UnlinkedPrelude...)
	return copyFile
}

func arm64ABI0TailPackageNamespaceMatches(pkg GoPackage, function, symbol string) bool {
	if pkg.Types == nil {
		return false
	}
	if pkg.Path == pkg.Types.Path() {
		return true
	}
	// Executables use main's symbol namespace while retaining the actual
	// typechecked source package. This is not an arbitrary package alias.
	return pkg.Path == "main" && pkg.Types.Name() == "main" && symbol == "main."+function
}

func (d *arm64ABI0TailDeclaration) matches(sig FuncSig) bool {
	if d == nil || !d.declaration.matches(sig) || d.file == nil ||
		!reflect.DeepEqual(d.original, arm64ABI0FileSnapshot(d.file)) || d.packageData.Types == nil ||
		d.packageData.Types != d.declaration.function.Pkg() || d.packageData.Path != d.symbolPath ||
		!arm64ABI0TailPackageNamespaceMatches(d.packageData, d.declaration.function.Name(), d.name) {
		return false
	}
	selection := d.packageData.SourceSelection
	if selection == nil || selection.Fset == nil || selection.Fset != d.fset || selection.TypesInfo == nil ||
		selection.Sizes == nil || !arm64PaddingDeclarationLayoutMatches(selection.Sizes, d.declaration.function.Type().(*types.Signature)) ||
		selection.TypesInfo.Defs[d.object] != d.declaration.function ||
		!reflect.DeepEqual(d.selected, selection.SelectedGoFiles) || len(d.syntax) != len(d.packageData.Syntax) ||
		len(d.sources) != len(selection.GoSources) {
		return false
	}
	for name, original := range d.sources {
		if !bytes.Equal(original, selection.GoSources[name]) {
			return false
		}
	}
	for i, file := range d.packageData.Syntax {
		text, err := arm64ABI0Syntax(file, selection.Fset)
		if err != nil || text != d.syntax[i] || file.Name.Name != d.packageData.Types.Name() {
			return false
		}
	}
	return true
}

// BindGoARM64ABI0TailDeclarations binds only actually consumed local ABI0 tail
// roots to the same typechecked bodyless declarations and complete selected Go
// bytes. It certifies neither ZIP/CPP/tool provenance nor a native extent. The
// complete source continuation and every return still need their own proof.
// Neither input is modified. File-only preparation remains strict.
func BindGoARM64ABI0TailDeclarations(pkg GoPackage, file *File, resolve func(string) string, sigs map[string]FuncSig) (map[string]FuncSig, error) {
	result := make(map[string]FuncSig, len(sigs))
	for name, sig := range sigs {
		result[name] = sig
	}
	if file == nil || file.Arch != ArchARM64 {
		return result, nil
	}
	for _, root := range file.Funcs {
		candidate := arm64ABI0TailCandidate(file, root)
		if !candidate || strings.HasSuffix(root.Sym, "<ABIInternal>") || strings.HasSuffix(root.Sym, "<>") {
			continue
		}
		if resolve == nil || !strings.HasPrefix(root.Sym, "·") || strings.ContainsAny(strings.TrimPrefix(root.Sym, "·"), "·<>") {
			return nil, arm64GoABIContext("ABI0 tail needs an exact local declaration/source namespace")
		}
		name := resolve(goTextSymbolForResolution(root.Sym))
		sig := result[name]
		if len(sig.ArgRegs) != 0 {
			continue // Existing explicit callable-helper register transport stays separate.
		}
		decl := sig.arm64ABI0Declaration
		selection := pkg.SourceSelection
		if !decl.matches(sig) || pkg.Types == nil || pkg.Types != decl.function.Pkg() ||
			!arm64ABI0TailPackageNamespaceMatches(pkg, decl.function.Name(), name) ||
			decl.function.Name() != strings.TrimPrefix(root.Sym, "·") ||
			selection == nil || selection.Fset == nil || selection.TypesInfo == nil || selection.Sizes == nil ||
			len(selection.SelectedGoFiles) == 0 || len(selection.SelectedGoFiles) > 256 ||
			len(selection.GoSources) != len(selection.SelectedGoFiles) || len(pkg.Syntax) != len(selection.SelectedGoFiles) {
			return nil, arm64GoABIContext("ABI0 tail lacks its actual selected bodyless declaration")
		}
		bound := &arm64ABI0TailDeclaration{
			declaration: decl, packageData: pkg, sources: make(map[string][]byte),
			selected: append([]string(nil), selection.SelectedGoFiles...), fset: selection.Fset, file: file,
			original: arm64ABI0FileSnapshot(file), root: arm64PrivateTailSnapshot(root), name: name, symbolPath: pkg.Path,
		}
		total := 0
		for i, filename := range selection.SelectedGoFiles {
			source, present := selection.GoSources[filename]
			total += len(source)
			if !present || len(source) == 0 || total > 16<<20 || bound.sources[filename] != nil {
				return nil, arm64GoABIContext("ABI0 tail has an incomplete/oversized selected Go inventory")
			}
			parsedSet := token.NewFileSet()
			parsed, err := parser.ParseFile(parsedSet, filename, source, parser.ParseComments)
			if err != nil {
				return nil, arm64GoABIContext("ABI0 tail selected Go source cannot parse: %v", err)
			}
			actual, err := arm64ABI0Syntax(pkg.Syntax[i], selection.Fset)
			fromBytes, parseErr := arm64ABI0Syntax(parsed, parsedSet)
			if err != nil || parseErr != nil || actual != fromBytes || pkg.Syntax[i].Name.Name != pkg.Types.Name() {
				return nil, arm64GoABIContext("ABI0 tail typed syntax differs from its complete selected bytes")
			}
			bound.syntax = append(bound.syntax, actual)
			bound.sources[filename] = append([]byte(nil), source...)
			for _, node := range pkg.Syntax[i].Decls {
				fn, ok := node.(*ast.FuncDecl)
				if !ok || fn.Name.Name != decl.function.Name() {
					continue
				}
				if bound.object != nil || fn.Recv != nil || fn.Body != nil ||
					selection.TypesInfo.Defs[fn.Name] != decl.function || fn.Name.Pos() != decl.function.Pos() ||
					selection.Fset.Position(fn.Name.Pos()).Filename != filename {
					return nil, arm64GoABIContext("ABI0 tail declaration role/type identity is not bodyless")
				}
				bound.object = fn.Name
			}
		}
		if bound.object == nil || !bound.matches(sig) {
			return nil, arm64GoABIContext("ABI0 tail has no complete actual bodyless source binding")
		}
		sig.arm64ABI0TailDeclaration = bound
		result[name] = sig
	}
	return result, nil
}

// The source binding is needed only for actual ABI0 private tails. Ordinary
// files and Phase1 ABIInternal roots do not load a second declaration graph.
func GoARM64ABI0TailDeclarationBindingNeeded(file *File) bool {
	if file == nil || file.Arch != ArchARM64 {
		return false
	}
	for _, fn := range file.Funcs {
		if strings.Contains(fn.Sym, "<") {
			continue
		}
		if arm64ABI0TailCandidate(file, fn) {
			return true
		}
	}
	return false
}

func arm64ABI0TailCandidate(file *File, root Func) bool {
	for _, ins := range root.Instrs {
		name, tail := arm64PrivateTailTarget(ins)
		if !tail {
			continue
		}
		for _, helper := range file.Funcs {
			if helper.Sym != name || helper.ArgSize != 0 {
				continue
			}
			fp := false
			for _, instruction := range helper.Instrs {
				for _, arg := range instruction.Args {
					fp = fp || arg.Kind == OpFP || arg.Kind == OpFPAddr
				}
			}
			if !fp {
				return true
			}
		}
	}
	return false
}

func goBindARM64ABI0TailDeclarations(pkg GoPackage, file *File, resolve func(string) string, opt GoModuleOptions) (map[string]FuncSig, error) {
	if !GoARM64ABI0TailDeclarationBindingNeeded(file) {
		return nil, nil
	}
	sizes, frameSizes := opt.Sizes, opt.FrameSizes
	if sizes == nil {
		sizes = types.SizesFor("gc", "arm64")
	}
	if frameSizes == nil {
		frameSizes = sizes
	}
	builder := goSigBuilder{
		sigs: make(map[string]FuncSig), localSigs: make(map[string]bool),
		scope: pkg.Types.Scope(), sz: sizes, frameSz: frameSizes,
		linknames: goLinknameRemoteToLocal(pkg.Syntax), pkgPath: pkg.Path,
		resolve: resolve, goarch: "arm64", manualSig: opt.ManualSig,
	}
	if err := builder.addDeclaredFuncSigs(file); err != nil {
		return nil, fmt.Errorf("%w: ABI0 tail declaration binding: %w", ErrProbeNeedsContext, err)
	}
	return BindGoARM64ABI0TailDeclarations(pkg, file, resolve, builder.sigs)
}
