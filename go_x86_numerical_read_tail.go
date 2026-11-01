package plan9asm

import (
	"bytes"
	"context"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

// Pure source-role audit only. Actual typed root state is checked by the
// continuation consumer after exact original-node numerical certificates join.
func numericalDirectTailRoles(file *File) (map[x86DirectTailPoint]string, error) {
	roles := make(map[x86DirectTailPoint]string)
	if !x86DirectTailSourceNeeded(file) {
		return roles, nil
	}
	helpers := make(map[string]bool)
	names := make(map[string]bool)
	for _, fn := range file.Funcs {
		if names[fn.Sym] {
			return nil, numericalSBContext("continuation repeats an original TEXT identity")
		}
		names[fn.Sym] = true
		if strings.HasSuffix(fn.Sym, "<>") {
			helpers[fn.Sym] = true
		}
	}
	graph := &x86DirectTailGraph{original: file, helpers: helpers}
	if err := graph.auditReferences(); err != nil {
		return nil, err
	}
	for text, fn := range file.Funcs {
		for ordinal, ins := range fn.Instrs {
			if ins.Op != OpJMP && ins.Op != OpCALL || len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
				continue
			}
			name, offset, valid := parseSBRef(ins.Args[0].Sym)
			if ins.Op == OpCALL && !helpers[name] {
				continue // Ordinary external calls retain their separate declaration/ABI owner.
			}
			if !valid || offset != 0 || strings.ContainsAny(name, "<>") && !helpers[name] {
				return nil, numericalSBContext("continuation has an unknown/offset/selector terminal")
			}
			if strings.HasSuffix(name, "<>") && !names[name] {
				return nil, numericalSBContext("continuation target lacks its complete original TEXT")
			}
			roles[x86DirectTailPoint{text, ordinal}] = name
		}
	}
	return roles, nil
}

func numericalTypedSourceEntries(file *File, pkg, arch string, role numericalSBSourceRole) (map[string]bool, map[string]bool, error) {
	observed, ordinary, err := numericalTypedSourceDeclarations(file, pkg, arch, role, numericalGoLinknames{}, nil)
	if err != nil {
		return nil, nil, err
	}
	entries, terminals := make(map[string]bool), make(map[string]bool)
	for _, declaration := range observed {
		entries[declaration.local] = true
	}
	for _, declaration := range ordinary {
		terminals[declaration.local] = true
	}
	return entries, terminals, nil
}

// Ordinary terminal callees may have an actual Go body. They remain separate
// declarations, not private continuations. Independently re-typecheck every
// original selected Go file/import and compare both complete language roles
// before deriving its ABI0 layout; a supplied root signature grants nothing.
func (source *GoX86NumericalReadSource) numericalSDKOrdinaryTailDeclarations(ctx context.Context, pkg GoPackage, arch string,
	terminals map[string]numericalSourceDeclaration,
) (map[string]goAMD64FrameDeclaration, error) {
	result := make(map[string]goAMD64FrameDeclaration)
	if len(terminals) == 0 {
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var syntax []*ast.File
	bodyless := make(map[string]bool)
	for _, name := range source.guard.selection.GoFiles {
		filename := filepath.Join(source.request.Directory, name)
		data, err := source.guard.read(filename)
		if err != nil {
			return nil, err
		}
		file, err := parser.ParseFile(fset, filename, data, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		syntax = append(syntax, file)
		for _, declaration := range file.Decls {
			if fn, valid := declaration.(*ast.FuncDecl); valid && fn.Recv == nil && fn.Body == nil {
				bodyless[fn.Name.Name] = true
			}
		}
	}
	imports := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		if mapped, found := source.guard.selection.ImportMap[path]; found {
			path = mapped
		}
		selected, found := source.guard.imports[path]
		if !found || selected.Export == "" {
			return nil, numericalSBContext("ordinary terminal lacks its actual compiler import")
		}
		data, err := source.guard.read(selected.Export)
		return io.NopCloser(bytes.NewReader(data)), err
	})
	sizes := types.SizesFor("gc", arch)
	typed, err := (&types.Config{Sizes: sizes, Importer: imports}).Check(pkg.Path, fset, syntax, nil)
	if err != nil || !reflect.DeepEqual(typed.Scope().Names(), pkg.Types.Scope().Names()) {
		return nil, numericalSBContext("ordinary terminal complete Go declaration graph differs: %v", err)
	}
	names, err := numericalGoDeclarationLinknames(syntax, typed)
	if err != nil {
		return nil, err
	}
	observed, _, err := numericalTypedSourceDeclarations(source.file, pkg.Path, arch, source.role, names, source.native.CompilerAliases)
	if err != nil {
		return nil, err
	}
	for name, declaration := range terminals {
		if original, found := observed[name]; !found || original != declaration {
			return nil, numericalSBContext("original declaration/compiler/native association differs")
		}
	}
	for name, declaration := range terminals {
		local := declaration.local
		actual, found := typed.Scope().Lookup(local).(*types.Func)
		provided, supplied := pkg.Types.Scope().Lookup(local).(*types.Func)
		if !found || !supplied || actual.Pkg() != typed || provided.Pkg() != pkg.Types {
			return nil, numericalSBContext("ordinary terminal lacks an actual source declaration")
		}
		// A selected source TEXT remains bodyless; only an actual ordinary
		// external terminal may have a Go body. Helpers never enter this set.
		if declaration.entry && !bodyless[local] {
			return nil, numericalSBContext("source TEXT lacks its actual bodyless entry declaration")
		}
		arguments := arch == "amd64" && declaration.entry && declaration.abi == 1 &&
			reflect.DeepEqual(source.native.ArgumentRules, amd64GoArgumentCompilerSchema)
		first, err := numericalSDKDeclarationLanguage(actual, sizes, arguments)
		second, priorErr := numericalSDKDeclarationLanguage(provided, sizes, arguments)
		if err != nil || priorErr != nil || first != second {
			return nil, numericalSBContext("ordinary terminal original complete language graph differs")
		}
		if arguments {
			for _, function := range []*types.Func{actual, provided} {
				plan, err := planAMD64GoArguments(function.Type().(*types.Signature))
				if err != nil || plan.requireRegisters() != nil {
					return nil, amd64GoArgumentContext("typed source declaration has unsupported register/stack grouping")
				}
			}
		}
		sig, abiErr := DeriveGoFuncABI0Signature(name, actual, arch, sizes)
		prior, priorABIError := DeriveGoFuncABI0Signature(name, provided, arch, sizes)
		if abiErr != nil || priorABIError != nil || !reflect.DeepEqual(sig, prior) {
			return nil, numericalSBContext("ordinary terminal original language/ABI0 layout differs")
		}
		result[name] = goAMD64FrameDeclaration{signature: sig, transport: goAMD64FrameCompositeTransport, languageType: first}
	}
	return result, ctx.Err()
}

// This is the existing issuer's bounded language comparison, not a source,
// compiler, entry, frame or result-transport certificate.
func numericalSDKDeclarationLanguage(fn *types.Func, sizes types.Sizes, arguments bool) (string, error) {
	sig, valid := fn.Type().(*types.Signature)
	if !valid || sig.Recv() != nil || sig.Variadic() || sig.TypeParams().Len() != 0 {
		return "", numericalSBContext("ordinary terminal is not a monomorphic direct function")
	}
	var value strings.Builder
	resultBuilder := amd64GoArgumentBuilder{sizes: sizes}
	for role, tuple := range []*types.Tuple{sig.Params(), sig.Results()} {
		if tuple.Len() > 4096 {
			return "", numericalSBContext("ordinary terminal tuple bound exceeded")
		}
		value.WriteString("[")
		for index := 0; index < tuple.Len(); index++ {
			var leaf string
			var err error
			if arguments && role == 0 {
				leaf, err = goAMD64LanguageTypeRole(tuple.At(index).Type(), sizes, true, true)
			} else {
				if arguments {
					// The old string adapter samples Underlying. First reject
					// non-source nodes and unresolved alias RHSs without invoking
					// caller callbacks; this layout grants no result transport.
					if _, err := resultBuilder.shape(tuple.At(index).Type(), 0); err != nil {
						return "", err
					}
				}
				// Argument carriers do not extend the old result-language
				// role. Their single integer/I1 result transport is checked
				// independently when the real entry binding is issued.
				leaf, err = numericalTailLanguageType(tuple.At(index).Type(), sizes)
			}
			if err != nil {
				return "", err
			}
			value.WriteString(leaf + ";")
			if value.Len() > 64<<10 {
				return "", numericalSBContext("ordinary terminal language bound exceeded")
			}
		}
		value.WriteString("]")
	}
	return value.String(), nil
}

// The existing Go signature builder transports string as an opaque data
// identity plus numerical length. This source-only comparison does not widen
// the generic frame/native observer or grant pointee/extent/pointer-bit facts.
func numericalTailLanguageType(typ types.Type, sizes types.Sizes) (string, error) {
	if basic, valid := typ.Underlying().(*types.Basic); valid && basic.Kind() == types.String {
		return "string:" + types.TypeString(typ, func(pkg *types.Package) string { return pkg.Path() }), nil
	}
	return goAMD64FrameLanguageTypeRole(typ, sizes, true)
}

func (source *GoX86NumericalReadSource) numericalSourceTextIdentity(ordinal int, fn Func, arch string) (string, uint16, bool) {
	if !strings.HasSuffix(fn.Sym, "<>") {
		return numericalFunctionSourceIdentity(fn.Sym, source.request.PackagePath, arch, source.role)
	}
	joined := source.sdkAssemblyJoin()
	if joined == nil || source.role != numericalSBSDKSource || !x86DirectTailSourceNeeded(source.file) ||
		joined.Observation.Objects == nil || joined.SourceOrdinal < 0 || joined.SourceOrdinal >= len(joined.Observation.Objects.Sources) {
		return "", 0, false
	}
	observed := joined.Observation.Objects.Sources[joined.SourceOrdinal]
	if ordinal < 0 || ordinal >= len(observed.TextOrder) || len(observed.TextOrder) != len(source.file.Funcs) {
		return "", 0, false
	}
	association := observed.TextOrder[ordinal]
	if association.SourceOrdinal != ordinal || association.Namespace != gostaticstorage.TextSymbolSelf || association.ABI != 65535 ||
		association.ObjectOrdinal < 0 || association.ObjectOrdinal >= len(observed.Original.Texts) {
		return "", 0, false
	}
	record := observed.Original.Texts[association.ObjectOrdinal]
	name := numericalNativeName(strings.TrimSuffix(fn.Sym, "<>"), source.request.PackagePath)
	if association.Name != name || record.Name != association.Name || record.ABI != association.ABI || record.Namespace != association.Namespace ||
		record.Relative != association.Relative || record.Index != association.Index ||
		!reflect.DeepEqual(record, observed.Expanded.Texts[association.ObjectOrdinal]) {
		return "", 0, false
	}
	return name, record.ABI, true
}
