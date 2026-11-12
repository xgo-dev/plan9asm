package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

// Reuse the immutable actual-load inventory, not the x86 caller permission.
// Only a genuinely consumed ABI0 private tail needs this second typed graph.
type arm64ABI0TailTypedSource struct {
	original  *packages.Package
	actual    *packages.Package
	selection *x86CallerPackageSelection
	goPackage plan9asm.GoPackage
	sources   map[string]string
	asm       string
	expanded  string
	member    *actualAssemblyMember
}

func (source *arm64ABI0TailTypedSource) verify(ctx context.Context, defines []string, feature *featureConsumer) (result error) {
	if err := source.member.verify(); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, source.member.verify()) }()
	selection, pkg := source.selection, source.original
	if selection == nil || selection.identity == "" || selection.identity != x86CallerSelectionIdentity(pkg, selection.env) ||
		selection.types != pkg.Types || !reflect.DeepEqual(selection.sizes, x86CallerSizes(pkg.TypesSizes)) ||
		len(selection.imports) != len(pkg.Imports) {
		return fmt.Errorf("%w: ABI0 continuation changed its actual-load selection/layout", plan9asm.ErrProbeNeedsContext)
	}
	for path, dependency := range pkg.Imports {
		if dependency == nil || dependency.Types != selection.imports[path] {
			return fmt.Errorf("%w: ABI0 continuation changed actual dependency types", plan9asm.ErrProbeNeedsContext)
		}
	}
	if err := selection.verifyEffectiveSourceMode(ctx); err != nil {
		return err
	}
	for filename, expected := range source.sources {
		if err := ctx.Err(); err != nil {
			return err
		}
		actual, err := gotoolprofile.FileSHA256(filename)
		if err != nil || actual != expected {
			return fmt.Errorf("%w: ABI0 continuation changed actual selected source bytes", plan9asm.ErrProbeNeedsContext)
		}
	}
	var expanded []byte
	var err error
	if feature != nil {
		expanded, _, err = feature.preprocessCPP(source.asm, pkg.PkgPath, defines)
	} else {
		expanded, err = readAsmSource(source.asm, asmSourceRoot(pkg, source.asm))
	}
	if err != nil {
		return err
	}
	expanded = plan9asm.ExpandGoAssemblySource(source.goPackage, expanded, "arm64")
	if featureBytesSHA256(expanded) != source.expanded {
		return fmt.Errorf("%w: ABI0 continuation changed original CPP/typed expansion", plan9asm.ErrProbeNeedsContext)
	}
	return nil
}

func loadARM64ABI0TailSource(pkg *packages.Package, asm string, expanded []byte,
	target string, defines []string, config compileConfig,
) (*arm64ABI0TailTypedSource, error) {
	selection := config.x86CallerSelections[pkg]
	if pkg == nil || selection == nil || !selection.ready || selection.target != target ||
		pkg.Types == nil || pkg.TypesSizes == nil || pkg.IllTyped || len(pkg.Errors) != 0 ||
		len(pkg.CompiledGoFiles) == 0 || len(pkg.CompiledGoFiles) > 256 || len(pkg.OtherFiles) > 512 {
		return nil, fmt.Errorf("%w: ABI0 continuation needs complete actual ordinary source selection", plan9asm.ErrProbeNeedsContext)
	}
	ctx := config.Context
	if ctx == nil {
		ctx = context.Background()
	}
	source := &arm64ABI0TailTypedSource{
		original: pkg, selection: selection, sources: make(map[string]string),
		asm: asm, expanded: featureBytesSHA256(expanded),
	}
	member, err := observeActualAssemblyMember(asm, pkg.OtherFiles)
	if err != nil {
		return nil, fmt.Errorf("%w: ABI0 tail assembly is absent from actual Go selection: %v", plan9asm.ErrProbeNeedsContext, err)
	}
	source.member = member
	if err := selection.verifyEffectiveSourceMode(ctx); err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	info := &types.Info{Defs: make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object),
		Types: make(map[ast.Expr]types.TypeAndValue)}
	selectionSource := &plan9asm.GoSourceSelection{
		Fset: fset, TypesInfo: info, Sizes: pkg.TypesSizes,
		SelectedGoFiles: append([]string(nil), pkg.CompiledGoFiles...), GoSources: make(map[string][]byte),
	}
	var syntax []*ast.File
	total := 0
	for _, filename := range pkg.CompiledGoFiles {
		if selectionSource.GoSources[filename] != nil {
			return nil, fmt.Errorf("%w: duplicate actual ABI0 Go source", plan9asm.ErrProbeNeedsContext)
		}
		data, err := x86CallerReadSource(ctx, filename, &total)
		if err != nil {
			return nil, err
		}
		parsed, err := parser.ParseFile(fset, filename, data, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		syntax = append(syntax, parsed)
		selectionSource.GoSources[filename] = data
		source.sources[filename] = featureBytesSHA256(data)
	}
	selectedAsm := false
	for _, filename := range pkg.OtherFiles {
		if filepath.Ext(filename) != ".s" && filepath.Ext(filename) != ".h" {
			return nil, fmt.Errorf("%w: ABI0 continuation has an unbound native source role", plan9asm.ErrProbeNeedsContext)
		}
		if _, duplicate := source.sources[filename]; duplicate {
			return nil, fmt.Errorf("%w: duplicate actual ABI0 native source", plan9asm.ErrProbeNeedsContext)
		}
		data, err := x86CallerReadSource(ctx, filename, &total)
		if err != nil {
			return nil, err
		}
		source.sources[filename] = featureBytesSHA256(data)
		selectedAsm = selectedAsm || filename == member.selected && filepath.Ext(filename) == ".s"
	}
	if !selectedAsm {
		return nil, fmt.Errorf("%w: ABI0 tail assembly is absent from actual Go selection", plan9asm.ErrProbeNeedsContext)
	}
	typeConfig := types.Config{
		Importer: x86CallerActualImports(pkg.Imports), Sizes: pkg.TypesSizes, GoVersion: pkg.Types.GoVersion(),
	}
	typed, err := typeConfig.Check(pkg.PkgPath, fset, syntax, info)
	if err != nil {
		return nil, fmt.Errorf("actual selected ABI0 declaration recheck: %w", err)
	}
	copyPackage := *pkg
	copyPackage.Types, copyPackage.Syntax, copyPackage.Fset, copyPackage.TypesInfo = typed, syntax, fset, info
	source.actual = &copyPackage
	imports := make(map[string]*types.Package, len(pkg.Imports))
	for path, dependency := range pkg.Imports {
		imports[path] = dependency.Types
	}
	source.goPackage = plan9asm.GoPackage{
		Path: typed.Path(), Types: typed, Imports: imports, Syntax: syntax, SourceSelection: selectionSource,
	}
	if err := source.verify(ctx, defines, config.Feature); err != nil {
		return nil, err
	}
	return source, nil
}

func prepareARM64ABI0TailSource(pkg *packages.Package, file *plan9asm.File, asm string, expanded []byte,
	target string, defines []string, config compileConfig, resolve func(string) string,
) (*plan9asm.File, *arm64ABI0TailTypedSource, map[string]plan9asm.FuncSig, error) {
	if !plan9asm.GoARM64ABI0TailDeclarationBindingNeeded(file) {
		prepared, err := plan9asm.CoalesceARM64PrivateRegisterHelpers(file)
		return prepared, nil, nil, err
	}
	source, err := loadARM64ABI0TailSource(pkg, asm, expanded, target, defines, config)
	if err != nil {
		return nil, nil, nil, err
	}
	declared := make(map[string]plan9asm.FuncSig)
	for _, fn := range file.Funcs {
		if !strings.HasPrefix(fn.Sym, "·") || strings.Contains(fn.Sym, "<") {
			continue
		}
		name := resolve(stripABISuffix(fn.Sym))
		sig, _, present, err := tryDeclSig(source.actual.Types.Scope(), fn.Sym, name, nil, "arm64", source.actual.TypesSizes, false)
		if err != nil {
			return nil, nil, nil, err
		}
		if present {
			declared[name] = sig
		}
	}
	bound, err := plan9asm.BindGoARM64ABI0TailDeclarations(source.goPackage, file, resolve, declared)
	if err != nil {
		return nil, nil, nil, err
	}
	prepared, err := plan9asm.PrepareGoARM64ABI0TailContinuations(file, bound, resolve)
	return prepared, source, bound, err
}

// Compare the complete public transport before retaining the actual Binder.
// Serialization is only an equality projection; it never restores a token.
func rebindARM64ABI0TailSignatures(sigs, bound map[string]plan9asm.FuncSig) error {
	for name, previous := range bound {
		current, present := sigs[name]
		if !present {
			continue // Removed helpers do not gain a signature or external entry.
		}
		before, beforeErr := json.Marshal(previous)
		after, afterErr := json.Marshal(current)
		if beforeErr != nil || afterErr != nil || !bytes.Equal(before, after) {
			return fmt.Errorf("%w: ABI0 continuation changed its complete typed transport", plan9asm.ErrProbeNeedsContext)
		}
		sigs[name] = previous
	}
	return nil
}
