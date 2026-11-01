package main

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

// This attempt-local reader owns declarations, not native storage or a second
// package selection. packages.Load's actual types and source lists stay intact.
// The GoModule frontend alone decides whether an instruction may read them.
type ordinaryDeclarationSource struct {
	pkg        plan9asm.GoPackage
	file       *plan9asm.File
	source     []byte
	target     string
	selected   map[*packages.Package]*x86CallerPackageSelection
	snapshot   *gooriginalsrc.Snapshot
	identities map[string]os.FileInfo
	bytes      int64
	sizes      types.Sizes
}

// This is only a cost query: a real variable mentioned by an SB operand makes
// its complete declaration source worth reading. It does not duplicate the
// translator's operand grammar, access widths, or imported-CMP-only admission.
func ordinaryDeclarationCandidates(pkg *packages.Package, file *plan9asm.File) map[string]*packages.Package {
	result := make(map[string]*packages.Package)
	if pkg == nil || pkg.Types == nil || file == nil {
		return result
	}
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			for _, operand := range instruction.Args {
				symbol := operand.Sym
				if operand.Kind == plan9asm.OpMem {
					symbol = operand.Mem.Sym
				}
				if !strings.HasSuffix(symbol, "(SB)") {
					continue
				}
				symbol = strings.TrimSuffix(symbol, "(SB)")
				symbol = strings.ReplaceAll(strings.ReplaceAll(symbol, "∕", "/"), "·", ".")
				separator := strings.LastIndexByte(symbol, '.')
				path, name := "", symbol
				if separator >= 0 {
					path, name = symbol[:separator], symbol[separator+1:]
				}
				// Displacements belong to the identifier tail, not a module path
				// which may itself contain '+' or '-'. Full validation stays below.
				if index := strings.IndexAny(name, "+-"); index >= 0 {
					name = name[:index]
				}
				owner := pkg
				if path != "" && path != pkg.PkgPath && path != pkg.Types.Path() {
					owner = pkg.Imports[path]
				}
				if owner == nil || owner.Types == nil || owner.Types.Scope() == nil || !token.IsIdentifier(name) {
					continue
				}
				if variable, ok := owner.Types.Scope().Lookup(name).(*types.Var); ok && !variable.IsField() && variable.Pkg() == owner.Types {
					if owner == pkg {
						path = ""
					}
					result[path] = owner
				}
			}
		}
	}
	return result
}

func captureOrdinaryDeclarations(pkg *packages.Package, file *plan9asm.File, source []byte,
	reads *plan9asm.GoAssemblySourceReadReport, goos, goarch string, config compileConfig,
) (_ *ordinaryDeclarationSource, captureErr error) {
	if goarch != "386" && goarch != "amd64" {
		return nil, nil
	}
	candidates := ordinaryDeclarationCandidates(pkg, file)
	if len(candidates) == 0 {
		return nil, nil
	}
	ctx, target := config.Context, goos+"/"+goarch
	if ctx == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("ordinary declaration reader needs a live bounded context")
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, fmt.Errorf("ordinary declaration reader needs a bounded context")
	}
	selection := config.x86CallerSelections[pkg]
	if err := verifyAMD64FixedLocalSelection(pkg, selection, target); err != nil {
		return nil, err
	}
	// Read the complete current package and only referenced direct imports. The
	// real dependency export graph is reused, never reloaded or replaced.
	candidates[""] = pkg
	paths := make([]string, 0, len(candidates))
	for path := range candidates {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	owners := make([]*packages.Package, 0, len(paths))
	for _, path := range paths {
		owners = append(owners, candidates[path])
	}
	actual := &ordinaryDeclarationSource{
		pkg: plan9asm.GoPackage{Path: pkg.PkgPath, Types: pkg.Types,
			Imports: make(map[string]*types.Package), ImportSyntax: make(map[string][]*ast.File)},
		file: file, source: append([]byte(nil), source...), target: target,
		sizes:    pkg.TypesSizes,
		selected: captureX86CallerSelectionsInEnvironment(owners, target, selection.env),
		snapshot: gooriginalsrc.NewSnapshot(), identities: make(map[string]os.FileInfo),
	}
	// Keep the original load-bound selection, not a fresh copy of the caller.
	actual.selected[pkg] = selection
	defer func() {
		if captureErr != nil {
			actual.close()
		}
	}()
	for path, dependency := range pkg.Imports {
		if dependency != nil {
			actual.pkg.Imports[path] = dependency.Types
		}
	}
	if reads == nil || len(reads.Inputs) == 0 {
		return nil, fmt.Errorf("ordinary declarations lack the complete original assembly read inventory")
	}
	for name, digest := range reads.Inputs {
		if err := actual.retain(name); err != nil {
			return nil, err
		}
		if actual.snapshot.View().Hashes[name] != digest {
			return nil, fmt.Errorf("original assembly/header changed before declaration capture")
		}
	}
	set, total := token.NewFileSet(), 0
	for _, path := range paths {
		owner := candidates[path]
		if err := verifyAMD64FixedLocalSelection(owner, actual.selected[owner], target); err != nil {
			return nil, err
		}
		if len(owner.CompiledGoFiles) == 0 || len(owner.CompiledGoFiles) > 256-total {
			return nil, fmt.Errorf("ordinary declaration source inventory exceeds its shared 256-file bound")
		}
		total += len(owner.CompiledGoFiles)
		if err := actual.snapshot.Directory(owner.Dir, false); err != nil {
			return nil, err
		}
		var syntax []*ast.File
		seen := make(map[string]bool)
		for _, name := range owner.CompiledGoFiles {
			if seen[name] {
				return nil, fmt.Errorf("duplicate selected ordinary declaration source")
			}
			seen[name] = true
			if err := actual.retain(name); err != nil {
				return nil, err
			}
			data, err := actual.snapshot.ReadRetained(name)
			if err != nil {
				return nil, err
			}
			parsed, err := parser.ParseFile(set, name, data, parser.ParseComments)
			if err != nil {
				return nil, err
			}
			syntax = append(syntax, parsed)
		}
		if path == "" {
			actual.pkg.Syntax = syntax
		} else {
			actual.pkg.ImportSyntax[path] = syntax
		}
	}
	if err := actual.verify(ctx); err != nil {
		return nil, err
	}
	return actual, nil
}

func (source *ordinaryDeclarationSource) retain(name string) error {
	info, err := sourcepath.Lstat(name)
	if err != nil {
		return err
	}
	if source.identities[name] == nil && (info.Size() < 0 || info.Size() > 64<<20-source.bytes) {
		return fmt.Errorf("ordinary declaration source exceeds its shared 64 MiB bound")
	}
	if err := source.snapshot.Retain(name); err != nil {
		return err
	}
	if source.identities[name] == nil {
		source.bytes += info.Size()
	}
	source.identities[name] = info
	return nil
}

func (source *ordinaryDeclarationSource) verify(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || source.snapshot == nil {
		return fmt.Errorf("ordinary declaration source expired or closed")
	}
	for pkg, selection := range source.selected {
		if err := verifyAMD64FixedLocalSelection(pkg, selection, source.target); err != nil {
			return err
		}
	}
	for name, before := range source.identities {
		after, err := sourcepath.Lstat(name)
		if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() ||
			before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			return fmt.Errorf("ordinary declaration source identity changed: %s", filepath.Base(name))
		}
	}
	return source.snapshot.Verify()
}

func (source *ordinaryDeclarationSource) translate(ctx llvm.Context, file *plan9asm.File, triple, arch string,
	annotate bool, resolve func(string) string,
) (llvm.Module, error) {
	if file != source.file {
		return llvm.Module{}, fmt.Errorf("ordinary declaration source cannot be split or substituted")
	}
	goos, _, _ := strings.Cut(source.target, "/")
	result, err := plan9asm.TranslateGoModuleInContext(ctx, source.pkg, source.source, plan9asm.GoModuleOptions{
		GOOS: goos, GOARCH: arch, Sizes: source.sizes, TargetTriple: triple,
		ResolveSym: resolve, AnnotateSource: annotate,
	})
	if err != nil {
		return llvm.Module{}, err
	}
	// The API above receives the complete immutable source, without KeepFunc.
	// It audits private tails before coalescing them into public entry bodies;
	// those source nodes intentionally have no callable/metadata entry. Public
	// metadata is therefore not a count of consumed original TEXTs. Check only
	// its namespace/uniqueness here, not the library's private source authority.
	original, seen := make(map[string]bool), make(map[string]bool)
	for _, function := range file.Funcs {
		original[function.Sym] = true
	}
	for _, function := range result.Functions {
		if !original[function.TextSymbol] || seen[function.TextSymbol] {
			result.Module.Dispose()
			return llvm.Module{}, fmt.Errorf("ordinary GoModule returned a foreign or duplicate public TEXT entry")
		}
		seen[function.TextSymbol] = true
	}
	return result.Module, nil
}

func (source *ordinaryDeclarationSource) close() {
	*source = ordinaryDeclarationSource{}
}
