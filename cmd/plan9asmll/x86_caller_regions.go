package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

// Created only at the actual packages.Load boundary, never decoded from JSON.
// Non-candidates retain names/layout only, not transitive syntax graphs.
type x86CallerPackageSelection struct {
	identity string
	target   string
	types    *types.Package
	sizes    []int64
	imports  map[string]*types.Package
	env      []string
	ready    bool
	loaded   *x86CallerTypedPackage
	mode     *string
}

type x86CallerTypedPackage struct {
	pkg       *packages.Package
	goPkg     plan9asm.GoPackage
	sources   map[string]string
	expanded  map[string]string
	selection *x86CallerPackageSelection
	member    *actualAssemblyMember
}

func x86CallerSelectionIdentity(pkg *packages.Package, environment []string) string {
	canonical := func(files []string) []string {
		result := append([]string(nil), files...)
		sort.Strings(result)
		return result
	}
	selection := generatedHeaderLoadSelection{
		Name: pkg.Name, PackagePath: pkg.PkgPath, Module: pkg.Module,
		GoFiles: canonical(pkg.GoFiles), CompiledGoFiles: canonical(pkg.CompiledGoFiles),
		OtherFiles: canonical(pkg.OtherFiles), Imports: make(map[string]string),
	}
	for name, dep := range pkg.Imports {
		if dep == nil {
			return ""
		}
		selection.Imports[name] = dep.PkgPath
	}
	// Preserve the exact ordered load environment, including duplicate keys.
	// A later profile/flag edit cannot borrow the original selected types/files.
	encoded, err := json.Marshal(struct {
		ID          string
		Dir         string
		Selection   generatedHeaderLoadSelection
		Environment []string
	}{ID: pkg.ID, Dir: pkg.Dir, Selection: selection, Environment: environment})
	if err != nil {
		return ""
	}
	return featureBytesSHA256(encoded)
}

func x86CallerSizes(sizes types.Sizes) []int64 {
	if sizes == nil {
		return nil
	}
	var values []int64
	for _, kind := range []types.BasicKind{
		types.UnsafePointer, types.Int8, types.Uint8, types.Int16, types.Uint16,
		types.Int32, types.Uint32, types.Int64, types.Uint64, types.Int, types.Uint,
		types.Float32, types.Float64,
	} {
		values = append(values, sizes.Sizeof(types.Typ[kind]))
	}
	return values
}

func captureX86CallerSelections(pkgs []*packages.Package, target string, feature *featureConsumer) map[*packages.Package]*x86CallerPackageSelection {
	env := append([]string(nil), os.Environ()...)
	goos, goarch, _ := strings.Cut(target, "/")
	env = append(env, "GOOS="+goos, "GOARCH="+goarch)
	if feature != nil {
		env = append([]string(nil), feature.Env...)
	}
	return captureX86CallerSelectionsInEnvironment(pkgs, target, env)
}

func captureX86CallerSelectionsInEnvironment(pkgs []*packages.Package, target string, environment []string) map[*packages.Package]*x86CallerPackageSelection {
	result := make(map[*packages.Package]*x86CallerPackageSelection, len(pkgs))
	env := append([]string(nil), environment...)
	var goFlags, driver string
	for _, value := range env {
		if strings.HasPrefix(value, "GOFLAGS=") {
			goFlags = strings.TrimPrefix(value, "GOFLAGS=")
		}
		if strings.HasPrefix(value, "GOPACKAGESDRIVER=") {
			driver = strings.TrimPrefix(value, "GOPACKAGESDRIVER=")
		}
	}
	defaultDriver := false
	if driver == "" {
		_, err := exec.LookPath("gopackagesdriver")
		defaultDriver = err == nil
	}
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		// Effective overlays/generated/cgo sources need their own mapping.
		// Reading original paths may not silently impersonate compiled bytes.
		ready := !isTestVariantPackage(pkg) && !strings.Contains(goFlags, "-overlay") &&
			(driver == "" || driver == "off") && !defaultDriver && len(pkg.CompiledGoFiles) != 0 &&
			reflect.DeepEqual(pkg.GoFiles, pkg.CompiledGoFiles)
		imports := make(map[string]*types.Package, len(pkg.Imports))
		for path, dependency := range pkg.Imports {
			if dependency != nil {
				imports[path] = dependency.Types
			}
		}
		result[pkg] = &x86CallerPackageSelection{
			identity: x86CallerSelectionIdentity(pkg, env), target: target,
			types: pkg.Types, sizes: x86CallerSizes(pkg.TypesSizes),
			imports: imports, env: env, ready: ready,
		}
	}
	return result
}

func (selection *x86CallerPackageSelection) verifyEffectiveSourceMode(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	stdout, stderr, err := gotoolprofile.RunBounded(ctx, "", selection.env, "go", "env", "-json", "GOFLAGS")
	if err != nil || len(stderr) != 0 {
		return fmt.Errorf("observe actual caller source mode: %v (stderr: %s)", err, stderr)
	}
	var actual struct {
		GoFlags string `json:"GOFLAGS"`
	}
	if err := json.Unmarshal(stdout, &actual); err != nil {
		return fmt.Errorf("decode actual caller source mode: %w", err)
	}
	if strings.Contains(actual.GoFlags, "-overlay") {
		return fmt.Errorf("%w: effective overlay bytes require their actual source mapping", plan9asm.ErrProbeNeedsContext)
	}
	if selection.mode != nil && *selection.mode != actual.GoFlags {
		return fmt.Errorf("%w: effective Go source flags changed after actual selection", plan9asm.ErrProbeNeedsContext)
	}
	selection.mode = &actual.GoFlags
	return nil
}

type x86CallerActualImports map[string]*packages.Package

func (imports x86CallerActualImports) Import(path string) (*types.Package, error) {
	if path == "unsafe" {
		return types.Unsafe, nil
	}
	pkg := imports[path]
	if pkg == nil || pkg.Types == nil || !pkg.Types.Complete() {
		return nil, fmt.Errorf("caller recheck has no actual selected dependency types: %s", path)
	}
	return pkg.Types, nil
}

func x86CallerReadSource(ctx context.Context, filename string, total *int) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	info, err := os.Stat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return nil, fmt.Errorf("caller source must be a bounded regular file: %s", filename)
	}
	reader, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(reader, 64<<20+1))
	closeErr := reader.Close()
	*total += len(data)
	if readErr != nil || closeErr != nil || *total > 64<<20 {
		return nil, fmt.Errorf("caller source read exceeded its bound: %v (close: %v)", readErr, closeErr)
	}
	return data, nil
}

func x86CallerAssemblySource(pkg *packages.Package, asm string, defines []string, feature *featureConsumer) ([]byte, error) {
	var source []byte
	var err error
	if feature != nil {
		source, _, err = feature.preprocessCallerCPP(asm, pkg.PkgPath, defines)
	} else {
		source, err = readAsmSource(asm, asmSourceRoot(pkg, asm))
	}
	if err != nil {
		return nil, err
	}
	imports := make(map[string]*types.Package, len(pkg.Imports))
	for path, imported := range pkg.Imports {
		if imported != nil {
			imports[path] = imported.Types
		}
	}
	return plan9asm.ExpandGoAssemblySource(plan9asm.GoPackage{
		Path: pkg.PkgPath, Types: pkg.Types, Imports: imports,
	}, source, "amd64"), nil
}

func loadX86CallerTypedPackage(ctx context.Context, pkg *packages.Package, defines []string, feature *featureConsumer) (*x86CallerTypedPackage, error) {
	if pkg.Types == nil || pkg.TypesSizes == nil || pkg.IllTyped || len(pkg.Errors) != 0 ||
		len(pkg.CompiledGoFiles) > 256 || len(pkg.OtherFiles) > 512 {
		return nil, fmt.Errorf("caller package lacks complete actual types/layout or exceeds its source bound")
	}
	loaded := &x86CallerTypedPackage{
		sources: make(map[string]string), expanded: make(map[string]string),
	}
	fset := token.NewFileSet()
	var syntax []*ast.File
	selected := &plan9asm.GoSourceSelection{
		Fset: fset, Sizes: pkg.TypesSizes,
		SelectedGoFiles: append([]string(nil), pkg.CompiledGoFiles...),
		GoSources:       make(map[string][]byte), Assembly: make(map[string]*plan9asm.File),
		TypesInfo: &types.Info{
			Types: make(map[ast.Expr]types.TypeAndValue),
			Defs:  make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object),
		},
	}
	total := 0
	for _, filename := range selected.SelectedGoFiles {
		if selected.GoSources[filename] != nil {
			return nil, fmt.Errorf("duplicate actual compiled Go source")
		}
		source, err := x86CallerReadSource(ctx, filename, &total)
		if err != nil {
			return nil, err
		}
		parsed, err := parser.ParseFile(fset, filename, source, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		syntax = append(syntax, parsed)
		selected.GoSources[filename] = source
		loaded.sources[filename] = featureBytesSHA256(source)
	}
	config := types.Config{
		Importer: x86CallerActualImports(pkg.Imports), Sizes: pkg.TypesSizes,
		GoVersion: pkg.Types.GoVersion(),
	}
	typed, err := config.Check(pkg.PkgPath, fset, syntax, selected.TypesInfo)
	if err != nil {
		return nil, fmt.Errorf("actual selected caller source recheck: %w", err)
	}
	copyPkg := *pkg
	copyPkg.Types, copyPkg.Syntax, copyPkg.Fset, copyPkg.TypesInfo = typed, syntax, fset, selected.TypesInfo
	loaded.pkg = &copyPkg
	loaded.goPkg = plan9asm.GoPackage{
		Path: pkg.PkgPath, Types: typed, Syntax: syntax, SourceSelection: selected,
	}
	for _, filename := range pkg.OtherFiles {
		if filepath.Ext(filename) == ".h" {
			raw, err := x86CallerReadSource(ctx, filename, &total)
			if err != nil {
				return nil, err
			}
			loaded.sources[filename] = featureBytesSHA256(raw)
			continue // Headers have CPP origin, never a Go/ASM declaration role.
		}
		if filepath.Ext(filename) != ".s" || selected.Assembly[filename] != nil {
			return nil, fmt.Errorf("caller closure has unknown native sources or duplicate assembly")
		}
		raw, err := x86CallerReadSource(ctx, filename, &total)
		if err != nil {
			return nil, err
		}
		source, err := x86CallerAssemblySource(loaded.pkg, filename, defines, feature)
		if err != nil || len(source) > 64<<20 {
			return nil, fmt.Errorf("actual caller assembly expansion: %v", err)
		}
		file, err := plan9asm.ParseWithDefines(plan9asm.ArchAMD64, string(source), defines)
		if len(raw) == 0 {
			file, err = &plan9asm.File{Arch: plan9asm.ArchAMD64}, nil
		}
		if err != nil {
			return nil, fmt.Errorf("actual caller assembly registration: %w", err)
		}
		selected.SelectedAssemblyFiles = append(selected.SelectedAssemblyFiles, filename)
		selected.Assembly[filename] = file
		loaded.sources[filename] = featureBytesSHA256(raw)
		loaded.expanded[filename] = featureBytesSHA256(source)
	}
	return loaded, nil
}

func (loaded *x86CallerTypedPackage) verify(ctx context.Context, defines []string, feature *featureConsumer) (result error) {
	if err := loaded.member.verify(); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, loaded.member.verify()) }()
	if loaded.selection != nil {
		if err := loaded.selection.verifyEffectiveSourceMode(ctx); err != nil {
			return err
		}
	}
	for filename, expected := range loaded.sources {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		actual, err := gotoolprofile.FileSHA256(filename)
		if err != nil || actual != expected {
			return fmt.Errorf("actual caller source changed before final object: %s", filename)
		}
	}
	for filename, expected := range loaded.expanded {
		source, err := x86CallerAssemblySource(loaded.pkg, filename, defines, feature)
		if err != nil || featureBytesSHA256(source) != expected {
			return fmt.Errorf("actual caller CPP/typed assembly changed before final object: %s", filename)
		}
	}
	return nil
}

func bindX86CallerRegions(pkg *packages.Package, file *plan9asm.File, target, goarch, asm string, defines []string,
	config compileConfig, resolve func(string) string, sigs map[string]plan9asm.FuncSig,
) (map[string]plan9asm.FuncSig, *x86CallerTypedPackage, error) {
	if !plan9asm.GoX86RawReturnCallerBindingNeeded(file, goarch, resolve, sigs) {
		return sigs, nil, nil
	}
	loaded, err := loadX86ActualSelectedAssembly(pkg, target, asm, defines, config)
	if err != nil {
		return nil, nil, err
	}
	actual, _, err := sigsForAsmFile(loaded.pkg, file, resolve, "amd64")
	if err != nil {
		return nil, nil, err
	}
	for name, previous := range sigs {
		if current, exists := actual[name]; !exists || !reflect.DeepEqual(previous, current) {
			return nil, nil, fmt.Errorf("%w: caller signatures differ from same-source typed recheck", plan9asm.ErrProbeNeedsContext)
		}
	}
	bound, err := plan9asm.BindGoX86RawReturnCallerRegions(loaded.goPkg, file, "amd64", resolve, actual)
	return bound, loaded, err
}

// This is a source observation only. The caller binder and continuation
// reference closure independently choose and prove their body permissions.
func loadX86ActualSelectedAssembly(pkg *packages.Package, target, asm string, defines []string,
	config compileConfig,
) (*x86CallerTypedPackage, error) {
	selection := config.x86CallerSelections[pkg]
	if pkg == nil || selection == nil || !selection.ready || selection.target != target || selection.identity == "" ||
		selection.types != pkg.Types || selection.identity != x86CallerSelectionIdentity(pkg, selection.env) ||
		!reflect.DeepEqual(selection.sizes, x86CallerSizes(pkg.TypesSizes)) {
		return nil, fmt.Errorf("%w: proof needs unchanged actual-load source role, inventory and layout", plan9asm.ErrProbeNeedsContext)
	}
	for path, dependency := range pkg.Imports {
		if dependency == nil || dependency.Types != selection.imports[path] {
			return nil, fmt.Errorf("%w: dependency types differ from actual load", plan9asm.ErrProbeNeedsContext)
		}
	}
	ctx := config.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if selection.loaded == nil {
		if err := selection.verifyEffectiveSourceMode(ctx); err != nil {
			return nil, err
		}
		var err error
		selection.loaded, err = loadX86CallerTypedPackage(ctx, pkg, defines, config.Feature)
		if err != nil {
			return nil, err
		}
		selection.loaded.selection = selection
	}
	member, err := observeActualAssemblyMember(asm, selection.loaded.goPkg.SourceSelection.SelectedAssemblyFiles)
	if err != nil || selection.loaded.goPkg.SourceSelection.Assembly[member.selected] == nil {
		return nil, fmt.Errorf("%w: translated assembly is absent from actual complete selection: %v", plan9asm.ErrProbeNeedsContext, err)
	}
	// The complete typed graph is cached, but each returned source keeps its
	// own original request/lifetime. No alias is added to the actual inventory
	// or accumulated in an unbounded shared cache.
	loaded := &x86CallerTypedPackage{
		pkg: selection.loaded.pkg, goPkg: selection.loaded.goPkg,
		sources: selection.loaded.sources, expanded: selection.loaded.expanded,
		selection: selection, member: member,
	}
	if err := loaded.verify(ctx, defines, config.Feature); err != nil {
		return nil, err
	}
	return loaded, nil
}
