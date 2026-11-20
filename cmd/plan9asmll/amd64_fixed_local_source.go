package main

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

type amd64FixedLocalCLISource struct {
	observation *gotoolprofile.AMD64OriginalPackageObservation
	binding     *gotoolprofile.AMD64OriginalFixedLocalBinding
	sdkFrame    *plan9asm.GoAMD64FrameSource
	selection   *x86CallerPackageSelection
	packageData *packages.Package
	target      string
	sources     map[string]string
	downloaded  *amd64FixedLocalDownloadRequest
}

// This records only the explicit invocation identity. The independent download
// observer and object factory, not these fields, establish the source role.
type amd64FixedLocalDownloadRequest struct {
	consumer                            *featureConsumer
	input                               *featureInput
	module, sourceModule, version, root string
}

func (source *amd64FixedLocalCLISource) verify(ctx context.Context) (result error) {
	defer func() {
		if result != nil {
			result = errors.Join(result, source.close())
		}
	}()
	if request := source.downloaded; request != nil {
		input := request.consumer.Input
		if input != request.input || input.Module != request.module ||
			input.SourceModule != request.sourceModule || input.Version != request.version ||
			input.SourceRoot != request.root {
			return fmt.Errorf("%w: fixed-local explicit download identity changed", plan9asm.ErrProbeNeedsContext)
		}
		if err := request.consumer.verifySources(); err != nil {
			return err
		}
	}
	if err := verifyAMD64FixedLocalSelection(source.packageData, source.selection, source.target); err != nil {
		return err
	}
	for name, expected := range source.sources {
		actual, err := gotoolprofile.FileSHA256(name)
		if err != nil || actual != expected {
			return fmt.Errorf("%w: fixed-local actual compiled Go source changed", plan9asm.ErrProbeNeedsContext)
		}
	}
	if source.sdkFrame != nil {
		return source.sdkFrame.Verify(ctx)
	}
	return source.binding.Verify(ctx)
}

func verifyAMD64FixedLocalSelection(pkg *packages.Package, selected *x86CallerPackageSelection, target string) error {
	if pkg == nil || selected == nil || !selected.ready || selected.types != pkg.Types ||
		selected.target != target || pkg.Types == nil || pkg.TypesSizes == nil || pkg.IllTyped || len(pkg.Errors) != 0 ||
		selected.identity == "" || selected.identity != x86CallerSelectionIdentity(pkg, selected.env) ||
		!reflect.DeepEqual(selected.sizes, x86CallerSizes(pkg.TypesSizes)) || len(selected.imports) != len(pkg.Imports) {
		return fmt.Errorf("%w: fixed-local actual-load identity changed", plan9asm.ErrProbeNeedsContext)
	}
	for path, dependency := range pkg.Imports {
		if dependency == nil || dependency.Types == nil || dependency.Types != selected.imports[path] {
			return fmt.Errorf("%w: fixed-local actual-load dependency types changed", plan9asm.ErrProbeNeedsContext)
		}
	}
	return nil
}

// packages.Load intentionally omits syntax for ordinary packages. Read every
// actual compiled Go file only for this candidate; the independent root factory
// typechecks those original bytes against the actual SDK export graph.
func amd64FixedLocalActualSyntax(ctx context.Context, pkg *packages.Package) ([]*ast.File, map[string]string, error) {
	if len(pkg.CompiledGoFiles) == 0 || len(pkg.CompiledGoFiles) > 256 {
		return nil, nil, fmt.Errorf("%w: fixed-local compiled Go inventory is empty or exceeds its bound", plan9asm.ErrProbeNeedsContext)
	}
	set, total := token.NewFileSet(), 0
	var syntax []*ast.File
	sources := make(map[string]string, len(pkg.CompiledGoFiles))
	for _, name := range pkg.CompiledGoFiles {
		if _, duplicate := sources[name]; duplicate {
			return nil, nil, fmt.Errorf("%w: fixed-local duplicate compiled Go source", plan9asm.ErrProbeNeedsContext)
		}
		data, err := x86CallerReadSource(ctx, name, &total)
		if err != nil {
			return nil, nil, err
		}
		file, err := parser.ParseFile(set, name, data, parser.ParseComments)
		if err != nil {
			return nil, nil, err
		}
		syntax = append(syntax, file)
		sources[name] = featureBytesSHA256(data)
	}
	return syntax, sources, nil
}

func (source *amd64FixedLocalCLISource) close() error {
	if source.sdkFrame != nil {
		return source.sdkFrame.Close()
	}
	return source.observation.Close()
}

// Fixed-frame owners independently parse the complete canonical Go CPP output.
// Use that same representation before any signatures or source contracts are
// built, once per candidate file rather than once per function. This preserves
// Raw, DATA and labels in the exact fingerprint; it grants no frame permission.
func parseCompleteCLIAssembly(arch plan9asm.Arch, source string, defines []string, goarch string,
	pkg *plan9asm.GoPackage,
) (*plan9asm.File, error) {
	file, err := plan9asm.ParseWithDefines(arch, source, defines)
	if err != nil || !plan9asm.GoAMD64FixedLocalFrameBindingNeeded(file, goarch) {
		return file, err
	}
	options := plan9asm.AssemblyPreprocessOptions{Defines: defines}
	if pkg != nil {
		// This supplies syntax from the same selected declarations already used
		// by ExpandGoAssemblySource. It does not qualify generated CPP for a
		// frame owner: that owner still verifies its actual source and object.
		options.ReadInclude = func(_ string, name string) (string, []byte, error) {
			if name != "go_asm.h" {
				return "", nil, fmt.Errorf("unresolved active assembly include %q", name)
			}
			header, err := plan9asm.GoAssemblyHeader(*pkg, goarch)
			return "generated/" + pkg.Path + "/go_asm.h", header, err
		}
	}
	expanded, err := plan9asm.PreprocessAssemblySource(source, options)
	if err != nil {
		return nil, fmt.Errorf("fixed-local complete source CPP: %w", err)
	}
	return plan9asm.Parse(arch, expanded)
}

// This complete-file seam precedes splitting. The source-role query supplies
// no permission; the existing independently captured object and numeric-only
// binder must close the full source, source/normalized CFG and every access.
func prepareAMD64FixedLocalSource(pkg *packages.Package, file *plan9asm.File, asm, target, triple, goarch string,
	config compileConfig, resolve func(string) string, sigs, registerFallbacks map[string]plan9asm.FuncSig,
) (_ map[string]plan9asm.FuncSig, _ *amd64FixedLocalCLISource, result error) {
	// This preliminary role query uses only the CLI's package-name mapping.
	// The binding callback runs after source capture: calling it here could
	// mutate an input before the owner records its original identity.
	var queryResolve func(string) string
	if pkg != nil {
		queryResolve = resolveSymFunc(pkg.PkgPath)
	}
	if !plan9asm.GoAMD64FixedLocalFrameBindingNeeded(file, goarch, plan9asm.Options{
		Goarch: goarch, ResolveSym: queryResolve, Sigs: sigs,
	}) {
		return sigs, nil, nil
	}
	selection := config.x86CallerSelections[pkg]
	if err := verifyAMD64FixedLocalSelection(pkg, selection, target); err != nil {
		return nil, nil, err
	}
	ctx := config.Context
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, fmt.Errorf("%w: fixed-local needs a bounded live compilation context", plan9asm.ErrProbeNeedsContext)
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, nil, fmt.Errorf("%w: fixed-local compilation context is unbounded", plan9asm.ErrProbeNeedsContext)
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		return nil, nil, err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return nil, nil, err
	}
	binary, err = sourcepath.Resolve(binary)
	if err != nil {
		return nil, nil, err
	}
	dir, err := sourcepath.Resolve(pkg.Dir)
	if err != nil {
		return nil, nil, err
	}
	actualAsm, err := sourcepath.Resolve(asm)
	if err != nil || filepath.Dir(actualAsm) != dir {
		return nil, nil, fmt.Errorf("%w: fixed-local original assembly origin differs", plan9asm.ErrProbeNeedsContext)
	}
	// Execute with the actual captured effective environment. Deduplication
	// follows exec's last-value rule; no flags, CGO, SDK or cache are replaced.
	values := make(map[string]string)
	for _, item := range selection.env {
		key, value, valid := strings.Cut(item, "=")
		if !valid || key == "" {
			return nil, nil, fmt.Errorf("malformed actual fixed-local environment")
		}
		values[key] = value
	}
	var env []string
	for key, value := range values {
		env = append(env, key+"="+value)
	}
	sort.Strings(env)
	syntax, sources, err := amd64FixedLocalActualSyntax(ctx, pkg)
	if err != nil {
		return nil, nil, err
	}
	original := gotoolprofile.AMD64OriginalObservationRequest{
		GoBinary: binary, Directory: dir, PackagePath: pkg.PkgPath, Target: target, Environment: env,
	}
	// This is only dispatch, not authority: the independent SDK factory must
	// prove the actual compiler's complete physical SDK selection and native
	// frame/source identity. Never infer an owned-main or caller role from it.
	sdkDirectory := filepath.Join(filepath.Dir(filepath.Dir(binary)), "src", filepath.FromSlash(pkg.PkgPath))
	if pkg.Module == nil && dir == sdkDirectory {
		frame, err := plan9asm.CaptureGoAMD64SDKFrameSource(ctx,
			plan9asm.GoPackage{Path: pkg.PkgPath, Types: pkg.Types, Syntax: syntax}, plan9asm.GoAMD64FrameCaptureRequest{
				GoBinary: binary, Directory: dir, AssemblyFile: filepath.Base(actualAsm), Target: target, Environment: env,
			})
		if err != nil {
			return nil, nil, err
		}
		defer func() {
			if result != nil {
				result = errors.Join(result, frame.Close())
			}
		}()
		sigs, err = fixedLocalCapturedSignatures(sigs, registerFallbacks)
		if err != nil {
			return nil, nil, err
		}
		bound, err := frame.BindFixedLocal(ctx, plan9asm.GoPackage{Path: pkg.PkgPath, Types: pkg.Types, Syntax: syntax}, file,
			plan9asm.Options{Goarch: goarch, TargetTriple: triple, ResolveSym: resolve, Sigs: sigs})
		if err != nil {
			return nil, nil, err
		}
		source := &amd64FixedLocalCLISource{sdkFrame: frame, selection: selection, packageData: pkg,
			target: target, sources: sources}
		if err := source.verify(ctx); err != nil {
			return nil, nil, err
		}
		return bound.Sigs, source, nil
	}
	var observed *gotoolprofile.AMD64OriginalPackageObservation
	var downloaded *amd64FixedLocalDownloadRequest
	if consumer := config.Feature; consumer != nil && consumer.Input != nil && consumer.Input.Version != "" {
		if err := consumer.verifySources(); err != nil {
			return nil, nil, err
		}
		input := consumer.Input
		downloaded = &amd64FixedLocalDownloadRequest{consumer: consumer, input: input,
			module: input.Module, sourceModule: input.SourceModule, version: input.Version, root: input.SourceRoot}
		module := input.SourceModule
		if module == "" {
			module = input.Module
		}
		observed, err = gotoolprofile.CaptureAMD64DownloadedPackageObservation(ctx,
			gotoolprofile.AMD64DownloadedObservationRequest{
				Original: original, SourceModule: module, SourceVersion: input.Version,
			}, gotoolprofile.RunBounded)
	} else {
		// In particular, Main=true and an empty version from a cache CWD do
		// not create an owned-source role or infer an exact version.
		observed, err = gotoolprofile.CaptureAMD64OriginalPackageObservation(ctx, original, gotoolprofile.RunBounded)
	}
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if result != nil {
			if err := observed.Close(); err != nil {
				result = errors.Join(result, err)
			}
		}
	}()
	sigs, err = fixedLocalCapturedSignatures(sigs, registerFallbacks)
	if err != nil {
		return nil, nil, err
	}
	bind := observed.BindFixedLocal
	if downloaded != nil {
		bind = observed.BindDownloadedFixedLocal
	}
	bound, binding, err := bind(ctx,
		plan9asm.GoPackage{Path: pkg.PkgPath, Types: pkg.Types, Syntax: syntax}, file, filepath.Base(actualAsm),
		plan9asm.Options{Goarch: goarch, TargetTriple: triple, ResolveSym: resolve, Sigs: sigs})
	if err != nil {
		return nil, nil, err
	}
	source := &amd64FixedLocalCLISource{
		observation: observed, binding: binding, selection: selection, packageData: pkg,
		target: target, sources: sources, downloaded: downloaded,
	}
	if err := source.verify(ctx); err != nil {
		return nil, nil, err
	}
	return bound.Sigs, source, nil
}

// Only after actual source capture may this CLI discard its own unchanged
// register-only guesses. Actual declarations and every unrecorded signature
// remain intact; the public binder still rejects supplied private helper ABIs.
func fixedLocalCapturedSignatures(sigs, registerFallbacks map[string]plan9asm.FuncSig) (map[string]plan9asm.FuncSig, error) {
	if len(registerFallbacks) == 0 {
		return sigs, nil
	}
	for name, original := range registerFallbacks {
		current, present := sigs[name]
		if !present || !reflect.DeepEqual(current, original) {
			return nil, fmt.Errorf("%w: CLI inferred entry changed before original frame binding", plan9asm.ErrProbeNeedsContext)
		}
	}
	declared := make(map[string]plan9asm.FuncSig, len(sigs)-len(registerFallbacks))
	for name, sig := range sigs {
		if _, inferred := registerFallbacks[name]; !inferred {
			declared[name] = sig
		}
	}
	return declared, nil
}
