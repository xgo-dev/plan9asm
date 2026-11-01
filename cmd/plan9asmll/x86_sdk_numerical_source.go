package main

import (
	"context"
	"errors"
	"fmt"
	"go/types"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sdkfrontend"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

// This adapter owns one complete-file observation. It never reconstructs a
// permission from the diagnostic readback and never lends it to file chunks.
type x86SDKNumericalCLISource struct {
	frontend  *sdkfrontend.Source
	selected  *x86CallerPackageSelection
	pkg       *packages.Package
	goPackage plan9asm.GoPackage
	target    string
	sources   map[string]string
	cleanup   []func() error
	original  *packages.Package
	origin    *x86CallerPackageSelection
}

type x86SDKNumericalRetryError struct{ cause error }

func (err *x86SDKNumericalRetryError) Error() string { return err.cause.Error() }
func (err *x86SDKNumericalRetryError) Unwrap() error { return err.cause }

// The independent SDK binder pins native object names, including private <>
// suffixes. Ordinary CLI $local aliases remain unchanged outside this exact
// observed complete-file route. This mapping grants no storage/read identity.
func (source *x86SDKNumericalCLISource) resolve(symbol string) string {
	return sdkfrontend.Resolve(source.pkg.PkgPath, symbol)
}

// Deferred source guards may join another error after translation. Such a
// failure is authoritative: retry must never hide it behind a new source load.
func x86SDKNumericalRetryCause(err error) (error, bool) {
	switch value := err.(type) {
	case *x86SDKNumericalRetryError:
		return value.cause, true
	case interface{ Unwrap() []error }:
		children := value.Unwrap()
		if len(children) == 1 {
			return x86SDKNumericalRetryCause(children[0])
		}
	case interface{ Unwrap() error }:
		return x86SDKNumericalRetryCause(value.Unwrap())
	}
	return nil, false
}

func (source *x86SDKNumericalCLISource) close() error {
	var result error
	for i := len(source.cleanup) - 1; i >= 0; i-- {
		result = errors.Join(result, source.cleanup[i]())
	}
	source.cleanup = nil
	return result
}

func (source *x86SDKNumericalCLISource) verify(ctx context.Context) error {
	if err := verifyAMD64FixedLocalSelection(source.original, source.origin, source.target); err != nil {
		return err
	}
	if err := verifyAMD64FixedLocalSelection(source.pkg, source.selected, source.target); err != nil {
		return err
	}
	for name, expected := range source.sources {
		actual, err := gotoolprofile.FileSHA256(name)
		if err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("%w: SDK numerical compiled Go source changed", plan9asm.ErrProbeNeedsContext)
		}
	}
	return source.frontend.Verify(ctx)
}

// The symbol query chooses whether to pay for an independent observer. It is
// not a read-shape, offset, layout, source-role or caller certificate. The
// supported SDK owner producer, rather than a package-name exemption, checks
// the complete actual internal/cpu variable and every native read separately.
func x86SDKCPUOwnerRequested(pkg *packages.Package, file *plan9asm.File, target string) bool {
	return sdkfrontend.CPUOwnerRequested(sdkPackageView(pkg), file, target)
}

func x86SDKNumericalOwnerRequested(pkg *packages.Package, file *plan9asm.File, target string) bool {
	return sdkfrontend.NumericalOwnerRequested(sdkPackageView(pkg), file, target)
}

func captureX86SDKNumericalSource(pkg *packages.Package, file *plan9asm.File, asm, target string,
	config compileConfig,
) (_ *plan9asm.File, _ *x86SDKNumericalCLISource, result error) {
	if !config.acquireSDKNumerical {
		return file, nil, nil
	}
	if config.Feature != nil || !x86SDKNumericalOwnerRequested(pkg, file, target) {
		return nil, nil, fmt.Errorf("%w: SDK numerical retry no longer has its original candidate role", plan9asm.ErrProbeNeedsContext)
	}
	selected := config.x86CallerSelections[pkg]
	if err := verifyAMD64FixedLocalSelection(pkg, selected, target); err != nil {
		return nil, nil, err
	}
	ctx := config.Context
	if ctx == nil {
		return nil, nil, fmt.Errorf("%w: SDK numerical source requires a bounded context", plan9asm.ErrProbeNeedsContext)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, nil, fmt.Errorf("%w: SDK numerical source context is unbounded", plan9asm.ErrProbeNeedsContext)
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
	original, origin := pkg, selected
	pkg, selected, release, err := loadX86SDKNumericalPackage(ctx, binary, pkg, selected)
	if err != nil {
		return nil, nil, err
	}
	source := &x86SDKNumericalCLISource{selected: selected, pkg: pkg, target: target,
		original: original, origin: origin, cleanup: []func() error{release}}
	defer func() {
		if result != nil {
			result = errors.Join(result, source.close())
		}
	}()
	directory, err := sourcepath.Resolve(pkg.Dir)
	if err != nil {
		return nil, nil, err
	}
	actualAsm, err := sourcepath.Resolve(asm)
	if err != nil || filepath.Dir(actualAsm) != directory {
		return nil, nil, fmt.Errorf("%w: SDK numerical assembly origin differs: %v", plan9asm.ErrProbeNeedsContext, err)
	}
	// Deduplicate only: exec uses the last value. Never replace a loaded
	// profile with more convenient flags, cache paths or environment defaults.
	values := make(map[string]string)
	for _, entry := range selected.env {
		key, value, valid := strings.Cut(entry, "=")
		if !valid || key == "" {
			return nil, nil, fmt.Errorf("malformed SDK numerical actual-load environment")
		}
		values[key] = value
	}
	var environment []string
	for key, value := range values {
		environment = append(environment, key+"="+value)
	}
	sort.Strings(environment)
	root, stderr, err := gotoolprofile.RunBounded(ctx, directory, environment, binary, "env", "GOROOT")
	if err != nil || len(stderr) != 0 {
		return nil, nil, fmt.Errorf("observe actual SDK root: %w", errors.Join(err, numericalCLIStderr(stderr)))
	}
	rootPath, err := sourcepath.Resolve(strings.TrimSpace(string(root)))
	if err != nil || !filepath.IsAbs(rootPath) {
		return nil, nil, fmt.Errorf("%w: SDK numerical root is not canonical: %v", plan9asm.ErrProbeNeedsContext, err)
	}
	syntax, sources, err := amd64FixedLocalActualSyntax(ctx, pkg)
	if err != nil {
		return nil, nil, err
	}
	imports := make(map[string]*types.Package, len(pkg.Imports))
	for path, dependency := range pkg.Imports {
		imports[path] = dependency.Types
	}
	source.sources = sources
	// Preserve linkname discovery for the newly loaded package as well as the
	// complete declaration syntax required by the independent numerical binder.
	pkg.Syntax = syntax
	source.goPackage = plan9asm.GoPackage{Path: pkg.PkgPath, Types: pkg.Types, Syntax: syntax, Imports: imports}
	actual, observed, err := sdkfrontend.Capture(ctx, sdkfrontend.CaptureRequest{
		GoBinary: binary, Root: rootPath, Directory: directory, PackagePath: pkg.PkgPath,
		AssemblyFile: actualAsm, Target: target, Environment: environment,
		Package: sdkPackageView(pkg),
	}, file)
	if err != nil {
		return nil, nil, err
	}
	source.frontend = observed
	source.cleanup = append(source.cleanup, observed.Close)
	if err := source.verify(ctx); err != nil {
		return nil, nil, err
	}
	return actual, source, nil
}

func numericalCLIStderr(stderr []byte) error {
	if len(stderr) == 0 {
		return nil
	}
	return fmt.Errorf("actual Go stderr: %s", strings.TrimSpace(string(stderr)))
}
