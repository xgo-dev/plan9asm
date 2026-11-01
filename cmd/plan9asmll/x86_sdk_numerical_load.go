package main

import (
	"context"
	"fmt"
	"go/types"
	"reflect"

	"github.com/xgo-dev/plan9asm/internal/sdkfrontend"
	"golang.org/x/tools/go/packages"
)

func sdkPackageView(pkg *packages.Package) *sdkfrontend.Package {
	seen := make(map[*packages.Package]*sdkfrontend.Package)
	var visit func(*packages.Package) *sdkfrontend.Package
	visit = func(pkg *packages.Package) *sdkfrontend.Package {
		if pkg == nil {
			return nil
		}
		if view := seen[pkg]; view != nil {
			return view
		}
		view := &sdkfrontend.Package{ID: pkg.ID, Name: pkg.Name, Path: pkg.PkgPath, Dir: pkg.Dir,
			GoFiles: pkg.GoFiles, CompiledGoFiles: pkg.CompiledGoFiles, OtherFiles: pkg.OtherFiles,
			Module: pkg.Module != nil, Test: isTestVariantPackage(pkg), IllTyped: pkg.IllTyped,
			Types: pkg.Types, Sizes: pkg.TypesSizes, Imports: make(map[string]*sdkfrontend.Package)}
		seen[pkg] = view
		for _, err := range pkg.Errors {
			view.Errors = append(view.Errors, err.Error())
		}
		for path, dependency := range pkg.Imports {
			view.Imports[path] = visit(dependency)
		}
		return view
	}
	return visit(pkg)
}

func loadX86SDKNumericalPackage(ctx context.Context, binary string, pkg *packages.Package,
	selected *x86CallerPackageSelection,
) (*packages.Package, *x86CallerPackageSelection, func() error, error) {
	if selected == nil {
		return nil, nil, nil, sdkfrontend.Check(sdkPackageView(pkg), nil, "")
	}
	if err := verifyAMD64FixedLocalSelection(pkg, selected, selected.target); err != nil {
		return nil, nil, nil, err
	}
	view := sdkPackageView(pkg)
	selection := sdkfrontend.CaptureSelection(view, selected.target, selected.env, selected.mode)
	var reloaded *packages.Package
	_, snapshot, close, err := sdkfrontend.Reload(ctx, binary, view, selection,
		func(ctx context.Context, directory string, environment []string) (*sdkfrontend.Package, error) {
			loaded, err := packages.Load(&packages.Config{Context: ctx, Dir: directory, Env: environment,
				Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
					packages.NeedModule | packages.NeedDeps | packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes,
			}, ".")
			if err != nil {
				return nil, err
			}
			if len(loaded) != 1 {
				return nil, fmt.Errorf("SDK numerical reload selected %d packages, want one", len(loaded))
			}
			reloaded = loaded[0]
			return sdkPackageView(reloaded), nil
		})
	if err != nil {
		return nil, nil, nil, err
	}
	imports := make(map[string]*types.Package, len(reloaded.Imports))
	for path, dependency := range reloaded.Imports {
		imports[path] = dependency.Types
	}
	environment := snapshot.Environment()
	actual := &x86CallerPackageSelection{
		identity: x86CallerSelectionIdentity(reloaded, environment), target: selected.target, types: reloaded.Types,
		sizes: x86CallerSizes(reloaded.TypesSizes), imports: imports, env: environment,
		ready: reflect.DeepEqual(reloaded.GoFiles, reloaded.CompiledGoFiles),
	}
	return reloaded, actual, close, nil
}

func x86SDKLoadGraph(pkg *packages.Package) (map[string]string, error) {
	return sdkfrontend.Graph(sdkPackageView(pkg))
}

func x86SDKPhysicalSelectionIdentity(pkg *packages.Package) (string, error) {
	return sdkfrontend.PhysicalIdentity(sdkPackageView(pkg))
}

func x86SDKSelectedSourceHashes(pkg *packages.Package) (map[string]string, error) {
	return sdkfrontend.SourceHashes(sdkPackageView(pkg))
}
