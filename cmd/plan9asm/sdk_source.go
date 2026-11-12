package main

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/sdkfrontend"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

type loadedPackage struct {
	*packages.Package
	selected *sdkfrontend.Selection
}

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
			Module: pkg.Module != nil, Test: strings.Contains(pkg.ID, " [") && strings.HasSuffix(pkg.ID, ".test]"),
			IllTyped: pkg.IllTyped, Types: pkg.Types, Sizes: pkg.TypesSizes, Imports: make(map[string]*sdkfrontend.Package)}
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

// The ordinary complete-file translation must fail before publication before
// this independent source route is considered. No rejected/changed selection
// is repaired by manufacturing a new load environment.
func translateSDKSource(ctx context.Context, pkg *packages.Package, selected *sdkfrontend.Selection,
	file *plan9asm.File, asmPath, target string, annotate bool,
) (_ translation, result error) {
	if err := sdkfrontend.Check(sdkPackageView(pkg), selected, target); err != nil {
		return translation{}, err
	}
	original := pkg
	defer func() {
		result = errors.Join(result, sdkfrontend.Check(sdkPackageView(original), selected, target))
	}()
	binary, err := exec.LookPath("go")
	if err != nil {
		return translation{}, err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return translation{}, err
	}
	binary, err = sourcepath.Resolve(binary)
	if err != nil {
		return translation{}, err
	}
	var actual *packages.Package
	_, observed, close, err := sdkfrontend.Reload(ctx, binary, sdkPackageView(pkg), selected,
		func(ctx context.Context, directory string, environment []string) (*sdkfrontend.Package, error) {
			loaded, err := packages.Load(&packages.Config{Context: ctx, Dir: directory, Env: environment,
				Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
					packages.NeedModule | packages.NeedDeps | packages.NeedImports | packages.NeedSyntax |
					packages.NeedTypes | packages.NeedTypesSizes,
			}, ".")
			if err != nil {
				return nil, err
			}
			if len(loaded) != 1 {
				return nil, fmt.Errorf("SDK numerical reload selected %d packages, want one", len(loaded))
			}
			actual = loaded[0]
			return sdkPackageView(actual), nil
		})
	if err != nil {
		return translation{}, err
	}
	defer func() {
		result = errors.Join(result, sdkfrontend.Check(sdkPackageView(actual), observed, target), close())
	}()
	values, err := sdkfrontend.EnvironmentValues(observed.Environment())
	if err != nil {
		return translation{}, err
	}
	file, source, err := sdkfrontend.Capture(ctx, sdkfrontend.CaptureRequest{
		GoBinary: binary, Root: values["GOROOT"], Directory: actual.Dir, PackagePath: actual.PkgPath,
		AssemblyFile: asmPath, Target: target, Environment: observed.Environment(),
		Package: sdkPackageView(actual),
	}, file)
	if err != nil {
		return translation{}, err
	}
	defer func() { result = errors.Join(result, source.Verify(ctx), source.Close()) }()
	resolve := func(symbol string) string { return sdkfrontend.Resolve(actual.PkgPath, symbol) }
	goos, goarch, _ := strings.Cut(target, "/")
	sigs, err := sigsForAsmFile(actual, file, resolve, goarch)
	if err != nil {
		return translation{}, err
	}
	options, err := source.BindNumericalReads(ctx, goPackageView(actual), file, plan9asm.Options{
		TargetTriple: targetTriple(goos, goarch), ResolveSym: resolve, Sigs: sigs, Goarch: goarch, AnnotateSource: annotate,
	})
	if err != nil {
		return translation{}, err
	}
	ir, err := plan9asm.Translate(file, options)
	if err != nil {
		return translation{}, err
	}
	return translation{LLVMIR: ir, Functions: collectFunctionInfo(file, sigs, resolve)}, nil
}

func goPackageView(pkg *packages.Package) plan9asm.GoPackage {
	imports := make(map[string]*types.Package, len(pkg.Imports))
	syntax := make(map[string][]*ast.File, len(pkg.Imports))
	for path, dependency := range pkg.Imports {
		if dependency != nil {
			imports[path] = dependency.Types
			if dependency.Types != nil && len(dependency.Syntax) != 0 {
				syntax[path] = dependency.Syntax
			}
		}
	}
	return plan9asm.GoPackage{Path: pkg.PkgPath, Types: pkg.Types, Imports: imports,
		Syntax: pkg.Syntax, ImportSyntax: syntax}
}

// The caller owns this one complete-source consumption. Never retain the LLVM
// module or its call-local declaration facts after copying the public result.
func translateLoadedGoModule(pkg *packages.Package, source []byte, asmPath, goos, goarch string, annotate bool) (translation, error) {
	wasmABI := plan9asm.WASMABIDirect
	if goarch == "wasm" && (goos == "js" || goos == "wasip1") {
		wasmABI = plan9asm.WASMABIGo
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := plan9asm.TranslateGoModuleInContext(ctx, goPackageView(pkg), source, plan9asm.GoModuleOptions{
		FileName: asmPath, GOOS: goos, GOARCH: goarch, Sizes: pkg.TypesSizes,
		TargetTriple: targetTriple(goos, goarch), WASMABI: wasmABI,
		AnnotateSource: annotate, ResolveSym: resolveSymFunc(pkg.PkgPath),
	})
	if module != nil && !module.Module.IsNil() {
		defer module.Module.Dispose()
	}
	if err != nil {
		return translation{}, err
	}
	if module == nil || module.Module.IsNil() {
		return translation{}, fmt.Errorf("complete GoModule translation returned no LLVM module")
	}
	functions := make([]functionInfo, 0, len(module.Functions))
	for _, function := range module.Functions {
		signature := module.Signatures[function.ResolvedSymbol]
		arguments := make([]string, len(signature.Args))
		for index, argument := range signature.Args {
			arguments[index] = string(argument)
		}
		result := string(signature.Ret)
		if result == "" {
			result = string(plan9asm.Void)
		}
		functions = append(functions, functionInfo{Symbol: function.TextSymbol,
			Resolved: function.ResolvedSymbol, Args: arguments, Ret: result})
	}
	return translation{LLVMIR: module.Module.String(), Functions: functions}, nil
}
