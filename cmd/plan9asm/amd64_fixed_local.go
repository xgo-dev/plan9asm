package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sdkfrontend"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

func translateAMD64FixedLocal(ctx context.Context, pkg *packages.Package, selected *sdkfrontend.Selection,
	source []byte, asmPath, target string, options plan9asm.Options,
) (_ translation, result error) {
	check := func() error { return sdkfrontend.Check(sdkPackageView(pkg), selected, target) }
	if err := check(); err != nil {
		return translation{}, err
	}
	defer func() { result = errors.Join(result, check()) }()
	binary, err := exec.LookPath("go")
	if err != nil {
		return translation{}, err
	}
	binary, err = sourcepath.Resolve(binary)
	if err != nil {
		return translation{}, err
	}
	dir, err := sourcepath.Resolve(pkg.Dir)
	if err != nil {
		return translation{}, err
	}
	asmPath, err = sourcepath.Resolve(asmPath)
	if err != nil {
		return translation{}, err
	}
	if filepath.Dir(asmPath) != dir {
		return translation{}, fmt.Errorf("%w: fixed-local assembly must belong to the loaded package", plan9asm.ErrProbeNeedsContext)
	}
	name := filepath.Base(asmPath)
	goos, goarch, _ := strings.Cut(target, "/")
	expanded, err := plan9asm.PreprocessAssemblySource(string(source), plan9asm.AssemblyPreprocessOptions{
		FileName: name, Defines: plan9asm.GoAssemblerDefines(goos, goarch),
	})
	if err != nil {
		return translation{}, err
	}
	file, err := plan9asm.ParseWithDefines(plan9asm.ArchAMD64, expanded, nil)
	if err != nil {
		return translation{}, err
	}

	goPkg := goPackageView(pkg)
	if pkg.Module == nil {
		frame, err := plan9asm.CaptureGoAMD64SDKFrameSource(ctx, goPkg, plan9asm.GoAMD64FrameCaptureRequest{
			GoBinary: binary, Directory: dir, AssemblyFile: name, Target: target, Environment: selected.Environment(),
		})
		if err != nil {
			return translation{}, err
		}
		defer func() { result = errors.Join(result, frame.Close()) }()
		options, err = frame.BindFixedLocal(ctx, goPkg, file, options)
		if err != nil {
			return translation{}, err
		}
	} else {
		original, err := gotoolprofile.CaptureAMD64OriginalPackageObservation(ctx, gotoolprofile.AMD64OriginalObservationRequest{
			GoBinary: binary, Directory: dir, PackagePath: pkg.PkgPath, Target: target, Environment: selected.Environment(),
		}, gotoolprofile.RunBounded)
		if err != nil {
			return translation{}, err
		}
		defer func() { result = errors.Join(result, original.Close()) }()
		options, _, err = original.BindFixedLocal(ctx, goPkg, file, name, options)
		if err != nil {
			return translation{}, err
		}
	}
	ir, err := plan9asm.Translate(file, options)
	if err != nil {
		return translation{}, err
	}
	return translation{LLVMIR: ir, Functions: collectFunctionInfo(file, options.Sigs, options.ResolveSym)}, nil
}
