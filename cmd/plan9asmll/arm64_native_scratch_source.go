package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

func prepareARM64NativeScratchSource(pkg *packages.Package, file *plan9asm.File, asm, target, triple string,
	config compileConfig, resolve func(string) string, sigs map[string]plan9asm.FuncSig,
) (map[string]plan9asm.FuncSig, *plan9asm.GoARM64ScratchSource, error) {
	if !plan9asm.GoARM64ScratchBindingNeeded(file) {
		return sigs, nil, nil
	}
	selected := config.x86CallerSelections[pkg]
	if pkg == nil || selected == nil || !selected.ready || selected.target != target || selected.mode != nil ||
		selected.types != pkg.Types || selected.identity == "" || selected.identity != x86CallerSelectionIdentity(pkg, selected.env) ||
		!reflect.DeepEqual(selected.sizes, x86CallerSizes(pkg.TypesSizes)) {
		return nil, nil, fmt.Errorf("%w: native scratch closure needs unchanged ordinary actual package-load identity", plan9asm.ErrProbeNeedsContext)
	}
	values := make(map[string]string)
	for _, item := range selected.env {
		key, value, valid := strings.Cut(item, "=")
		if !valid || key == "" {
			return nil, nil, fmt.Errorf("malformed actual native scratch environment")
		}
		values[key] = value
	}
	var env []string
	for key, value := range values {
		env = append(env, key+"="+value)
	}
	sort.Strings(env)
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
	directory, err := sourcepath.Resolve(pkg.Dir)
	if err != nil {
		return nil, nil, err
	}
	original, err := sourcepath.Resolve(asm)
	if err != nil || filepath.Dir(original) != directory {
		return nil, nil, fmt.Errorf("%w: native scratch original assembly root changed", plan9asm.ErrProbeNeedsContext)
	}
	source, err := plan9asm.CaptureGoARM64ScratchSource(config.Context,
		plan9asm.GoPackage{Path: pkg.PkgPath, Types: pkg.Types, Syntax: pkg.Syntax},
		plan9asm.GoARM64ScratchCaptureRequest{GoBinary: binary, Directory: directory, AssemblyFile: filepath.Base(original), Target: target, Environment: env})
	if err != nil {
		return nil, nil, err
	}
	bound, err := source.BindScratchClosure(config.Context, file, plan9asm.Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: resolve, Sigs: sigs})
	if err != nil {
		closeErr := source.Close()
		if closeErr != nil {
			return nil, nil, fmt.Errorf("%w; cleanup: %v", err, closeErr)
		}
		return nil, nil, err
	}
	return bound.Sigs, source, nil
}
