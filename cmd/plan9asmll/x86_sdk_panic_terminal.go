package main

import (
	"context"
	"fmt"
	"go/types"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

// This query only decides whether to try observing the actual compiler. A void
// signature does not establish that the original CALL cannot return.
func sdkPanicTerminalCandidate(pkg *packages.Package, file *plan9asm.File) bool {
	if pkg.Module != nil || pkg.Types == nil || file.Arch != plan9asm.ArchAMD64 {
		return false
	}
	defined := make(map[string]bool, len(file.Funcs))
	for _, function := range file.Funcs {
		defined[function.Sym] = true
	}
	for _, function := range file.Funcs {
		for _, ins := range function.Instrs {
			if ins.Op != plan9asm.OpCALL || len(ins.Args) != 1 || ins.Args[0].Kind != plan9asm.OpSym {
				continue
			}
			name, direct := strings.CutSuffix(ins.Args[0].Sym, "(SB)")
			if !direct || !strings.HasPrefix(name, "·") || defined[name] {
				continue
			}
			callee, ok := pkg.Types.Scope().Lookup(strings.TrimPrefix(name, "·")).(*types.Func)
			if ok && callee.Pkg() == pkg.Types {
				sig := callee.Type().(*types.Signature)
				if sig.Params().Len() == 0 && sig.Results().Len() == 0 && sig.TypeParams().Len() == 0 {
					return true
				}
			}
		}
	}
	return false
}

type sdkSourceTranslator func(context.Context, llvm.Context, plan9asm.GoSDKAssemblyCaptureRequest, plan9asm.GoModuleOptions) (*plan9asm.GoModuleTranslation, error)

func sdkOriginalSourceFallback(pkg *packages.Package, task asmTask, reads *plan9asm.GoAssemblySourceReadReport,
	goos, goarch, triple string, annotate bool, resolve func(string) string, config compileConfig, translate sdkSourceTranslator,
) func(llvm.Context) (llvm.Module, error) {
	return func(irCtx llvm.Context) (llvm.Module, error) {
		target := goos + "/" + goarch
		selected := config.x86CallerSelections[pkg]
		if err := verifyAMD64FixedLocalSelection(pkg, selected, target); err != nil {
			return llvm.Module{}, err
		}
		path, err := exec.LookPath("go")
		if err != nil {
			return llvm.Module{}, err
		}
		binary, err := sourcepath.Resolve(path)
		if err != nil {
			return llvm.Module{}, err
		}
		member, err := sourcepath.Resolve(task.AsmFile)
		if err != nil {
			return llvm.Module{}, err
		}
		request := plan9asm.GoSDKAssemblyCaptureRequest{
			GoBinary: binary, Directory: filepath.Dir(member), PackagePath: pkg.PkgPath,
			Target: target, Environment: selected.env,
		}
		result, err := translate(config.Context, irCtx, request,
			plan9asm.GoModuleOptions{
				FileName: member, GOOS: goos, GOARCH: goarch, TargetTriple: triple,
				ResolveSym: resolve, AnnotateSource: annotate,
			})
		if err != nil {
			return llvm.Module{}, err
		}
		for name, before := range reads.Inputs {
			after, err := gotoolprofile.FileSHA256(name)
			if err != nil || after != before {
				result.Module.Dispose()
				return llvm.Module{}, fmt.Errorf("the original assembly or include changed during SDK source observation")
			}
		}
		return result.Module, nil
	}
}
