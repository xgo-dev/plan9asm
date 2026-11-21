package main

import (
	"fmt"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

// Assembly does not add imports to cmd/go's typed graph. Collect source
// candidates separately; the translator checks the actual linker directive
// and both declarations before using any of them.
func sdkAssemblyTailPackages(pkg *packages.Package, file *plan9asm.File, config compileConfig) (map[string]*packages.Package, error) {
	selection := config.x86CallerSelections[pkg]
	if pkg == nil || pkg.Module != nil || file == nil || file.Arch != plan9asm.ArchAMD64 ||
		selection == nil || !selection.ready {
		return nil, nil
	}
	paths := make(map[string]bool)
	for _, fn := range file.Funcs {
		if fn.FrameSize != 0 || len(fn.Instrs) != 2 || fn.Instrs[0].Op != plan9asm.OpTEXT {
			continue
		}
		jump := fn.Instrs[1]
		if jump.Op != plan9asm.OpJMP || len(jump.Args) != 1 || jump.Args[0].Kind != plan9asm.OpSym {
			continue
		}
		symbol, direct := strings.CutSuffix(jump.Args[0].Sym, "(SB)")
		path, name, qualified := strings.Cut(strings.ReplaceAll(symbol, "∕", "/"), "·")
		if direct && qualified && token.IsIdentifier(name) && path != pkg.PkgPath &&
			pkg.Imports[path] == nil && filepath.IsLocal(filepath.FromSlash(path)) {
			paths[path] = true
		}
	}
	if len(paths) == 0 {
		return nil, nil
	}
	var root string
	for _, entry := range selection.env {
		if value, ok := strings.CutPrefix(entry, "GOROOT="); ok {
			root = value
		}
	}
	if !filepath.IsAbs(root) {
		return nil, nil
	}
	sdk := filepath.Join(root, "src")
	isSDKPackage := func(p *packages.Package) bool {
		if p.Module != nil || p.Types == nil || !p.Types.Complete() {
			return false
		}
		physical, err := sourcepath.Resolve(p.Dir)
		return err == nil && physical == filepath.Join(sdk, filepath.FromSlash(p.PkgPath))
	}
	if !isSDKPackage(pkg) {
		return nil, nil
	}
	result := make(map[string]*packages.Package)
	for candidate := range config.x86CallerSelections {
		if paths[candidate.PkgPath] && !isTestVariantPackage(candidate) && isSDKPackage(candidate) {
			result[candidate.PkgPath] = candidate
			delete(paths, candidate.PkgPath)
		}
	}
	var missing []string
	for path := range paths {
		info, err := os.Stat(filepath.Join(sdk, filepath.FromSlash(path)))
		if err == nil && info.IsDir() {
			missing = append(missing, path)
		}
	}
	if len(missing) == 0 {
		return result, nil
	}
	sort.Strings(missing)
	request := &packages.Config{
		Context: config.Context, Dir: pkg.Dir, Env: selection.env,
		Mode: packages.LoadTypes | packages.NeedCompiledGoFiles | packages.NeedModule | packages.NeedTypesSizes | packages.NeedDeps,
	}
	if len(config.buildTags) != 0 {
		request.BuildFlags = []string{"-tags=" + strings.Join(config.buildTags, ",")}
	}
	loaded, err := packages.Load(request, missing...)
	if err != nil {
		return nil, err
	}
	for _, candidate := range loaded {
		if !paths[candidate.PkgPath] || !isSDKPackage(candidate) || candidate.IllTyped || len(candidate.Errors) != 0 {
			return nil, fmt.Errorf("%w: assembly tail lacks its actual selected SDK package %s", plan9asm.ErrProbeNeedsContext, candidate.PkgPath)
		}
		result[candidate.PkgPath] = candidate
	}
	return result, nil
}
