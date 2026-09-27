package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/asmsig"
	"golang.org/x/tools/go/packages"
)

type goListPackage struct {
	Dir        string   `json:"Dir"`
	ImportPath string   `json:"ImportPath"`
	SFiles     []string `json:"SFiles"`
}

type functionInfo struct {
	Symbol   string   `json:"symbol"`
	Resolved string   `json:"resolved"`
	Args     []string `json:"args"`
	Ret      string   `json:"ret"`
}

type translation struct {
	LLVMIR    string
	Functions []functionInfo
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		usage()
		return
	}
	switch cmd {
	case "list":
		check(runList(os.Args[2:]))
	case "transpile":
		check(runTranspile(os.Args[2:]))
	default:
		if strings.HasPrefix(cmd, "-") {
			check(runTranspile(os.Args[1:]))
			return
		}
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  go run ./cmd/plan9asm list [-goos <goos>] [-goarch <goarch>] [<pkg-or-path>]")
	fmt.Fprintln(os.Stderr, "  go run ./cmd/plan9asm transpile [-goos <goos>] [-goarch <goarch>] -dir <out-dir> [patterns...]")
	fmt.Fprintln(os.Stderr, "  go run ./cmd/plan9asm transpile -i <file.s> -o <file.ll> [-goos <goos>] [-goarch <goarch>] [flags]")
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		goos   string
		goarch string
	)
	fs.StringVar(&goos, "goos", runtime.GOOS, "target GOOS")
	fs.StringVar(&goarch, "goarch", runtime.GOARCH, "target GOARCH (amd64/arm64/arm/386/wasm)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := toPlan9Arch(goarch); err != nil {
		return err
	}

	rest := fs.Args()
	if len(rest) > 1 {
		return fmt.Errorf("list accepts at most one argument: <pkg or path>")
	}

	query := "std"
	if len(rest) == 1 {
		query = strings.TrimSpace(rest[0])
		if query == "" {
			return fmt.Errorf("empty <pkg or path>")
		}
	}

	pkgs, err := goListPackages(query, goos, goarch)
	if err != nil {
		return err
	}

	withSFiles := make([]goListPackage, 0, len(pkgs))
	for _, p := range pkgs {
		if len(p.SFiles) > 0 {
			withSFiles = append(withSFiles, p)
		}
	}
	sort.Slice(withSFiles, func(i, j int) bool {
		return withSFiles[i].ImportPath < withSFiles[j].ImportPath
	})

	for i, p := range withSFiles {
		fmt.Println(p.ImportPath)
		files := packageSFilesAbs(p)
		sort.Strings(files)
		for _, s := range files {
			fmt.Printf("  %s\n", s)
		}
		if i != len(withSFiles)-1 {
			fmt.Println()
		}
	}
	return nil
}

func runTranspile(args []string) error {
	fs := flag.NewFlagSet("transpile", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		patterns string
		pkgPath  string
		outDir   string
		inFile   string
		outFile  string
		goos     string
		goarch   string
		metaFile string
		annotate bool
	)
	fs.BoolVar(&annotate, "annotate", true, "emit source asm lines as IR comments")
	fs.StringVar(&inFile, "i", "", "Plan9 asm .s file path")
	fs.StringVar(&outFile, "o", "", "output .ll file path")
	fs.StringVar(&goarch, "goarch", runtime.GOARCH, "target GOARCH (amd64/arm64/arm/386/wasm)")
	fs.StringVar(&goos, "goos", runtime.GOOS, "target GOOS")
	fs.StringVar(&metaFile, "meta", "", "optional output metadata json path")
	fs.StringVar(&patterns, "patterns", "", "deprecated comma-separated package patterns")
	fs.StringVar(&pkgPath, "pkg", "", "deprecated alias for package patterns")
	fs.StringVar(&outDir, "dir", "", "output directory for package transpile")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := toPlan9Arch(goarch); err != nil {
		return err
	}
	patList := make([]string, 0)
	patList = append(patList, splitCSV(patterns)...)
	patList = append(patList, splitCSV(pkgPath)...)
	patList = append(patList, fs.Args()...)
	patList = dedupStrings(patList)

	pkgMode := len(patList) != 0 || strings.TrimSpace(outDir) != ""
	fileMode := strings.TrimSpace(inFile) != "" || strings.TrimSpace(outFile) != ""

	if pkgMode && fileMode {
		return fmt.Errorf("package patterns and -i/-o are mutually exclusive")
	}
	if !pkgMode && !fileMode {
		return fmt.Errorf("missing mode: use transpile -dir <out-dir> <patterns...>, or -i <file.s> -o <file.ll>")
	}

	if pkgMode {
		if len(patList) == 0 || strings.TrimSpace(outDir) == "" {
			return fmt.Errorf("package mode requires both patterns and -dir")
		}
		return transpilePackageMode(patList, outDir, goos, goarch, annotate, metaFile)
	}

	if strings.TrimSpace(inFile) == "" || strings.TrimSpace(outFile) == "" {
		return fmt.Errorf("single-file mode requires both -i and -o")
	}
	return transpileSingleFileMode(inFile, outFile, goos, goarch, annotate, metaFile)
}

func transpilePackageMode(patterns []string, outDir, goos, goarch string, annotate bool, metaFile string) error {
	pkgs, err := listPackagesForPatterns(patterns, goos, goarch)
	if err != nil {
		return err
	}
	withSFiles := make([]goListPackage, 0, len(pkgs))
	for _, p := range pkgs {
		if len(p.SFiles) > 0 {
			withSFiles = append(withSFiles, p)
		}
	}
	if len(withSFiles) == 0 {
		return fmt.Errorf("no package with selected .s files for GOOS=%s GOARCH=%s and patterns=%s", goos, goarch, strings.Join(patterns, ","))
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	multiPkg := len(withSFiles) > 1

	type metaItem struct {
		File      string         `json:"file"`
		Output    string         `json:"output"`
		Functions []functionInfo `json:"functions"`
	}
	type packageMeta struct {
		Package string     `json:"package"`
		Items   []metaItem `json:"items"`
	}
	pkgMetas := make([]packageMeta, 0, len(withSFiles))

	for _, gpkg := range withSFiles {
		pkg, err := loadPackage(gpkg.ImportPath, goos, goarch)
		if err != nil {
			return err
		}
		sfiles := packageSFilesAbs(gpkg)
		sort.Strings(sfiles)
		items := make([]metaItem, 0, len(sfiles))
		pkgOutDir := outDir
		if multiPkg {
			pkgOutDir = filepath.Join(outDir, packageOutputDir(gpkg.ImportPath))
		}

		for _, sfile := range sfiles {
			tr, ok, err := translateAsmForPackage(pkg, sfile, goos, goarch, annotate)
			if err != nil {
				return fmt.Errorf("transpile %s: %w", sfile, err)
			}
			if !ok {
				continue
			}
			outPath := filepath.Join(pkgOutDir, filepath.Base(sfile)+".ll")
			if err := writeTextFile(outPath, tr.LLVMIR); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "wrote llvm ir: %s\n", outPath)
			items = append(items, metaItem{File: sfile, Output: outPath, Functions: tr.Functions})
		}

		pkgMetas = append(pkgMetas, packageMeta{Package: gpkg.ImportPath, Items: items})
	}

	if metaFile == "" {
		return nil
	}
	if len(pkgMetas) == 1 {
		payload := struct {
			Patterns []string   `json:"patterns,omitempty"`
			Package  string     `json:"package"`
			GOOS     string     `json:"goos"`
			GOARCH   string     `json:"goarch"`
			Items    []metaItem `json:"items"`
		}{
			Patterns: patterns,
			Package:  pkgMetas[0].Package,
			GOOS:     goos,
			GOARCH:   goarch,
			Items:    pkgMetas[0].Items,
		}
		if err := writeJSONFile(metaFile, payload); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote metadata: %s\n", metaFile)
		return nil
	}
	payload := struct {
		Patterns []string      `json:"patterns"`
		GOOS     string        `json:"goos"`
		GOARCH   string        `json:"goarch"`
		Packages []packageMeta `json:"packages"`
	}{
		Patterns: patterns,
		GOOS:     goos,
		GOARCH:   goarch,
		Packages: pkgMetas,
	}
	if err := writeJSONFile(metaFile, payload); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote metadata: %s\n", metaFile)
	return nil
}

func transpileSingleFileMode(inFile, outFile, goos, goarch string, annotate bool, metaFile string) error {
	asmPath, err := resolvePath(inFile)
	if err != nil {
		return err
	}
	gpkg, err := selectSinglePackage(filepath.Dir(asmPath), goos, goarch)
	if err != nil {
		return err
	}
	pkg, err := loadPackage(gpkg.ImportPath, goos, goarch)
	if err != nil {
		return err
	}

	tr, ok, err := translateAsmForPackage(pkg, asmPath, goos, goarch, annotate)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s has no TEXT directive", asmPath)
	}
	if err := writeTextFile(outFile, tr.LLVMIR); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote llvm ir: %s\n", outFile)

	if metaFile != "" {
		payload := struct {
			Package   string         `json:"package"`
			File      string         `json:"file"`
			GOOS      string         `json:"goos"`
			GOARCH    string         `json:"goarch"`
			Functions []functionInfo `json:"functions"`
		}{
			Package:   pkg.PkgPath,
			File:      asmPath,
			GOOS:      goos,
			GOARCH:    goarch,
			Functions: tr.Functions,
		}
		if err := writeJSONFile(metaFile, payload); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote metadata: %s\n", metaFile)
	}
	return nil
}

func translateAsmForPackage(pkg *packages.Package, asmPath, goos, goarch string, annotate bool) (translation, bool, error) {
	sourceRoot := filepath.Dir(asmPath)
	if pkg != nil && pkg.Module != nil && pkg.Module.Dir != "" {
		sourceRoot = pkg.Module.Dir
	}
	src, err := plan9asm.ReadGoAssemblySource(asmPath, sourceRoot)
	if err != nil {
		return translation{}, false, err
	}
	imports := make(map[string]*types.Package, len(pkg.Imports))
	for path, imported := range pkg.Imports {
		if imported != nil && imported.Types != nil {
			imports[path] = imported.Types
		}
	}
	src = plan9asm.ExpandGoAssemblySource(plan9asm.GoPackage{
		Path:    pkg.PkgPath,
		Types:   pkg.Types,
		Imports: imports,
	}, src, goarch)
	arch, err := toPlan9Arch(goarch)
	if err != nil {
		return translation{}, false, err
	}
	file, err := plan9asm.ParseWithDefines(arch, string(src), plan9asm.GoAssemblerDefines(goos, goarch))
	if err != nil {
		if strings.Contains(err.Error(), "no TEXT directive found") {
			return translation{}, false, nil
		}
		return translation{}, false, err
	}
	if len(file.Funcs) == 0 {
		return translation{}, false, nil
	}

	resolve := resolveSymFunc(pkg.PkgPath)
	if goarch == "wasm" {
		wasmABI := plan9asm.WASMABIDirect
		if goos == "js" || goos == "wasip1" {
			wasmABI = plan9asm.WASMABIGo
		}
		tr, err := plan9asm.TranslateGoModule(plan9asm.GoPackage{
			Path:    pkg.PkgPath,
			Types:   pkg.Types,
			Imports: imports,
			Syntax:  pkg.Syntax,
		}, src, plan9asm.GoModuleOptions{
			FileName:       asmPath,
			GOOS:           goos,
			GOARCH:         goarch,
			Sizes:          pkg.TypesSizes,
			TargetTriple:   targetTriple(goos, goarch),
			WASMABI:        wasmABI,
			AnnotateSource: annotate,
			ResolveSym:     resolve,
		})
		if err != nil {
			return translation{}, false, err
		}
		defer tr.Module.Dispose()
		fns := make([]functionInfo, 0, len(tr.Functions))
		for _, fn := range tr.Functions {
			sig := tr.Signatures[fn.ResolvedSymbol]
			args := make([]string, len(sig.Args))
			for i, arg := range sig.Args {
				args[i] = string(arg)
			}
			ret := string(sig.Ret)
			if ret == "" {
				ret = string(plan9asm.Void)
			}
			fns = append(fns, functionInfo{
				Symbol: fn.TextSymbol, Resolved: fn.ResolvedSymbol,
				Args: args, Ret: ret,
			})
		}
		return translation{LLVMIR: tr.Module.String(), Functions: fns}, true, nil
	}
	sigs, err := sigsForAsmFile(pkg, file, resolve, goarch)
	if err != nil {
		return translation{}, false, err
	}
	ll, err := plan9asm.Translate(file, plan9asm.Options{
		TargetTriple:   targetTriple(goos, goarch),
		ResolveSym:     resolve,
		Sigs:           sigs,
		Goarch:         goarch,
		AnnotateSource: annotate,
	})
	if err != nil {
		return translation{}, false, err
	}
	fns := collectFunctionInfo(file, sigs, resolve)
	return translation{LLVMIR: ll, Functions: fns}, true, nil
}

func collectFunctionInfo(file *plan9asm.File, sigs map[string]plan9asm.FuncSig, resolve func(string) string) []functionInfo {
	seen := map[string]bool{}
	out := make([]functionInfo, 0, len(file.Funcs))
	for _, fn := range file.Funcs {
		resolved := resolve(stripABISuffix(fn.Sym))
		if resolved == "" || seen[resolved] {
			continue
		}
		seen[resolved] = true
		sig := sigs[resolved]
		args := make([]string, len(sig.Args))
		for i, a := range sig.Args {
			args[i] = string(a)
		}
		ret := string(sig.Ret)
		if ret == "" {
			ret = string(plan9asm.Void)
		}
		out = append(out, functionInfo{
			Symbol:   fn.Sym,
			Resolved: resolved,
			Args:     args,
			Ret:      ret,
		})
	}
	return out
}

func toPlan9Arch(goarch string) (plan9asm.Arch, error) {
	switch goarch {
	case "amd64", "386":
		return plan9asm.ArchAMD64, nil
	case "arm":
		return plan9asm.ArchARM, nil
	case "arm64":
		return plan9asm.ArchARM64, nil
	case "wasm":
		return plan9asm.ArchWASM, nil
	default:
		return "", fmt.Errorf("unsupported -goarch %q (expect amd64/arm64/arm/386/wasm)", goarch)
	}
}

func targetTriple(goos, goarch string) string {
	switch goos {
	case "darwin":
		switch goarch {
		case "amd64":
			return "x86_64-apple-macosx"
		case "arm64":
			return "arm64-apple-macosx"
		case "386":
			return "i386-apple-macosx"
		}
	case "linux":
		switch goarch {
		case "amd64":
			return "x86_64-unknown-linux-gnu"
		case "arm64":
			return "aarch64-unknown-linux-gnu"
		case "arm":
			switch strings.SplitN(os.Getenv("GOARM"), ",", 2)[0] {
			case "5":
				return "armv5te-unknown-linux-gnueabi"
			case "6":
				return "armv6-unknown-linux-gnueabihf"
			default:
				return "armv7-unknown-linux-gnueabihf"
			}
		case "386":
			return "i386-unknown-linux-gnu"
		}
	case "windows":
		switch goarch {
		case "amd64":
			return "x86_64-pc-windows-msvc"
		case "arm64":
			return "aarch64-pc-windows-msvc"
		case "386":
			return "i686-pc-windows-msvc"
		}
	case "js":
		if goarch == "wasm" {
			return "wasm32-unknown-unknown"
		}
	case "wasip1":
		if goarch == "wasm" {
			return "wasm32-unknown-wasi"
		}
	}
	return ""
}

func loadPackage(pkgPath, goos, goarch string) (*packages.Package, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedDeps |
			packages.NeedImports |
			packages.NeedSyntax |
			packages.NeedTypes |
			packages.NeedTypesSizes |
			packages.NeedTypesInfo,
		Env: append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch),
	}
	pkgs, err := packages.Load(cfg, pkgPath)
	if err != nil {
		return nil, err
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("package not found: %s", pkgPath)
	}
	for _, p := range pkgs {
		if len(p.Errors) != 0 {
			return nil, fmt.Errorf("load %s: %s", p.PkgPath, p.Errors[0].Msg)
		}
	}
	for _, p := range pkgs {
		if p.PkgPath == pkgPath {
			if p.Types == nil || p.Types.Scope() == nil {
				return nil, fmt.Errorf("package %s loaded without types", pkgPath)
			}
			return p, nil
		}
	}
	p := pkgs[0]
	if p.Types == nil || p.Types.Scope() == nil {
		return nil, fmt.Errorf("package %s loaded without types", p.PkgPath)
	}
	return p, nil
}

func resolvePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("empty path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if fi.IsDir() {
		return "", fmt.Errorf("path is a directory: %s", abs)
	}
	return abs, nil
}

func goListPackages(query, goos, goarch string) ([]goListPackage, error) {
	args := []string{"list", "-json", query}
	cmd := exec.Command("go", args...)
	// Package discovery only needs metadata. Disabling cgo prevents a host C
	// toolchain from being used while listing a different target (for example,
	// Windows-hosted tooling inspecting Linux standard-library assembly).
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)

	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			stderr = strings.TrimSpace(string(ee.Stderr))
		}
		if stderr != "" {
			return nil, fmt.Errorf("go list -json %s failed: %w\n%s", query, err, stderr)
		}
		return nil, fmt.Errorf("go list -json %s failed: %w", query, err)
	}

	dec := json.NewDecoder(bytes.NewReader(out))
	var pkgs []goListPackage
	for {
		var p goListPackage
		if err := dec.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("parse go list output for %q: %w", query, err)
		}
		if strings.TrimSpace(p.ImportPath) == "" {
			continue
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

func listPackagesForPatterns(patterns []string, goos, goarch string) ([]goListPackage, error) {
	uniq := map[string]goListPackage{}
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pkgs, err := goListPackages(p, goos, goarch)
		if err != nil {
			return nil, err
		}
		for _, pkg := range pkgs {
			key := strings.TrimSpace(pkg.ImportPath)
			if key == "" {
				key = strings.TrimSpace(pkg.Dir)
			}
			if key == "" {
				continue
			}
			uniq[key] = pkg
		}
	}
	out := make([]goListPackage, 0, len(uniq))
	for _, pkg := range uniq {
		out = append(out, pkg)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ImportPath < out[j].ImportPath
	})
	return out, nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func packageOutputDir(importPath string) string {
	importPath = strings.TrimSpace(importPath)
	if importPath == "" {
		return "_unknown"
	}
	return filepath.FromSlash(importPath)
}

func packageSFilesAbs(p goListPackage) []string {
	files := make([]string, 0, len(p.SFiles))
	for _, f := range p.SFiles {
		if filepath.Ext(f) != ".s" {
			continue
		}
		if filepath.IsAbs(f) {
			files = append(files, f)
		} else if p.Dir != "" {
			files = append(files, filepath.Join(p.Dir, f))
		}
	}
	return files
}

func selectSinglePackage(query, goos, goarch string) (goListPackage, error) {
	pkgs, err := goListPackages(query, goos, goarch)
	if err != nil {
		return goListPackage{}, err
	}
	if len(pkgs) == 0 {
		return goListPackage{}, fmt.Errorf("package not found: %s", query)
	}
	if len(pkgs) == 1 {
		return pkgs[0], nil
	}

	absQuery := query
	if filepath.IsAbs(query) {
		absQuery = filepath.Clean(query)
	}
	for _, p := range pkgs {
		if p.ImportPath == query {
			return p, nil
		}
		if absQuery != "" && p.Dir != "" && filepath.Clean(p.Dir) == absQuery {
			return p, nil
		}
	}

	paths := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		paths = append(paths, p.ImportPath)
	}
	sort.Strings(paths)
	return goListPackage{}, fmt.Errorf("query %q matches multiple packages: %s", query, strings.Join(paths, ", "))
}

func writeTextFile(path, data string) error {
	if path == "-" {
		_, err := os.Stdout.WriteString(data)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(data), 0644)
}

func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeTextFile(path, string(data))
}

func resolveSymFunc(pkgPath string) func(sym string) string {
	return func(sym string) string {
		sym = stripABISuffix(sym)
		hadLocal := strings.HasSuffix(sym, "<>")
		sym = strings.TrimSuffix(sym, "<>")
		if strings.HasPrefix(sym, "·") {
			name := pkgPath + "." + strings.TrimPrefix(sym, "·")
			if hadLocal {
				return name + "$local"
			}
			return name
		}
		sym = strings.ReplaceAll(sym, "∕", "/")
		sym = strings.ReplaceAll(sym, "·", ".")
		if hadLocal {
			if !strings.Contains(sym, "/") && !strings.Contains(sym, ".") {
				return pkgPath + "." + sym + "$local"
			}
			return sym + "$local"
		}
		return sym
	}
}

var abiSuffixRe = regexp.MustCompile(`<ABI[^>]*>$`)

func stripABISuffix(sym string) string {
	return abiSuffixRe.ReplaceAllString(sym, "")
}

func sigsForAsmFile(pkg *packages.Package, file *plan9asm.File, resolve func(string) string, goarch string) (map[string]plan9asm.FuncSig, error) {
	sigs := map[string]plan9asm.FuncSig{}
	if pkg == nil || pkg.Types == nil || pkg.Types.Scope() == nil {
		for _, fn := range file.Funcs {
			fs := fallbackSigForAsmFunc(fn, resolve(stripABISuffix(fn.Sym)), goarch)
			if goarch == "wasm" {
				if native, ok := plan9asm.LookupGoWASMNativeFuncSig(fs.Name); ok {
					fs = native
				} else if strings.HasSuffix(stripABISuffix(fn.Sym), "<>") && plan9asm.WASMAssemblyUsesNativeReturn(fn) {
					var err error
					fs, err = plan9asm.InferWASMAssemblyFuncSig(fn, fs.Name)
					if err != nil {
						return nil, err
					}
					fs.WASMNative = true
				}
			}
			sigs[fs.Name] = fs
		}
		asmsig.RefineTailForwarders(file, sigs, resolve, nil)
		return sigs, nil
	}

	sz := pkg.TypesSizes
	if sz == nil {
		sz = types.SizesFor("gc", goarch)
	}
	if sz == nil {
		return nil, fmt.Errorf("missing type sizes for %q", goarch)
	}

	scope := pkg.Types.Scope()
	linknames := linknameRemoteToLocal(pkg.Syntax)
	declaredSigs := map[string]bool{}

	for _, fn := range file.Funcs {
		sym := stripABISuffix(fn.Sym)
		resolved := resolve(sym)
		if resolved == "" {
			continue
		}
		fs, ok, err := tryDeclSig(scope, asmDeclLookupSym(pkg, sym), resolved, linknames, goarch, sz)
		if err != nil {
			return nil, err
		}
		if !ok {
			fs = fallbackSigForAsmFunc(fn, resolved, goarch)
		} else {
			if goarch == "arm64" {
				inferred := fallbackSigForAsmFunc(fn, resolved, goarch)
				if borrowed, ok := asmsig.ARM64BorrowedTailFrame(file, fn, fs, inferred, resolve); ok {
					fs = borrowed
				}
			}
			declaredSigs[resolved] = true
		}
		sigs[resolved] = fs
	}
	if goarch == "wasm" {
		for _, fn := range file.Funcs {
			resolved := resolve(stripABISuffix(fn.Sym))
			fs, ok := plan9asm.LookupGoWASMNativeFuncSig(resolved)
			if !ok {
				if !strings.HasSuffix(stripABISuffix(fn.Sym), "<>") || !plan9asm.WASMAssemblyUsesNativeReturn(fn) {
					continue
				}
				var err error
				fs, err = plan9asm.InferWASMAssemblyFuncSig(fn, resolved)
				if err != nil {
					return nil, err
				}
			}
			fs.WASMNative = true
			sigs[resolved] = fs
		}
	}

	addTargetSig := func(sym string, caller plan9asm.FuncSig, tail bool) {
		if sym == "" {
			return
		}
		sym = stripABISuffix(sym)
		resolved := resolve(sym)
		if resolved == "" {
			return
		}
		if existing, ok := sigs[resolved]; ok {
			// A local assembly helper may have no Go declaration and no FP result
			// slots even though every entry reaches it by tail call. Preserve its
			// inferred register/frame inputs, but make its LLVM return and matching
			// result slots agree with the declared caller. Local helpers share the
			// caller's physical frame, so a byte result may otherwise remain an i32
			// fallback slot underneath an i1 function signature.
			if tail && declaredSigs[caller.Name] && !declaredSigs[resolved] {
				existing.Ret = caller.Ret
				if len(existing.Frame.Results) == len(caller.Frame.Results) {
					for i := range existing.Frame.Results {
						for _, callerResult := range caller.Frame.Results {
							if existing.Frame.Results[i].Offset == callerResult.Offset {
								existing.Frame.Results[i].Type = callerResult.Type
								break
							}
						}
					}
				}
				sigs[resolved] = existing
			}
			return
		}
		if goarch == "wasm" {
			if fs, ok := plan9asm.LookupGoWASMNativeFuncSig(resolved); ok {
				sigs[resolved] = fs
				return
			}
		}
		fs, ok, err := tryDeclSig(scope, asmDeclLookupSym(pkg, sym), resolved, linknames, goarch, sz)
		if err == nil && ok {
			sigs[resolved] = fs
			declaredSigs[resolved] = true
			return
		}
		if tail && caller.Name != "" {
			copySig := caller
			copySig.Name = resolved
			sigs[resolved] = copySig
			return
		}
		sigs[resolved] = plan9asm.FuncSig{Name: resolved, Ret: plan9asm.I64}
	}

	for _, fn := range file.Funcs {
		callerName := resolve(stripABISuffix(fn.Sym))
		caller := sigs[callerName]
		for _, ins := range fn.Instrs {
			op := strings.ToUpper(string(ins.Op))
			tail := op == "JMP" || op == "B" || (op == "RET" && len(ins.Args) == 1)
			if !(tail || op == "CALL" || op == "CALLNORESUME" || op == "WASMCALL" || op == "BL") {
				continue
			}
			if len(ins.Args) != 1 || ins.Args[0].Kind != plan9asm.OpSym {
				continue
			}
			s := strings.TrimSpace(ins.Args[0].Sym)
			if !strings.HasSuffix(s, "(SB)") {
				continue
			}
			s = strings.TrimSuffix(s, "(SB)")
			base, off := splitSymPlusOff(s)
			if base == "" || off != 0 {
				continue
			}
			addTargetSig(base, caller, tail)

			// Entry stubs such as _rt0_386 have no Go declaration or FP
			// result slot, so their fallback signature conservatively assumes a
			// word return. A tail jump to a declared void function proves that
			// the stub itself does not return a value. Reconcile the caller here
			// instead of weakening the lowerer's return-type checks globally.
			targetName := resolve(stripABISuffix(base))
			target, targetOK := sigs[targetName]
			if tail && caller.Name != "" && !declaredSigs[callerName] &&
				len(caller.Frame.Results) == 0 && targetOK &&
				declaredSigs[targetName] && target.Ret == plan9asm.Void {
				caller.Ret = plan9asm.Void
				sigs[callerName] = caller
			}
		}
	}

	asmsig.RefineTailForwarders(file, sigs, resolve, declaredSigs)
	return sigs, nil
}

func asmDeclLookupSym(pkg *packages.Package, sym string) string {
	if pkg == nil || pkg.Types == nil {
		return sym
	}
	prefix := pkg.Types.Name() + "·"
	if strings.HasPrefix(sym, prefix) {
		return "·" + strings.TrimPrefix(sym, prefix)
	}
	return sym
}

func fallbackSigForAsmFunc(fn plan9asm.Func, resolved, goarch string) plan9asm.FuncSig {
	paramOff := map[int64]struct{}{}
	retOff := map[int64]struct{}{}

	for _, ins := range fn.Instrs {
		op := strings.ToUpper(string(ins.Op))
		for i, a := range ins.Args {
			if a.Kind != plan9asm.OpFP && a.Kind != plan9asm.OpFPAddr {
				continue
			}
			if isLikelyResultSlot(op, i, len(ins.Args), a.FPName) {
				retOff[a.FPOffset] = struct{}{}
			} else {
				paramOff[a.FPOffset] = struct{}{}
			}
		}
	}

	paramList := sortOffsets(paramOff)
	retList := sortOffsets(retOff)
	word := plan9asm.I64
	if goarch == "386" || goarch == "arm" {
		word = plan9asm.I32
	}
	params := make([]plan9asm.FrameSlot, 0, len(paramList))
	for i, off := range paramList {
		params = append(params, plan9asm.FrameSlot{Offset: off, Type: word, Index: i, Field: -1})
	}
	results := make([]plan9asm.FrameSlot, 0, len(retList))
	for i, off := range retList {
		results = append(results, plan9asm.FrameSlot{Offset: off, Type: word, Index: i, Field: -1})
	}

	args := make([]plan9asm.LLVMType, len(params))
	for i := range args {
		args[i] = word
	}
	ret := plan9asm.Void
	switch len(results) {
	case 0:
		// A fallback with FP parameters follows ABI0, whose results also live
		// in explicit FP slots. No result slot therefore means void. Keep the
		// conservative word return only for register-only assembly helpers.
		if len(params) == 0 {
			ret = word
		}
	case 1:
		ret = word
	default:
		parts := make([]string, 0, len(results))
		for range results {
			parts = append(parts, string(word))
		}
		ret = plan9asm.LLVMType("{ " + strings.Join(parts, ", ") + " }")
	}
	return plan9asm.FuncSig{
		Name: resolved,
		Args: args,
		Ret:  ret,
		Frame: plan9asm.FrameLayout{
			Params:  params,
			Results: results,
		},
	}
}

func isLikelyResultSlot(op string, argIndex int, argCount int, fpName string) bool {
	name := strings.ToLower(fpName)
	if strings.HasPrefix(name, "ret") {
		return true
	}
	if argCount > 0 && argIndex == argCount-1 {
		switch {
		case strings.HasPrefix(op, "MOV"), strings.HasPrefix(op, "VMOV"), strings.HasPrefix(op, "FMOV"):
			return true
		}
	}
	return false
}

func sortOffsets(m map[int64]struct{}) []int64 {
	out := make([]int64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func tryDeclSig(scope *types.Scope, sym, resolved string, linknames map[string]string, goarch string, sz types.Sizes) (plan9asm.FuncSig, bool, error) {
	declName := strings.TrimPrefix(sym, "·")
	if strings.ContainsRune(declName, '·') {
		key := strings.ReplaceAll(sym, "∕", "/")
		key = strings.ReplaceAll(key, "·", ".")
		if local, ok := linknames[key]; ok {
			declName = local
		} else {
			return plan9asm.FuncSig{}, false, nil
		}
	}
	obj := scope.Lookup(declName)
	if obj == nil {
		return plan9asm.FuncSig{}, false, nil
	}
	fn, ok := obj.(*types.Func)
	if !ok {
		return plan9asm.FuncSig{}, false, nil
	}
	sig := fn.Type().(*types.Signature)
	if sig.Recv() != nil || sig.Variadic() {
		return plan9asm.FuncSig{}, false, nil
	}

	args, frameParams, nextOff, err := llvmArgsAndFrameSlotsForTuple(sig.Params(), goarch, sz, 0, false)
	if err != nil {
		return plan9asm.FuncSig{}, false, fmt.Errorf("%s: %w", fn.FullName(), err)
	}
	nextOff = alignOff(nextOff, int64(wordSize(goarch)))
	retTys, frameResults, _, err := llvmArgsAndFrameSlotsForTuple(sig.Results(), goarch, sz, nextOff, true)
	if err != nil {
		return plan9asm.FuncSig{}, false, fmt.Errorf("%s: %w", fn.FullName(), err)
	}
	ret := tupleRetType(retTys)
	return plan9asm.FuncSig{
		Name: resolved,
		Args: args,
		Ret:  ret,
		Frame: plan9asm.FrameLayout{
			Params:  frameParams,
			Results: frameResults,
		},
	}, true, nil
}

func tupleRetType(ts []plan9asm.LLVMType) plan9asm.LLVMType {
	switch len(ts) {
	case 0:
		return plan9asm.Void
	case 1:
		return ts[0]
	default:
		parts := make([]string, 0, len(ts))
		for _, t := range ts {
			parts = append(parts, string(t))
		}
		return plan9asm.LLVMType("{ " + strings.Join(parts, ", ") + " }")
	}
}

func splitSymPlusOff(s string) (base string, off int64) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0
	}
	sep := strings.LastIndexAny(s, "+-")
	if sep <= 0 || sep == len(s)-1 {
		return s, 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s[sep:]), 0, 64)
	if err != nil {
		return s, 0
	}
	return strings.TrimSpace(s[:sep]), n
}

func linknameRemoteToLocal(files []*ast.File) map[string]string {
	m := map[string]string{}
	for _, f := range files {
		if f == nil {
			continue
		}
		for _, cg := range f.Comments {
			if cg == nil {
				continue
			}
			for _, c := range cg.List {
				if c == nil {
					continue
				}
				text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
				if !strings.HasPrefix(text, "go:linkname ") {
					continue
				}
				parts := strings.Fields(text)
				if len(parts) < 3 {
					continue
				}
				local := parts[1]
				remote := strings.ReplaceAll(parts[2], "∕", "/")
				m[remote] = local
			}
		}
	}
	return m
}

func llvmArgsAndFrameSlotsForTuple(tup *types.Tuple, goarch string, sz types.Sizes, startOff int64, flattenAgg bool) (args []plan9asm.LLVMType, slots []plan9asm.FrameSlot, nextOff int64, err error) {
	if tup == nil || tup.Len() == 0 {
		return nil, nil, startOff, nil
	}

	word := int64(wordSize(goarch))
	wordTy := plan9asm.I64
	if word == 4 {
		wordTy = plan9asm.LLVMType("i32")
	}
	align := func(off, a int64) int64 {
		if a <= 1 {
			return off
		}
		m := off % a
		if m == 0 {
			return off
		}
		return off + (a - m)
	}

	off := startOff
	argIdx := 0
	for i := 0; i < tup.Len(); i++ {
		t := tup.At(i).Type()
		off = align(off, int64(sz.Alignof(t)))
		if sz.Sizeof(t) == 0 {
			// Zero-sized marker parameters (for example runtime.goexit's
			// neverCallThisFunction) consume neither an LLVM argument nor a
			// physical Plan 9 frame slot.
			continue
		}

		switch u := types.Unalias(t).(type) {
		case *types.Basic:
			if u.Kind() == types.String {
				if flattenAgg {
					args = append(args, plan9asm.Ptr, wordTy)
					slots = append(slots,
						plan9asm.FrameSlot{Offset: off + 0*word, Type: plan9asm.Ptr, Index: argIdx + 0, Field: -1},
						plan9asm.FrameSlot{Offset: off + 1*word, Type: wordTy, Index: argIdx + 1, Field: -1},
					)
					argIdx += 2
					off += int64(sz.Sizeof(t))
					continue
				}
				ty, e := llvmTypeForGo(t, goarch)
				if e != nil {
					return nil, nil, 0, e
				}
				args = append(args, ty)
				slots = append(slots,
					plan9asm.FrameSlot{Offset: off + 0*word, Type: plan9asm.Ptr, Index: argIdx, Field: 0},
					plan9asm.FrameSlot{Offset: off + 1*word, Type: wordTy, Index: argIdx, Field: 1},
				)
				argIdx++
				off += int64(sz.Sizeof(t))
				continue
			}
		case *types.Slice:
			if flattenAgg {
				args = append(args, plan9asm.Ptr, wordTy, wordTy)
				slots = append(slots,
					plan9asm.FrameSlot{Offset: off + 0*word, Type: plan9asm.Ptr, Index: argIdx + 0, Field: -1},
					plan9asm.FrameSlot{Offset: off + 1*word, Type: wordTy, Index: argIdx + 1, Field: -1},
					plan9asm.FrameSlot{Offset: off + 2*word, Type: wordTy, Index: argIdx + 2, Field: -1},
				)
				argIdx += 3
				off += int64(sz.Sizeof(t))
				continue
			}
			ty, e := llvmTypeForGo(t, goarch)
			if e != nil {
				return nil, nil, 0, e
			}
			args = append(args, ty)
			slots = append(slots,
				plan9asm.FrameSlot{Offset: off + 0*word, Type: plan9asm.Ptr, Index: argIdx, Field: 0},
				plan9asm.FrameSlot{Offset: off + 1*word, Type: wordTy, Index: argIdx, Field: 1},
				plan9asm.FrameSlot{Offset: off + 2*word, Type: wordTy, Index: argIdx, Field: 2},
			)
			argIdx++
			off += int64(sz.Sizeof(t))
			continue
		case *types.Interface:
			// An interface value is its runtime type/itab pointer followed by
			// its data pointer. Keep the two physical FP slots visible even
			// when the LLVM function signature uses one aggregate argument.
			if flattenAgg {
				args = append(args, plan9asm.Ptr, plan9asm.Ptr)
				slots = append(slots,
					plan9asm.FrameSlot{Offset: off + 0*word, Type: plan9asm.Ptr, Index: argIdx + 0, Field: -1},
					plan9asm.FrameSlot{Offset: off + 1*word, Type: plan9asm.Ptr, Index: argIdx + 1, Field: -1},
				)
				argIdx += 2
				off += int64(sz.Sizeof(t))
				continue
			}
			args = append(args, plan9asm.LLVMType("{ ptr, ptr }"))
			slots = append(slots,
				plan9asm.FrameSlot{Offset: off + 0*word, Type: plan9asm.Ptr, Index: argIdx, Field: 0},
				plan9asm.FrameSlot{Offset: off + 1*word, Type: plan9asm.Ptr, Index: argIdx, Field: 1},
			)
			argIdx++
			off += int64(sz.Sizeof(t))
			continue
		}

		ty, e := llvmTypeForGo(t, goarch)
		if e != nil {
			return nil, nil, 0, e
		}
		args = append(args, ty)
		slots = append(slots, plan9asm.FrameSlot{Offset: off, Type: ty, Index: argIdx, Field: -1})
		argIdx++
		off += int64(sz.Sizeof(t))
	}
	return args, slots, off, nil
}

func llvmTypeForGo(t types.Type, goarch string) (plan9asm.LLVMType, error) {
	switch tt := types.Unalias(t).(type) {
	case *types.Basic:
		switch tt.Kind() {
		case types.Bool:
			return plan9asm.I1, nil
		case types.UnsafePointer:
			return plan9asm.Ptr, nil
		case types.Int8, types.Uint8:
			return plan9asm.I8, nil
		case types.Int16, types.Uint16:
			return plan9asm.I16, nil
		case types.Int32, types.Uint32:
			return plan9asm.I32, nil
		case types.Int64, types.Uint64:
			return plan9asm.I64, nil
		case types.Int, types.Uint, types.Uintptr:
			if wordSize(goarch) == 8 {
				return plan9asm.I64, nil
			}
			return plan9asm.I32, nil
		case types.Float32:
			return plan9asm.LLVMType("float"), nil
		case types.Float64:
			return plan9asm.LLVMType("double"), nil
		case types.String:
			if wordSize(goarch) == 8 {
				return plan9asm.LLVMType("{ ptr, i64 }"), nil
			}
			return plan9asm.LLVMType("{ ptr, i32 }"), nil
		default:
			return "", fmt.Errorf("unsupported basic type %s", tt.String())
		}
	case *types.Pointer:
		return plan9asm.Ptr, nil
	case *types.Signature, *types.Map, *types.Chan:
		// Go function values, maps, and channels occupy one pointer-sized word
		// in an assembly frame. The pointee/runtime descriptor is intentionally
		// opaque to the instruction translator.
		return plan9asm.Ptr, nil
	case *types.Interface:
		return plan9asm.LLVMType("{ ptr, ptr }"), nil
	case *types.Slice:
		if wordSize(goarch) == 8 {
			return plan9asm.LLVMType("{ ptr, i64, i64 }"), nil
		}
		return plan9asm.LLVMType("{ ptr, i32, i32 }"), nil
	case *types.Named:
		return llvmTypeForGo(tt.Underlying(), goarch)
	default:
		return "", fmt.Errorf("unsupported type %s", t.String())
	}
}

func wordSize(goarch string) int {
	switch goarch {
	case "amd64", "arm64", "loong64", "mips64", "mips64le", "ppc64", "ppc64le", "riscv64", "s390x", "wasm":
		return 8
	default:
		return 4
	}
}

func alignOff(off, a int64) int64 {
	if a <= 1 {
		return off
	}
	m := off % a
	if m == 0 {
		return off
	}
	return off + (a - m)
}

func check(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
