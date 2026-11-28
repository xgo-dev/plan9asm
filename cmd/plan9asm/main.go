package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"

	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"runtime"
	"sort"

	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/cmd/internal/asmfile"

	"golang.org/x/tools/go/packages"
)

type goListPackage struct {
	Dir        string   `json:"Dir"`
	ImportPath string   `json:"ImportPath"`
	SFiles     []string `json:"SFiles"`
}

type translation struct {
	LLVMIR    string
	Functions []asmfile.FunctionInfo
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
	if _, err := asmfile.Architecture(goarch); err != nil {
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
	if _, err := asmfile.Architecture(goarch); err != nil {
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
		File      string                 `json:"file"`
		Output    string                 `json:"output"`
		Functions []asmfile.FunctionInfo `json:"functions"`
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
			tr, err := translateAsmForPackage(pkg, sfile, goos, goarch, annotate)
			if err != nil {
				return fmt.Errorf("transpile %s: %w", sfile, err)
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

	tr, err := translateAsmForPackage(pkg, asmPath, goos, goarch, annotate)
	if err != nil {
		return err
	}
	if err := writeTextFile(outFile, tr.LLVMIR); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote llvm ir: %s\n", outFile)

	if metaFile != "" {
		payload := struct {
			Package   string                 `json:"package"`
			File      string                 `json:"file"`
			GOOS      string                 `json:"goos"`
			GOARCH    string                 `json:"goarch"`
			Functions []asmfile.FunctionInfo `json:"functions"`
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

func asmPackage(pkg *packages.Package) plan9asm.GoPackage {
	imports := make(map[string]*types.Package, len(pkg.Imports))
	for path, imported := range pkg.Imports {
		if imported != nil && imported.Types != nil {
			imports[path] = imported.Types
		}
	}
	return plan9asm.GoPackage{
		Path:    pkg.PkgPath,
		Types:   pkg.Types,
		Imports: imports,
		Syntax:  pkg.Syntax,
	}
}

func translateAsmForPackage(pkg *packages.Package, path, goos, goarch string, annotate bool) (translation, error) {
	mod, funcs, err := asmfile.TranslatePackageFile(asmPackage(pkg), pkg.TypesSizes, path, goos, goarch, targetTriple(goos, goarch), annotate)
	if err != nil {
		return translation{}, err
	}
	defer mod.Dispose()
	return translation{LLVMIR: mod.String(), Functions: funcs}, nil
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
	case "freebsd", "netbsd", "dragonfly":
		if goarch == "amd64" {
			return "x86_64-unknown-" + goos
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

func check(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
