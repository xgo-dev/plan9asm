package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"

	"strings"
	"time"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/cmd/internal/asmfile"

	"golang.org/x/tools/go/packages"
)

type asmTask struct {
	PkgPath string `json:"pkg_path"`
	AsmFile string `json:"asm_file"`
	OutLL   string `json:"out_ll"`
}

type failItem struct {
	PkgPath         string           `json:"pkg_path"`
	AsmFile         string           `json:"asm_file"`
	Err             string           `json:"err"`
	Unsupported     []string         `json:"unsupported,omitempty"`
	UnsupportedHits []unsupportedHit `json:"unsupported_hits,omitempty"`
}

type opCount struct {
	Op    string `json:"op"`
	Count int    `json:"count"`
}

type unsupportedHit struct {
	Op     string `json:"op"`
	Line   int    `json:"line"`
	Source string `json:"source"`
}

type runReport struct {
	Goos           string     `json:"goos"`
	Goarch         string     `json:"goarch"`
	Patterns       []string   `json:"patterns"`
	TotalPkgs      int        `json:"total_pkgs"`
	AsmPackages    []string   `json:"asm_packages,omitempty"`
	TotalAsm       int        `json:"total_asm"`
	Success        int        `json:"success"`
	Failed         int        `json:"failed"`
	Duration       string     `json:"duration"`
	UnsupportedOps []opCount  `json:"unsupported_ops,omitempty"`
	Fails          []failItem `json:"fails,omitempty"`
}

type targetSpec struct {
	Goos   string `json:"goos"`
	Goarch string `json:"goarch"`
}

type targetTasks struct {
	Target string    `json:"target"`
	Tasks  []asmTask `json:"tasks"`
}

type matrixReport struct {
	Targets      []runReport `json:"targets"`
	TotalTargets int         `json:"total_targets"`
	TotalAsm     int         `json:"total_asm"`
	Success      int         `json:"success"`
	Failed       int         `json:"failed"`
}

type compileConfig struct {
	Enabled bool
	LLC     string
	KeepObj bool
}

func main() {
	var (
		goos       = flag.String("goos", runtime.GOOS, "target GOOS")
		goarch     = flag.String("goarch", runtime.GOARCH, "target GOARCH (386/amd64/arm/arm64/wasm)")
		targets    = flag.String("targets", "", "comma-separated GOOS/GOARCH list (e.g. linux/amd64,windows/arm64)")
		allTargets = flag.Bool("all-targets", false, "run the complete default Plan 9 target matrix")
		patterns   = flag.String("patterns", "std", "comma-separated package patterns")
		modulePath = flag.String("module-path", "", "only include packages owned by this module path")
		outDir     = flag.String("out", "", "output dir for generated .ll files")
		annotate   = flag.Bool("annotate", false, "emit source asm lines as IR comments")
		limit      = flag.Int("limit", 0, "max number of asm files per target (0 means all)")
		keepGoing  = flag.Bool("keep-going", true, "continue on per-file failures")
		listOnly   = flag.Bool("list-only", false, "only print asm task list and exit")
		compile    = flag.Bool("compile", false, "compile generated .ll to .o via llc")
		llcPath    = flag.String("llc", "", "path to llc executable (auto-detect when empty)")
		keepObj    = flag.Bool("keep-obj", false, "keep generated .o files when -compile is set")
		strictLoad = flag.Bool("strict-load", false, "fail when go/packages reports any package loading error")
		reportOut  = flag.String("report", "", "optional report json path")
		repoRoot   = flag.String("repo-root", "../..", "repo root for extracting supported instruction set")
	)
	flag.Parse()

	pats := splitCSV(*patterns)
	if len(pats) == 0 {
		fatalf("empty -patterns")
	}

	specs, err := resolveTargets(*goos, *goarch, *targets, *allTargets)
	if err != nil {
		fatalf("%v", err)
	}
	ccfg, err := resolveCompileConfig(*compile, *llcPath, *keepObj)
	if err != nil {
		fatalf("%v", err)
	}

	baseOut := *outDir
	if baseOut == "" {
		if len(specs) == 1 {
			baseOut = filepath.Join("_out", "plan9asmll", targetID(specs[0]))
		} else {
			baseOut = filepath.Join("_out", "plan9asmll")
		}
	}

	allReports := make([]runReport, 0, len(specs))
	taskLists := make([]targetTasks, 0, len(specs))
	exitCode := 0

	for _, spec := range specs {
		runOutDir := baseOut
		if len(specs) > 1 {
			runOutDir = filepath.Join(baseOut, targetID(spec))
			fmt.Fprintf(os.Stderr, "\n== target %s ==\n", targetID(spec))
		}
		rep, tasks, err := runOneTarget(spec, pats, *modulePath, runOutDir, *annotate, *limit, *keepGoing, *listOnly, *strictLoad, *repoRoot, ccfg)
		if err != nil {
			fatalf("%s: %v", targetID(spec), err)
		}
		if *listOnly {
			taskLists = append(taskLists, targetTasks{Target: targetID(spec), Tasks: tasks})
			continue
		}
		if rep.Failed != 0 {
			exitCode = 1
		}
		allReports = append(allReports, rep)
	}

	if *listOnly {
		var out any
		if len(taskLists) == 1 {
			out = taskLists[0].Tasks
		} else {
			out = taskLists
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		check(enc.Encode(out))
		return
	}

	if len(allReports) == 1 {
		writeReport(*reportOut, allReports[0])
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return
	}

	mr := matrixReport{
		Targets:      allReports,
		TotalTargets: len(allReports),
	}
	for _, r := range allReports {
		mr.TotalAsm += r.TotalAsm
		mr.Success += r.Success
		mr.Failed += r.Failed
	}
	writeReport(*reportOut, mr)
	if exitCode != 0 {
		fmt.Fprintf(os.Stderr, "\nmatrix finished with failures: success=%d failed=%d total=%d\n", mr.Success, mr.Failed, mr.TotalAsm)
		os.Exit(exitCode)
	}
	fmt.Fprintf(os.Stderr, "\nmatrix finished: success=%d total=%d\n", mr.Success, mr.TotalAsm)
}

func resolveCompileConfig(compile bool, llcPath string, keepObj bool) (compileConfig, error) {
	cfg := compileConfig{Enabled: compile, LLC: strings.TrimSpace(llcPath), KeepObj: keepObj}
	if !cfg.Enabled {
		return cfg, nil
	}
	if cfg.LLC != "" {
		if err := requireLLVM22LLC(cfg.LLC); err != nil {
			return compileConfig{}, fmt.Errorf("-llc %q requires LLVM 22: %w", cfg.LLC, err)
		}
		return cfg, nil
	}
	names := []string{"llc-22", "llc"}
	for _, name := range names {
		if p, err := exec.LookPath(name); err == nil && p != "" {
			if requireLLVM22LLC(p) == nil {
				cfg.LLC = p
				return cfg, nil
			}
		}
	}
	return compileConfig{}, fmt.Errorf("-compile is set but LLVM 22 llc is not found in PATH; install llc-22 or set -llc to an LLVM 22 binary")
}

var llvmLLCVersionRE = regexp.MustCompile(`(?m)\bLLVM version ([0-9]+)(?:\.|$)`)

func requireLLVM22LLC(path string) error {
	out, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("run --version: %w", err)
	}
	match := llvmLLCVersionRE.FindSubmatch(out)
	if len(match) != 2 {
		return fmt.Errorf("cannot determine LLVM version from %q", strings.TrimSpace(string(out)))
	}
	if string(match[1]) != "22" {
		return fmt.Errorf("found LLVM %s", match[1])
	}
	return nil
}

func writeReport(path string, payload any) {
	if path == "" {
		return
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	check(err)
	data = append(data, '\n')
	check(os.WriteFile(path, data, 0644))
}

func resolveTargets(goos, goarch, targets string, allTargets bool) ([]targetSpec, error) {
	if allTargets {
		return defaultMatrixTargets(), nil
	}
	if strings.TrimSpace(targets) == "" {
		if _, err := asmfile.Architecture(goarch); err != nil {
			return nil, err
		}
		return []targetSpec{{Goos: goos, Goarch: goarch}}, nil
	}
	parts := splitCSV(targets)
	out := make([]targetSpec, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		ts, err := parseTargetSpec(p)
		if err != nil {
			return nil, err
		}
		if _, err := asmfile.Architecture(ts.Goarch); err != nil {
			return nil, err
		}
		id := targetID(ts)
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, ts)
	}
	return out, nil
}

func parseTargetSpec(s string) (targetSpec, error) {
	s = strings.TrimSpace(s)
	i := strings.IndexByte(s, '/')
	if i <= 0 || i >= len(s)-1 {
		return targetSpec{}, fmt.Errorf("invalid target %q, expect GOOS/GOARCH", s)
	}
	return targetSpec{
		Goos:   strings.TrimSpace(s[:i]),
		Goarch: strings.TrimSpace(s[i+1:]),
	}, nil
}

func defaultMatrixTargets() []targetSpec {
	return []targetSpec{
		{Goos: "darwin", Goarch: "amd64"},
		{Goos: "darwin", Goarch: "arm64"},
		{Goos: "linux", Goarch: "386"},
		{Goos: "linux", Goarch: "amd64"},
		{Goos: "linux", Goarch: "arm"},
		{Goos: "linux", Goarch: "arm64"},
		{Goos: "windows", Goarch: "386"},
		{Goos: "windows", Goarch: "amd64"},
		{Goos: "windows", Goarch: "arm64"},
		{Goos: "js", Goarch: "wasm"},
		{Goos: "wasip1", Goarch: "wasm"},
	}
}

func targetID(t targetSpec) string {
	return t.Goos + "-" + t.Goarch
}

func runOneTarget(spec targetSpec, pats []string, modulePath, outDir string, annotate bool, limit int, keepGoing bool, listOnly, strictLoad bool, repoRoot string, ccfg compileConfig) (runReport, []asmTask, error) {
	arch, err := asmfile.Architecture(spec.Goarch)
	if err != nil {
		return runReport{}, nil, err
	}
	pkgs, err := loadPkgs(spec.Goos, spec.Goarch, pats, modulePath, strictLoad)
	if err != nil {
		return runReport{}, nil, fmt.Errorf("load packages: %w", err)
	}
	pkgByPath := map[string]*packages.Package{}
	for _, p := range pkgs {
		if p != nil && p.PkgPath != "" {
			pkgByPath[p.PkgPath] = p
		}
	}
	tasks, asmPackages := collectAsmTasks(pkgs, outDir)
	if limit > 0 && limit < len(tasks) {
		tasks = tasks[:limit]
	}
	if listOnly {
		return runReport{}, tasks, nil
	}
	rep := runReport{
		Goos:        spec.Goos,
		Goarch:      spec.Goarch,
		Patterns:    pats,
		TotalPkgs:   len(asmPackages),
		AsmPackages: asmPackages,
		TotalAsm:    len(tasks),
	}
	if len(tasks) == 0 {
		fmt.Fprintf(os.Stderr, "no asm files found for patterns=%v (%s/%s)\n", pats, spec.Goos, spec.Goarch)
		return rep, nil, nil
	}

	check(os.MkdirAll(outDir, 0755))
	triple := targetTriple(spec.Goos, spec.Goarch)
	supportedOps, supErr := extractSupportedOps(repoRoot, spec.Goarch)
	if supErr != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot extract supported ops from %s: %v\n", repoRoot, supErr)
	}
	unsupportedAgg := map[string]int{}
	start := time.Now()

	for i, t := range tasks {
		idx := i + 1
		pkg := pkgByPath[t.PkgPath]
		if pkg == nil {
			fmt.Fprintf(os.Stderr, "[%d/%d] FAIL %s\n", idx, len(tasks), t.AsmFile)
			printFailureReason("package not loaded")
			rep.Failed++
			rep.Fails = append(rep.Fails, failItem{PkgPath: t.PkgPath, AsmFile: t.AsmFile, Err: "package not loaded"})
			if !keepGoing {
				break
			}
			continue
		}
		err := compileOne(pkg, spec.Goos, spec.Goarch, triple, t, annotate, ccfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%d/%d] FAIL %s\n", idx, len(tasks), t.AsmFile)
			printFailureReason(err.Error())
			unsupported, hits := unsupportedInAsmFile(t.AsmFile, arch, supportedOps)
			if len(unsupported) > 0 {
				fmt.Fprintf(os.Stderr, "  unsupported: %s\n", strings.Join(unsupported, ", "))
				for _, op := range unsupported {
					unsupportedAgg[op]++
				}
			}
			if len(hits) > 0 {
				printUnsupportedHits(hits)
			}
			rep.Failed++
			rep.Fails = append(rep.Fails, failItem{
				PkgPath:         t.PkgPath,
				AsmFile:         t.AsmFile,
				Err:             err.Error(),
				Unsupported:     unsupported,
				UnsupportedHits: hits,
			})
			if !keepGoing {
				break
			}
			continue
		}
		fmt.Fprintf(os.Stderr, "[%d/%d] OK   %s\n", idx, len(tasks), t.AsmFile)
		rep.Success++
	}

	rep.Duration = time.Since(start).String()
	rep.UnsupportedOps = flattenUnsupportedAgg(unsupportedAgg)
	if rep.Failed != 0 {
		fmt.Fprintf(os.Stderr, "finished with failures: success=%d failed=%d total=%d\n", rep.Success, rep.Failed, rep.TotalAsm)
	} else {
		fmt.Fprintf(os.Stderr, "finished: success=%d total=%d\n", rep.Success, rep.TotalAsm)
	}
	return rep, nil, nil
}

func compileOne(pkg *packages.Package, goos, goarch, triple string, t asmTask, annotate bool, ccfg compileConfig) error {
	mod, _, err := asmfile.TranslatePackageFile(asmPackage(pkg), pkg.TypesSizes, t.AsmFile, goos, goarch, triple, annotate)
	if err != nil {
		return err
	}
	defer mod.Dispose()
	if err := llvm.VerifyModule(mod, llvm.ReturnStatusAction); err != nil {
		return fmt.Errorf("verify module: %w", err)
	}
	ll := mod.String()
	if err := os.MkdirAll(filepath.Dir(t.OutLL), 0755); err != nil {
		return fmt.Errorf("mkdir out dir: %w", err)
	}
	if err := os.WriteFile(t.OutLL, []byte(ll), 0644); err != nil {
		return fmt.Errorf("write ll: %w", err)
	}
	if ccfg.Enabled {
		objPath := strings.TrimSuffix(t.OutLL, filepath.Ext(t.OutLL)) + ".o"
		// Never count an artifact left by an earlier invocation as current.
		tmp, err := os.CreateTemp(filepath.Dir(objPath), ".plan9asm-*.o")
		if err != nil {
			return err
		}
		tempObj := tmp.Name()
		defer os.Remove(tempObj)
		if err := tmp.Close(); err != nil {
			return err
		}
		args := []string{"-mtriple=" + triple}
		args = append(args, llcExtraArgs(goarch)...)
		args = append(args, "-filetype=obj", t.OutLL, "-o", tempObj)
		cmd := exec.Command(ccfg.LLC, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			s := strings.TrimSpace(string(out))
			if s == "" {
				return fmt.Errorf("llc compile failed: %w", err)
			}
			return fmt.Errorf("llc compile failed: %w\n%s", err, s)
		}
		fi, err := os.Stat(tempObj)
		if err != nil {
			return fmt.Errorf("check llc object: %w", err)
		}
		if !fi.Mode().IsRegular() || fi.Size() == 0 {
			return fmt.Errorf("llc produced no object for %s", t.AsmFile)
		}
		if ccfg.KeepObj {
			if err := os.Rename(tempObj, objPath); err != nil {
				return fmt.Errorf("save object: %w", err)
			}
		}
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

func llcExtraArgs(goarch string) []string {
	switch goarch {
	case "amd64":
		// Enable ISA features used by stdlib crypto/runtime asm paths.
		return []string{
			"-mcpu=haswell",
			"-mattr=+aes,+ssse3,+sse4.1,+sse4.2,+pclmul,+avx,+avx2,+sha,+popcnt,+adx",
		}
	case "arm64":
		// CRC32 intrinsics in hash/crc32 require +crc.
		return []string{"-mattr=+crc"}
	default:
		return nil
	}
}

func loadPkgs(goos, goarch string, patterns []string, modulePath string, strict bool) ([]*packages.Package, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedModule |
			packages.NeedDeps |
			packages.NeedImports |
			packages.NeedTypes |
			packages.NeedTypesInfo |
			packages.NeedTypesSizes |
			packages.NeedSyntax,
		Env: append(os.Environ(),
			"GOOS="+goos,
			"GOARCH="+goarch,
		),
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, err
	}
	pkgs = filterPackagesByModule(pkgs, modulePath)
	if count := packages.PrintErrors(pkgs); strict && count != 0 {
		return nil, fmt.Errorf("%d package loading error(s)", count)
	}
	return pkgs, nil
}

func filterPackagesByModule(pkgs []*packages.Package, modulePath string) []*packages.Package {
	if modulePath == "" {
		return pkgs
	}
	filtered := make([]*packages.Package, 0, len(pkgs))
	for _, pkg := range pkgs {
		if pkg != nil && pkg.Module != nil && pkg.Module.Path == modulePath {
			filtered = append(filtered, pkg)
		}
	}
	return filtered
}

func collectAsmTasks(pkgs []*packages.Package, outDir string) ([]asmTask, []string) {
	tasks := make([]asmTask, 0)
	asmPackages := make([]string, 0)
	seenPkg := map[string]bool{}
	for _, p := range pkgs {
		if p == nil || p.PkgPath == "" {
			continue
		}
		if seenPkg[p.PkgPath] {
			continue
		}
		seenPkg[p.PkgPath] = true
		files := asmFilesOfPkg(p)
		if len(files) == 0 {
			continue
		}
		asmPackages = append(asmPackages, p.PkgPath)
		for _, f := range files {
			out := filepath.Join(outDir, filepath.FromSlash(p.PkgPath), filepath.Base(f)+".ll")
			tasks = append(tasks, asmTask{PkgPath: p.PkgPath, AsmFile: f, OutLL: out})
		}
	}
	sort.Slice(tasks, func(i, j int) bool {
		if tasks[i].PkgPath != tasks[j].PkgPath {
			return tasks[i].PkgPath < tasks[j].PkgPath
		}
		return tasks[i].AsmFile < tasks[j].AsmFile
	})
	sort.Strings(asmPackages)
	return tasks, asmPackages
}

func asmFilesOfPkg(p *packages.Package) []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0)
	for _, f := range p.OtherFiles {
		if isAsmFile(f) && assemblyFileHasContent(f) {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

func assemblyFileHasContent(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		// Preserve unreadable files as tasks so compilation reports the error.
		return true
	}
	return assemblySourceHasContent(data)
}

func assemblySourceHasContent(data []byte) bool {
	for i := 0; i < len(data); {
		switch {
		case data[i] == ' ' || data[i] == '\t' || data[i] == '\r' || data[i] == '\n' || data[i] == '\f':
			i++
		case i+1 < len(data) && data[i] == '/' && data[i+1] == '/':
			i += 2
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case i+1 < len(data) && data[i] == '/' && data[i+1] == '*':
			end := strings.Index(string(data[i+2:]), "*/")
			if end < 0 {
				return true
			}
			i += end + 4
		default:
			return true
		}
	}
	return false
}

func isAsmFile(path string) bool {
	return filepath.Ext(path) == ".s"
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
		case "386":
			return "i386-unknown-linux-gnu"
		case "arm":
			return "armv7-unknown-linux-gnueabihf"
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
			return "wasm32-wasi"
		}
	}
	return ""
}

var (
	reCaseString = regexp.MustCompile(`case\s+"([A-Za-z0-9_.$]+)"`)
	reCaseOp     = regexp.MustCompile(`case\s+(?:asm\.)?Op([A-Za-z0-9_]+)`)
	reQuotedOp   = regexp.MustCompile(`"([A-Za-z0-9_.$]+)"`)
	reOpToken    = regexp.MustCompile(`Op([A-Za-z0-9_]+)`)
)

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func check(err error) {
	if err == nil {
		return
	}
	fatalf("%v", err)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func printFailureReason(err string) {
	lines := strings.Split(strings.TrimSpace(err), "\n")
	if len(lines) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "  reason: %s\n", lines[0])
	for _, ln := range lines[1:] {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		fmt.Fprintf(os.Stderr, "          %s\n", ln)
	}
}

func normalizeOp(op string) string {
	op = strings.ToUpper(strings.TrimSpace(op))
	if op == "" {
		return ""
	}
	if i := strings.IndexByte(op, '.'); i >= 0 {
		op = op[:i]
	}
	if strings.ContainsAny(op, "(),;*/") {
		return ""
	}
	if strings.Contains(op, "_") {
		return ""
	}
	return op
}

func isDirective(op string) bool {
	switch op {
	case "TEXT", "DATA", "GLOBL", "BYTE", "WORD", "LONG", "QUAD", "PCALIGN", "FUNCDATA", "PCDATA":
		return true
	default:
		return false
	}
}

func extractSupportedOps(repoRoot, goarch string) (map[string]struct{}, error) {
	supported := map[string]struct{}{
		"RET":      {},
		"TEXT":     {},
		"GLOBL":    {},
		"DATA":     {},
		"BYTE":     {},
		"WORD":     {},
		"LONG":     {},
		"QUAD":     {},
		"PCALIGN":  {},
		"FUNCDATA": {},
		"PCDATA":   {},
	}

	backendArch := goarch
	internalDir := goarch
	if goarch == "386" {
		backendArch = "amd64"
		internalDir = "x86"
	} else if goarch == "amd64" {
		internalDir = "x86"
	}
	var files []string
	seen := map[string]struct{}{}
	for _, glob := range []string{
		filepath.Join(repoRoot, "internal", internalDir, "*.go"),
		filepath.Join(repoRoot, backendArch+"_*.go"),
	} {
		matches, err := filepath.Glob(glob)
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			if _, ok := seen[m]; ok {
				continue
			}
			seen[m] = struct{}{}
			files = append(files, m)
		}
	}
	files = append(files, filepath.Join(repoRoot, "translate.go"))
	sort.Strings(files)

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		for _, m := range reCaseString.FindAllSubmatch(src, -1) {
			nop := normalizeOp(string(m[1]))
			if nop != "" {
				supported[nop] = struct{}{}
			}
		}
		for _, m := range reCaseOp.FindAllSubmatch(src, -1) {
			nop := normalizeOp(string(m[1]))
			if nop != "" {
				supported[nop] = struct{}{}
			}
		}
		// Handle multi-value case clauses like:
		// case "A", "B", "C":
		for _, ln := range strings.Split(string(src), "\n") {
			if !strings.Contains(ln, "case") {
				continue
			}
			for _, m := range reQuotedOp.FindAllStringSubmatch(ln, -1) {
				nop := normalizeOp(m[1])
				if nop != "" {
					supported[nop] = struct{}{}
				}
			}
			for _, m := range reOpToken.FindAllStringSubmatch(ln, -1) {
				nop := normalizeOp(m[1])
				if nop != "" {
					supported[nop] = struct{}{}
				}
			}
		}
	}
	return supported, nil
}

func unsupportedInAsmFile(path string, arch plan9asm.Arch, supported map[string]struct{}) ([]string, []unsupportedHit) {
	if len(supported) == 0 {
		return nil, nil
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	hits := scanUnsupportedHits(src, supported)
	file, err := plan9asm.Parse(arch, string(src))
	if err != nil {
		if len(hits) == 0 {
			return nil, nil
		}
		return uniqueUnsupportedOpsFromHits(hits), hits
	}
	seen := map[string]struct{}{}
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			nop := normalizeOp(string(ins.Op))
			if nop == "" || nop == "LABEL" || isDirective(nop) {
				continue
			}
			if _, ok := supported[nop]; !ok {
				seen[nop] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		return nil, hits
	}
	out := make([]string, 0, len(seen))
	for op := range seen {
		out = append(out, op)
	}
	sort.Strings(out)
	// If parser-based set and line-based scan differ, prefer parser result for
	// op list but still keep line hits from source scanning.
	return out, hits
}

func flattenUnsupportedAgg(agg map[string]int) []opCount {
	if len(agg) == 0 {
		return nil
	}
	out := make([]opCount, 0, len(agg))
	for op, n := range agg {
		out = append(out, opCount{Op: op, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Op < out[j].Op
	})
	return out
}

func uniqueUnsupportedOpsFromHits(hits []unsupportedHit) []string {
	seen := map[string]struct{}{}
	for _, h := range hits {
		seen[h.Op] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for op := range seen {
		out = append(out, op)
	}
	sort.Strings(out)
	return out
}

func scanUnsupportedHits(src []byte, supported map[string]struct{}) []unsupportedHit {
	lines := strings.Split(string(src), "\n")
	out := make([]unsupportedHit, 0)
	for i, line := range lines {
		lineno := i + 1
		raw := stripLineComment(line)
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		stmts := strings.Split(raw, ";")
		for _, stmt := range stmts {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			// Skip labels.
			if strings.HasSuffix(stmt, ":") {
				continue
			}
			// Handle "label: INSTR ..." on one line.
			if c := strings.IndexByte(stmt, ':'); c >= 0 {
				left := strings.TrimSpace(stmt[:c])
				right := strings.TrimSpace(stmt[c+1:])
				if left != "" && right != "" && !strings.Contains(left, " ") && !strings.Contains(left, "\t") {
					stmt = right
				}
			}
			fields := strings.Fields(stmt)
			if len(fields) == 0 {
				continue
			}
			op := normalizeOp(fields[0])
			if op == "" || op == "LABEL" || isDirective(op) {
				continue
			}
			if _, ok := supported[op]; ok {
				continue
			}
			out = append(out, unsupportedHit{
				Op:     op,
				Line:   lineno,
				Source: stmt,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		if out[i].Op != out[j].Op {
			return out[i].Op < out[j].Op
		}
		return out[i].Source < out[j].Source
	})
	return out
}

func stripLineComment(s string) string {
	// Plan9 asm comments typically start with //.
	if i := strings.Index(s, "//"); i >= 0 {
		return s[:i]
	}
	return s
}

func printUnsupportedHits(hits []unsupportedHit) {
	for _, h := range hits {
		fmt.Fprintf(os.Stderr, "    L%-5d %-12s %s\n", h.Line, h.Op, h.Source)
	}
}
