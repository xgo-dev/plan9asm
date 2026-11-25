package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm"
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
		if _, err := toPlan9Arch(goarch); err != nil {
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
		if _, err := toPlan9Arch(ts.Goarch); err != nil {
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
	arch, err := toPlan9Arch(spec.Goarch)
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
		err := compileOne(pkg, arch, spec.Goarch, triple, t, annotate, ccfg)
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

func compileOne(pkg *packages.Package, arch plan9asm.Arch, goarch, triple string, t asmTask, annotate bool, ccfg compileConfig) error {
	src, err := os.ReadFile(t.AsmFile)
	if err != nil {
		return fmt.Errorf("read asm: %w", err)
	}
	file, err := plan9asm.Parse(arch, string(src))
	if err != nil {
		if strings.Contains(err.Error(), "no TEXT directive found") {
			return nil
		}
		return fmt.Errorf("parse asm: %w", err)
	}
	if len(file.Funcs) == 0 {
		return nil
	}

	resolve := resolveSymFunc(pkg.PkgPath)
	sigs, err := sigsForAsmFile(pkg, file, resolve, goarch)
	if err != nil {
		return fmt.Errorf("infer signatures: %w", err)
	}
	mod, err := plan9asm.TranslateModule(file, plan9asm.Options{
		TargetTriple:   triple,
		ResolveSym:     resolve,
		Sigs:           sigs,
		Goarch:         goarch,
		AnnotateSource: annotate,
	})
	if err != nil {
		return fmt.Errorf("translate: %w", err)
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
		args := []string{"-mtriple=" + triple}
		args = append(args, llcExtraArgs(goarch)...)
		args = append(args, "-filetype=obj", t.OutLL, "-o", objPath)
		cmd := exec.Command(ccfg.LLC, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			s := strings.TrimSpace(string(out))
			if s == "" {
				return fmt.Errorf("llc compile failed: %w", err)
			}
			return fmt.Errorf("llc compile failed: %w\n%s", err, s)
		}
		if !ccfg.KeepObj {
			_ = os.Remove(objPath)
		}
	}
	return nil
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
		return "", fmt.Errorf("unsupported arch %q", goarch)
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
var (
	reCaseString = regexp.MustCompile(`case\s+"([A-Za-z0-9_.$]+)"`)
	reCaseOp     = regexp.MustCompile(`case\s+(?:asm\.)?Op([A-Za-z0-9_]+)`)
	reQuotedOp   = regexp.MustCompile(`"([A-Za-z0-9_.$]+)"`)
	reOpToken    = regexp.MustCompile(`Op([A-Za-z0-9_]+)`)
)

func stripABISuffix(sym string) string {
	return abiSuffixRe.ReplaceAllString(sym, "")
}

func sigsForAsmFile(pkg *packages.Package, file *plan9asm.File, resolve func(string) string, goarch string) (map[string]plan9asm.FuncSig, error) {
	sigs := map[string]plan9asm.FuncSig{}
	if pkg == nil || pkg.Types == nil || pkg.Types.Scope() == nil {
		for _, fn := range file.Funcs {
			fs := fallbackSigForAsmFunc(fn, resolve(stripABISuffix(fn.Sym)))
			sigs[fs.Name] = fs
		}
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

	for _, fn := range file.Funcs {
		sym := stripABISuffix(fn.Sym)
		resolved := resolve(sym)
		if resolved == "" {
			continue
		}
		fs, ok, err := tryDeclSig(scope, sym, resolved, linknames, goarch, sz)
		if err != nil {
			return nil, err
		}
		if !ok {
			fs = fallbackSigForAsmFunc(fn, resolved)
		}
		sigs[resolved] = fs
	}

	addTargetSig := func(sym string, caller plan9asm.FuncSig, tail bool) {
		if sym == "" {
			return
		}
		sym = stripABISuffix(strings.TrimSuffix(sym, "<>"))
		resolved := resolve(sym)
		if resolved == "" {
			return
		}
		if _, ok := sigs[resolved]; ok {
			return
		}
		fs, ok, err := tryDeclSig(scope, sym, resolved, linknames, goarch, sz)
		if err == nil && ok {
			sigs[resolved] = fs
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
		caller := sigs[resolve(stripABISuffix(fn.Sym))]
		for _, ins := range fn.Instrs {
			op := strings.ToUpper(string(ins.Op))
			tail := op == "JMP" || op == "B"
			if !(tail || op == "CALL" || op == "BL") {
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
		}
	}

	return sigs, nil
}

func fallbackSigForAsmFunc(fn plan9asm.Func, resolved string) plan9asm.FuncSig {
	paramOff := map[int64]struct{}{}
	retOff := map[int64]struct{}{}

	for _, ins := range fn.Instrs {
		op := strings.ToUpper(string(ins.Op))
		for i, a := range ins.Args {
			if a.Kind != plan9asm.OpFP {
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
	params := make([]plan9asm.FrameSlot, 0, len(paramList))
	for i, off := range paramList {
		params = append(params, plan9asm.FrameSlot{Offset: off, Type: plan9asm.I64, Index: i, Field: -1})
	}
	results := make([]plan9asm.FrameSlot, 0, len(retList))
	for i, off := range retList {
		results = append(results, plan9asm.FrameSlot{Offset: off, Type: plan9asm.I64, Index: i, Field: -1})
	}

	args := make([]plan9asm.LLVMType, len(params))
	for i := range args {
		args[i] = plan9asm.I64
	}
	ret := plan9asm.Void
	switch len(results) {
	case 0:
		ret = plan9asm.I64
	case 1:
		ret = plan9asm.I64
	default:
		parts := make([]string, 0, len(results))
		for range results {
			parts = append(parts, string(plan9asm.I64))
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
	if strings.HasPrefix(name, "ret") || strings.HasPrefix(name, "r") && strings.Contains(name, "ret") {
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

		parts, ok := framePartsForType(t, goarch)
		if ok {
			if flattenAgg {
				for _, part := range parts {
					args = append(args, part.Type)
					slots = append(slots, plan9asm.FrameSlot{Offset: off + part.Offset, Type: part.Type, Index: argIdx, Field: -1})
					argIdx++
				}
			} else {
				ty, e := llvmTypeForGo(t, goarch)
				if e != nil {
					return nil, nil, 0, e
				}
				args = append(args, ty)
				for _, part := range parts {
					slots = append(slots, plan9asm.FrameSlot{Offset: off + part.Offset, Type: part.Type, Index: argIdx, Field: part.Field})
				}
				argIdx++
			}
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

type framePart struct {
	Offset int64
	Type   plan9asm.LLVMType
	Field  int
}

func framePartsForType(t types.Type, goarch string) ([]framePart, bool) {
	word := int64(wordSize(goarch))
	wordTy := plan9asm.I64
	if word == 4 {
		wordTy = plan9asm.LLVMType("i32")
	}
	switch u := types.Unalias(t).(type) {
	case *types.Basic:
		if u.Kind() == types.String {
			return []framePart{
				{Offset: 0, Type: plan9asm.Ptr, Field: 0},
				{Offset: word, Type: wordTy, Field: 1},
			}, true
		}
	case *types.Slice:
		return []framePart{
			{Offset: 0, Type: plan9asm.Ptr, Field: 0},
			{Offset: word, Type: wordTy, Field: 1},
			{Offset: 2 * word, Type: wordTy, Field: 2},
		}, true
	case *types.Interface:
		// Both empty and non-empty interfaces occupy two pointers in Go ABI.
		return []framePart{
			{Offset: 0, Type: plan9asm.Ptr, Field: 0},
			{Offset: word, Type: plan9asm.Ptr, Field: 1},
		}, true
	}
	return nil, false
}

func llvmTypeForGo(t types.Type, goarch string) (plan9asm.LLVMType, error) {
	switch tt := t.(type) {
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
	case *types.Slice:
		if wordSize(goarch) == 8 {
			return plan9asm.LLVMType("{ ptr, i64, i64 }"), nil
		}
		return plan9asm.LLVMType("{ ptr, i32, i32 }"), nil
	case *types.Interface:
		return plan9asm.LLVMType("{ ptr, ptr }"), nil
	case *types.Named:
		return llvmTypeForGo(tt.Underlying(), goarch)
	default:
		return "", fmt.Errorf("unsupported type %s", t.String())
	}
}

func wordSize(goarch string) int {
	switch goarch {
	case "amd64", "arm64", "loong64", "mips64", "mips64le", "ppc64", "ppc64le", "riscv64", "s390x":
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
