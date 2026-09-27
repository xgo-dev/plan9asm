package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/asmsig"
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

const targetNotApplicableGoTextArgSize = "go_text_arg_size_mismatch"

type notApplicableItem struct {
	PkgPath         string `json:"pkg_path"`
	AsmFile         string `json:"asm_file"`
	Kind            string `json:"kind"`
	Symbol          string `json:"symbol"`
	DeclaredArgSize int64  `json:"declared_arg_size"`
	ExpectedArgSize int64  `json:"expected_arg_size"`
	Reason          string `json:"reason"`
}

type asmABINotApplicableError struct {
	Symbol          string
	Goarch          string
	DeclaredArgSize int64
	ExpectedArgSize int64
}

func (e *asmABINotApplicableError) Error() string {
	return fmt.Sprintf("%s: TEXT argument size is incompatible with the Go declaration on %s: got %d, want %d", e.Symbol, e.Goarch, e.DeclaredArgSize, e.ExpectedArgSize)
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
	Goos               string              `json:"goos"`
	Goarch             string              `json:"goarch"`
	Patterns           []string            `json:"patterns"`
	TotalPkgs          int                 `json:"total_pkgs"`
	AsmPackages        []string            `json:"asm_packages,omitempty"`
	AsmFiles           []string            `json:"asm_files,omitempty"`
	TotalAsm           int                 `json:"total_asm"`
	Success            int                 `json:"success"`
	NotApplicable      int                 `json:"not_applicable"`
	Failed             int                 `json:"failed"`
	Duration           string              `json:"duration"`
	UnsupportedOps     []opCount           `json:"unsupported_ops,omitempty"`
	Fails              []failItem          `json:"fails,omitempty"`
	NotApplicableItems []notApplicableItem `json:"not_applicable_items,omitempty"`
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
	Targets       []runReport `json:"targets"`
	TotalTargets  int         `json:"total_targets"`
	TotalAsm      int         `json:"total_asm"`
	Success       int         `json:"success"`
	NotApplicable int         `json:"not_applicable"`
	Failed        int         `json:"failed"`
}

type compileConfig struct {
	Enabled  bool
	LLC      string
	KeepObj  bool
	OptLevel int
	// MaxFunctions bounds LLVM module size when object compilation is used
	// only as a validation gate. Zero selects the production default.
	MaxFunctions int
	// MaxInstructions also bounds generated-source-heavy modules whose few
	// functions each contain thousands of assembly instructions. A single
	// oversized function stays intact and is checked on its own.
	MaxInstructions int
	X86TailGroups   []plan9asm.X86TailGroup
}

func main() {
	var (
		goos        = flag.String("goos", runtime.GOOS, "target GOOS")
		goarch      = flag.String("goarch", runtime.GOARCH, "target GOARCH (386/amd64/arm/arm64/wasm)")
		targets     = flag.String("targets", "", "comma-separated GOOS/GOARCH list (e.g. linux/amd64,windows/arm64)")
		allTargets  = flag.Bool("all-targets", false, "run the complete default Plan 9 target matrix")
		patterns    = flag.String("patterns", "std", "comma-separated package patterns")
		asmFiles    = flag.String("asm-files", "", "comma-separated module-relative assembly files to exercise exactly")
		buildTags   = flag.String("tags", "", "comma-separated Go build tags used to expose tagged assembly implementations")
		modulePath  = flag.String("module-path", "", "only include packages owned by this module path")
		outDir      = flag.String("out", "", "output dir for generated .ll files")
		annotate    = flag.Bool("annotate", false, "emit source asm lines as IR comments")
		limit       = flag.Int("limit", 0, "max number of asm files per target (0 means all)")
		keepGoing   = flag.Bool("keep-going", true, "continue on per-file failures")
		listOnly    = flag.Bool("list-only", false, "only print asm task list and exit")
		compile     = flag.Bool("compile", false, "compile generated .ll to .o via llc")
		llcPath     = flag.String("llc", "", "path to llc executable (auto-detect when empty)")
		llcOptLevel = flag.Int("llc-opt-level", 2, "LLVM llc optimization level (0-3)")
		keepObj     = flag.Bool("keep-obj", false, "keep generated .o files when -compile is set")
		strictLoad  = flag.Bool("strict-load", false, "fail when go/packages reports any package loading error")
		reportOut   = flag.String("report", "", "optional report json path")
		repoRoot    = flag.String("repo-root", "../..", "repo root for extracting supported instruction set")
	)
	flag.Parse()

	pats := splitCSV(*patterns)
	if len(pats) == 0 {
		fatalf("empty -patterns")
	}
	tags := splitCSV(*buildTags)
	exactAsmFiles := splitCSV(*asmFiles)
	if err := validateExactAsmFiles(exactAsmFiles); err != nil {
		fatalf("%v", err)
	}

	specs, err := resolveTargets(*goos, *goarch, *targets, *allTargets)
	if err != nil {
		fatalf("%v", err)
	}
	ccfg, err := resolveCompileConfig(*compile, *llcPath, *keepObj, *llcOptLevel)
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
		rep, tasks, err := runOneTarget(spec, pats, tags, exactAsmFiles, *modulePath, runOutDir, *annotate, *limit, *keepGoing, *listOnly, *strictLoad, *repoRoot, ccfg)
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
		if !useMatrixReport(*allTargets, *targets, len(taskLists)) {
			out = taskLists[0].Tasks
		} else {
			out = taskLists
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		check(enc.Encode(out))
		return
	}

	if !useMatrixReport(*allTargets, *targets, len(allReports)) {
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
		mr.NotApplicable += r.NotApplicable
		mr.Failed += r.Failed
	}
	writeReport(*reportOut, mr)
	if exitCode != 0 {
		fmt.Fprintf(os.Stderr, "\nmatrix finished with failures: success=%d not_applicable=%d failed=%d total=%d\n", mr.Success, mr.NotApplicable, mr.Failed, mr.TotalAsm)
		os.Exit(exitCode)
	}
	fmt.Fprintf(os.Stderr, "\nmatrix finished: success=%d not_applicable=%d total=%d\n", mr.Success, mr.NotApplicable, mr.TotalAsm)
}

func useMatrixReport(allTargets bool, targets string, reportCount int) bool {
	return allTargets || strings.TrimSpace(targets) != "" || reportCount != 1
}

func resolveCompileConfig(compile bool, llcPath string, keepObj bool, optLevel int) (compileConfig, error) {
	if optLevel < 0 || optLevel > 3 {
		return compileConfig{}, fmt.Errorf("-llc-opt-level must be between 0 and 3, got %d", optLevel)
	}
	cfg := compileConfig{
		Enabled:  compile,
		LLC:      strings.TrimSpace(llcPath),
		KeepObj:  keepObj,
		OptLevel: optLevel,
	}
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

func runOneTarget(spec targetSpec, pats, buildTags, exactAsmFiles []string, modulePath, outDir string, annotate bool, limit int, keepGoing bool, listOnly, strictLoad bool, repoRoot string, ccfg compileConfig) (runReport, []asmTask, error) {
	arch, err := toPlan9Arch(spec.Goarch)
	if err != nil {
		return runReport{}, nil, err
	}
	pkgs, err := loadPkgs(spec.Goos, spec.Goarch, pats, buildTags, modulePath, strictLoad, containsTestAssembly(exactAsmFiles))
	if err != nil {
		return runReport{}, nil, fmt.Errorf("load packages: %w", err)
	}
	pkgByPath := map[string]*packages.Package{}
	for _, p := range pkgs {
		if p != nil && p.PkgPath != "" {
			previous := pkgByPath[p.PkgPath]
			if previous == nil || isTestVariantPackage(p) && !isTestVariantPackage(previous) {
				pkgByPath[p.PkgPath] = p
			}
		}
	}
	tasks, asmPackages := collectAsmTasks(pkgs, outDir, exactAsmFiles)
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
	for _, task := range tasks {
		rep.AsmFiles = append(rep.AsmFiles, task.AsmFile)
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
		err := compileOne(pkg, arch, spec.Goos, spec.Goarch, triple, t, annotate, ccfg)
		if err != nil {
			var abiMismatch *asmABINotApplicableError
			if errors.As(err, &abiMismatch) {
				fmt.Fprintf(os.Stderr, "[%d/%d] N/A  %s\n", idx, len(tasks), t.AsmFile)
				printFailureReason(abiMismatch.Error())
				rep.NotApplicable++
				rep.NotApplicableItems = append(rep.NotApplicableItems, notApplicableItem{
					PkgPath:         t.PkgPath,
					AsmFile:         t.AsmFile,
					Kind:            targetNotApplicableGoTextArgSize,
					Symbol:          abiMismatch.Symbol,
					DeclaredArgSize: abiMismatch.DeclaredArgSize,
					ExpectedArgSize: abiMismatch.ExpectedArgSize,
					Reason:          abiMismatch.Error(),
				})
				continue
			}
			fmt.Fprintf(os.Stderr, "[%d/%d] FAIL %s\n", idx, len(tasks), t.AsmFile)
			printFailureReason(err.Error())
			unsupported, hits := unsupportedInAsmFile(t.AsmFile, asmSourceRoot(pkg, t.AsmFile), arch, supportedOps)
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
		fmt.Fprintf(os.Stderr, "finished with failures: success=%d not_applicable=%d failed=%d total=%d\n", rep.Success, rep.NotApplicable, rep.Failed, rep.TotalAsm)
	} else {
		fmt.Fprintf(os.Stderr, "finished: success=%d not_applicable=%d total=%d\n", rep.Success, rep.NotApplicable, rep.TotalAsm)
	}
	return rep, nil, nil
}

func compileOne(pkg *packages.Package, arch plan9asm.Arch, goos, goarch, triple string, t asmTask, annotate bool, ccfg compileConfig) error {
	src, err := readAsmSource(t.AsmFile, asmSourceRoot(pkg, t.AsmFile))
	if err != nil {
		return fmt.Errorf("read asm: %w", err)
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
	file, err := plan9asm.ParseWithDefines(arch, string(src), plan9asm.GoAssemblerDefines(goos, goarch))
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
	sigs, declaredArgSizes, err := sigsForAsmFile(pkg, file, resolve, goarch)
	if err != nil {
		return fmt.Errorf("infer signatures: %w", err)
	}
	if err := validateDeclaredTextArgSizes(file, resolve, declaredArgSizes, goarch); err != nil {
		return fmt.Errorf("target applicability: %w", err)
	}
	ccfg.X86TailGroups, err = inferX86TailGroups(pkg, file, t.AsmFile, goarch, resolve, sigs)
	if err != nil {
		return fmt.Errorf("prove private continuation entries: %w", err)
	}
	maxFunctions := ccfg.MaxFunctions
	if maxFunctions <= 0 {
		maxFunctions = 128
	}
	maxInstructions := ccfg.MaxInstructions
	if maxInstructions <= 0 {
		maxInstructions = 32768
	}
	instructionCount := 0
	for _, fn := range file.Funcs {
		instructionCount += len(fn.Instrs)
	}
	// A continuation and the initializer taking its block address must remain
	// in one LLVM module, just as an oversized ordinary function stays intact.
	if ccfg.Enabled && !ccfg.KeepObj && len(ccfg.X86TailGroups) == 0 &&
		(len(file.Funcs) > maxFunctions || instructionCount > maxInstructions) {
		// A complete pass is necessary before splitting: an x86 function may
		// take the byte-exact address of raw TEXT in a different chunk.
		file, err = plan9asm.NormalizeRawFileForTranslation(file, goarch)
		if err != nil {
			return fmt.Errorf("normalize raw file: %w", err)
		}
		for first, chunk := 0, 0; first < len(file.Funcs); chunk++ {
			last := first
			chunkInstructions := 0
			for last < len(file.Funcs) && last-first < maxFunctions {
				next := len(file.Funcs[last].Instrs)
				if last > first && chunkInstructions+next > maxInstructions {
					break
				}
				chunkInstructions += next
				last++
			}
			part := *file
			part.Funcs = file.Funcs[first:last]
			partTask := t
			if chunk != 0 {
				stem := strings.TrimSuffix(t.OutLL, filepath.Ext(t.OutLL))
				partTask.OutLL = fmt.Sprintf("%s.part-%04d.ll", stem, chunk)
			}
			if err := translateAndCompileModule(&part, triple, goarch, partTask, annotate, ccfg, resolve, sigs); err != nil {
				return fmt.Errorf("functions %d-%d/%d: %w", first+1, last, len(file.Funcs), err)
			}
			first = last
		}
		return nil
	}
	return translateAndCompileModule(file, triple, goarch, t, annotate, ccfg, resolve, sigs)
}

func translateAndCompileModule(file *plan9asm.File, triple, goarch string, t asmTask, annotate bool,
	ccfg compileConfig, resolve func(string) string, sigs map[string]plan9asm.FuncSig,
) error {
	ctx := llvm.NewContext()
	mod, err := plan9asm.TranslateModuleInContext(ctx, file, plan9asm.Options{
		TargetTriple:   triple,
		ResolveSym:     resolve,
		Sigs:           sigs,
		Goarch:         goarch,
		WASMABI:        wasmABIForGoPackageTarget(goarch),
		AnnotateSource: annotate,
		X86TailGroups:  ccfg.X86TailGroups,
	})
	if err != nil {
		ctx.Dispose()
		return fmt.Errorf("translate: %w", err)
	}
	if err := llvm.VerifyModule(mod, llvm.ReturnStatusAction); err != nil {
		mod.Dispose()
		ctx.Dispose()
		return fmt.Errorf("verify module: %w", err)
	}
	ll := mod.String()
	// The external llc process may run for a while. Release both the module
	// and its context before writing files or waiting for it.
	mod.Dispose()
	ctx.Dispose()
	if err := os.MkdirAll(filepath.Dir(t.OutLL), 0755); err != nil {
		return fmt.Errorf("mkdir out dir: %w", err)
	}
	if err := os.WriteFile(t.OutLL, []byte(ll), 0644); err != nil {
		return fmt.Errorf("write ll: %w", err)
	}
	if ccfg.Enabled {
		objPath := strings.TrimSuffix(t.OutLL, filepath.Ext(t.OutLL)) + ".o"
		if err := os.Remove(objPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale object: %w", err)
		}
		args := llcCompileArgs(triple, goarch, t.OutLL, objPath, ccfg.OptLevel)
		cmd := exec.Command(ccfg.LLC, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			s := strings.TrimSpace(string(out))
			if s == "" {
				return fmt.Errorf("llc compile failed: %w", err)
			}
			return fmt.Errorf("llc compile failed: %w\n%s", err, s)
		}
		stat, err := os.Lstat(objPath)
		if err != nil || !stat.Mode().IsRegular() || stat.Size() == 0 {
			return fmt.Errorf("llc did not produce a nonempty object %s: %v", objPath, err)
		}
		if !ccfg.KeepObj {
			if err := os.Remove(objPath); err != nil {
				return fmt.Errorf("remove generated object: %w", err)
			}
		}
	}
	return nil
}

func llcCompileArgs(triple, goarch, input, output string, optLevel int) []string {
	args := []string{"-mtriple=" + triple, fmt.Sprintf("-O%d", optLevel)}
	args = append(args, llcExtraArgs(goarch)...)
	return append(args, "-filetype=obj", input, "-o", output)
}

// plan9asmll translates Go package assembly, rather than arbitrary native LLVM
// entry points. Go's wasm assembler therefore always uses the resumable
// linear-memory stack ABI; other architectures retain the direct convention.
func wasmABIForGoPackageTarget(goarch string) plan9asm.WASMABI {
	if goarch == "wasm" {
		return plan9asm.WASMABIGo
	}
	return plan9asm.WASMABIDirect
}

func asmSourceRoot(pkg *packages.Package, asmFile string) string {
	if pkg != nil && pkg.Module != nil && pkg.Module.Dir != "" {
		return pkg.Module.Dir
	}
	return filepath.Dir(asmFile)
}

// readAsmSource expands quoted headers that live inside the package's module.
// Go assembly commonly keeps large function-like macros in sibling .h files.
// Toolchain headers such as textflag.h and funcdata.h are resolved from the
// current GOROOT's pkg/include directory, matching the include path supplied
// by the Go command. Generated package headers such as go_asm.h remain as
// directives when they do not exist yet.
func readAsmSource(asmFile, sourceRoot string) ([]byte, error) {
	return plan9asm.ReadGoAssemblySource(asmFile, sourceRoot)
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

func loadPkgs(goos, goarch string, patterns, buildTags []string, modulePath string, strict, includeTests bool) ([]*packages.Package, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedModule |
			packages.NeedDeps |
			packages.NeedImports |
			packages.NeedTypes |
			packages.NeedTypesSizes,
		Env: append(os.Environ(),
			"GOOS="+goos,
			"GOARCH="+goarch,
		),
		Tests: includeTests,
	}
	if len(buildTags) != 0 {
		cfg.BuildFlags = []string{"-tags=" + strings.Join(buildTags, ",")}
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, err
	}
	pkgs = filterPackagesByModule(pkgs, modulePath)
	if count := packages.PrintErrors(pkgs); strict && count != 0 {
		return nil, fmt.Errorf("%d package loading error(s)", count)
	}
	for _, pkg := range pkgs {
		if err := loadLinknameSyntax(pkg); err != nil {
			return nil, err
		}
	}
	return pkgs, nil
}

// Only target packages need source comments for go:linkname resolution. Loading
// syntax and type-info for every transitive dependency retains large AST and
// types.Info graphs, especially for third-party modules such as Arrow.
func loadLinknameSyntax(pkg *packages.Package) error {
	for _, name := range pkg.GoFiles {
		src, err := os.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read Go source %s: %w", name, err)
		}
		if !bytes.Contains(src, []byte("go:linkname ")) {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parse Go source %s: %w", name, err)
		}
		pkg.Syntax = append(pkg.Syntax, file)
	}
	return nil
}

func containsTestAssembly(files []string) bool {
	for _, name := range files {
		base := filepath.Base(filepath.FromSlash(name))
		if strings.Contains(strings.TrimSuffix(base, filepath.Ext(base)), "_test_") || strings.HasSuffix(strings.TrimSuffix(base, filepath.Ext(base)), "_test") {
			return true
		}
	}
	return false
}

func isTestVariantPackage(pkg *packages.Package) bool {
	return pkg != nil && strings.Contains(pkg.ID, " [") && strings.HasSuffix(pkg.ID, ".test]")
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

func collectAsmTasks(pkgs []*packages.Package, outDir string, exactAsmFiles []string) ([]asmTask, []string) {
	tasks := make([]asmTask, 0)
	asmPackages := make([]string, 0)
	seenPkg := map[string]bool{}
	allow := make(map[string]bool, len(exactAsmFiles))
	for _, path := range exactAsmFiles {
		allow[filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))] = true
	}
	for _, p := range pkgs {
		if p == nil || p.PkgPath == "" {
			continue
		}
		if seenPkg[p.PkgPath] {
			continue
		}
		seenPkg[p.PkgPath] = true
		files := asmFilesOfPkg(p)
		if len(allow) != 0 {
			filtered := files[:0]
			for _, file := range files {
				if rel, ok := moduleRelativeAsmPath(p, file); ok && allow[rel] {
					filtered = append(filtered, file)
				}
			}
			files = filtered
		}
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

func validateExactAsmFiles(files []string) error {
	for _, path := range files {
		clean := filepath.Clean(filepath.FromSlash(path))
		if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("invalid -asm-files entry %q: expect a module-relative path", path)
		}
	}
	return nil
}

func moduleRelativeAsmPath(pkg *packages.Package, path string) (string, bool) {
	if pkg == nil || pkg.Module == nil || pkg.Module.Dir == "" {
		return "", false
	}
	rel, err := filepath.Rel(pkg.Module.Dir, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(filepath.Clean(rel)), true
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

func stripABISuffix(sym string) string {
	return abiSuffixRe.ReplaceAllString(sym, "")
}

func sigsForAsmFile(pkg *packages.Package, file *plan9asm.File, resolve func(string) string, goarch string) (map[string]plan9asm.FuncSig, map[string]int64, error) {
	sigs := map[string]plan9asm.FuncSig{}
	declaredArgSizes := map[string]int64{}
	declaredSigs := map[string]bool{}
	knownABISigs := map[string]bool{}
	fallbackAsmSigs := map[string]bool{}
	if pkg == nil || pkg.Types == nil || pkg.Types.Scope() == nil {
		for _, fn := range file.Funcs {
			fs := fallbackSigForAsmFunc(fn, resolve(stripABISuffix(fn.Sym)), goarch)
			sigs[fs.Name] = fs
		}
		asmsig.RefineTailForwarders(file, sigs, resolve, nil)
		return sigs, declaredArgSizes, nil
	}

	sz := pkg.TypesSizes
	if sz == nil {
		sz = types.SizesFor("gc", goarch)
	}
	if sz == nil {
		return nil, nil, fmt.Errorf("missing type sizes for %q", goarch)
	}

	scope := pkg.Types.Scope()
	linknames := linknameRemoteToLocal(pkg.Syntax)

	for _, fn := range file.Funcs {
		sym := stripABISuffix(fn.Sym)
		resolved := resolve(sym)
		if resolved == "" {
			continue
		}
		fs, argSize, ok, err := tryDeclSig(scope, sym, resolved, linknames, goarch, sz)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			fs = fallbackSigForAsmFunc(fn, resolved, goarch)
			fallbackAsmSigs[resolved] = true
		} else {
			if goarch == "arm64" {
				inferred := fallbackSigForAsmFunc(fn, resolved, goarch)
				if borrowed, ok := asmsig.ARM64BorrowedTailFrame(file, fn, fs, inferred, resolve); ok {
					fs = borrowed
				}
			}
			declaredArgSizes[resolved] = argSize
			declaredSigs[resolved] = true
			knownABISigs[resolved] = true
		}
		sigs[resolved] = fs
	}

	// File-local WebAssembly helpers use the native wasm operand stack and
	// virtual registers rather than Go's stack-frame ABI. They have no Go
	// declaration, so derive their complete argument and result types from the
	// instructions before resolving calls. Keeping this generic covers the
	// standard library's bytealg helpers as they evolve without a name table.
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
					return nil, nil, err
				}
			}
			fs.WASMNative = true
			sigs[resolved] = fs
			knownABISigs[resolved] = true
			delete(fallbackAsmSigs, resolved)
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
		if _, ok := sigs[resolved]; ok {
			return
		}
		if goarch == "wasm" {
			if fs, ok := plan9asm.LookupGoWASMNativeFuncSig(resolved); ok {
				sigs[resolved] = fs
				knownABISigs[resolved] = true
				return
			}
		}
		fs, _, ok, err := tryDeclSig(scope, sym, resolved, linknames, goarch, sz)
		if err == nil && ok {
			sigs[resolved] = fs
			declaredSigs[resolved] = true
			knownABISigs[resolved] = true
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

	declaredTailCallers := make(map[string][]plan9asm.FuncSig)
	declaredTailCallerFuncs := make(map[string][]plan9asm.Func)
	for _, fn := range file.Funcs {
		callerResolved := resolve(stripABISuffix(fn.Sym))
		caller := sigs[callerResolved]
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
			targetResolved := resolve(stripABISuffix(base))
			if tail && declaredSigs[callerResolved] && fallbackAsmSigs[targetResolved] {
				candidate := caller
				candidate.Name = targetResolved
				declaredTailCallers[targetResolved] = append(declaredTailCallers[targetResolved], candidate)
				declaredTailCallerFuncs[targetResolved] = append(declaredTailCallerFuncs[targetResolved], fn)
			}
		}
	}

	// A declaration-free local helper reached only through tail transfers from
	// Go-declared functions executes in the caller's frame. Copy the complete
	// ABI when every caller agrees; this is how 32-bit ARM implements its 64-bit
	// atomic helpers. Shared register-based bodies such as x86 memeqbody can
	// have callers with different argument lists, so in that case propagate
	// only a common return type and retain the helper's own inferred inputs.
	for targetResolved, callers := range declaredTailCallers {
		if len(callers) == 0 {
			continue
		}
		inferred := callers[0]
		fullABIAGrees := true
		returnTypeAgrees := true
		for _, caller := range callers[1:] {
			if !reflect.DeepEqual(inferred, caller) {
				fullABIAGrees = false
			}
			if inferred.Ret != caller.Ret {
				returnTypeAgrees = false
			}
		}
		if fullABIAGrees {
			sigs[targetResolved] = inferred
			knownABISigs[targetResolved] = true
			continue
		}
		if helper, ok := inferSharedABI0ResultPointerHelper(
			file,
			resolve,
			targetResolved,
			callers,
			declaredTailCallerFuncs[targetResolved],
			goarch,
		); ok {
			sigs[targetResolved] = helper
			knownABISigs[targetResolved] = true
			continue
		}
		if returnTypeAgrees {
			target := sigs[targetResolved]
			// Explicit FP result slots are part of the helper's frame ABI and
			// cannot be replaced by return-type evidence alone. With no such
			// slots, the declared callers are the only reliable return oracle.
			if len(target.Frame.Results) == 0 {
				target.Ret = inferred.Ret
				sigs[targetResolved] = target
			}
		}
	}

	// A declaration-free TEXT can be a C-ABI entry trampoline that consists of
	// a direct tail transfer to a Go-declared function. FP-slot heuristics have
	// no return information for such a function, while the tail target provides
	// its complete ABI. Inherit that signature only when every external tail
	// target is declared and agrees, leaving ordinary register-return assembly
	// on the conservative fallback above.
	for _, fn := range file.Funcs {
		callerResolved := resolve(stripABISuffix(fn.Sym))
		if !fallbackAsmSigs[callerResolved] {
			continue
		}
		var inferred *plan9asm.FuncSig
		valid := true
		for _, ins := range fn.Instrs {
			op := strings.ToUpper(string(ins.Op))
			if !(op == "JMP" || op == "B" || (op == "RET" && len(ins.Args) == 1)) || len(ins.Args) != 1 || ins.Args[0].Kind != plan9asm.OpSym {
				continue
			}
			s := strings.TrimSpace(ins.Args[0].Sym)
			if !strings.HasSuffix(s, "(SB)") {
				continue
			}
			base, off := splitSymPlusOff(strings.TrimSuffix(s, "(SB)"))
			targetResolved := resolve(stripABISuffix(base))
			target, ok := sigs[targetResolved]
			if base == "" || off != 0 || !ok || !knownABISigs[targetResolved] {
				valid = false
				break
			}
			target.Name = callerResolved
			if inferred == nil {
				candidate := target
				inferred = &candidate
			} else if !reflect.DeepEqual(*inferred, target) {
				valid = false
				break
			}
		}
		if valid && inferred != nil {
			sigs[callerResolved] = *inferred
		}
	}

	asmsig.RefineTailForwarders(file, sigs, resolve, knownABISigs)

	return sigs, declaredArgSizes, nil
}

func validateDeclaredTextArgSizes(file *plan9asm.File, resolve func(string) string, declaredArgSizes map[string]int64, goarch string) error {
	for _, fn := range file.Funcs {
		if !hasExplicitTextArgSize(fn) {
			continue
		}
		// Go's own assembly uses the historical $frame-0 spelling for
		// declaration-backed functions whose arguments are supplied by ABI
		// wrappers or intentionally unused (for example runtime.procyieldAsm
		// and exitThread on wasm). The assembler treats that zero as a legacy
		// wildcard, so only a non-zero conflicting size proves incompatibility.
		if fn.ArgSize == 0 {
			continue
		}
		resolved := resolve(stripABISuffix(fn.Sym))
		expected, ok := declaredArgSizes[resolved]
		if !ok || fn.ArgSize == expected {
			continue
		}
		return &asmABINotApplicableError{
			Symbol:          resolved,
			Goarch:          goarch,
			DeclaredArgSize: fn.ArgSize,
			ExpectedArgSize: expected,
		}
	}
	return nil
}

func hasExplicitTextArgSize(fn plan9asm.Func) bool {
	for _, ins := range fn.Instrs {
		if ins.Op != plan9asm.OpTEXT {
			continue
		}
		parts := strings.Split(ins.Raw, ",")
		if len(parts) < 2 {
			return false
		}
		spec := strings.TrimSpace(parts[len(parts)-1])
		if !strings.HasPrefix(spec, "$") {
			return false
		}
		return strings.LastIndex(strings.TrimPrefix(spec, "$"), "-") > 0
	}
	return false
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

func tryDeclSig(scope *types.Scope, sym, resolved string, linknames map[string]string, goarch string, sz types.Sizes) (plan9asm.FuncSig, int64, bool, error) {
	declName := strings.TrimPrefix(sym, "·")
	if strings.ContainsRune(declName, '·') {
		key := strings.ReplaceAll(sym, "∕", "/")
		key = strings.ReplaceAll(key, "·", ".")
		if local, ok := linknames[key]; ok {
			declName = local
		} else {
			dot := strings.LastIndexByte(key, '.')
			if dot < 0 || dot == len(key)-1 {
				return plan9asm.FuncSig{}, 0, false, nil
			}
			candidate := key[dot+1:]
			obj := scope.Lookup(candidate)
			if obj == nil || (key != resolved && (obj.Pkg() == nil || resolved != obj.Pkg().Path()+"."+candidate)) {
				return plan9asm.FuncSig{}, 0, false, nil
			}
			declName = candidate
		}
	}
	obj := scope.Lookup(declName)
	if obj == nil {
		return plan9asm.FuncSig{}, 0, false, nil
	}
	fn, ok := obj.(*types.Func)
	if !ok {
		return plan9asm.FuncSig{}, 0, false, nil
	}
	sig := fn.Type().(*types.Signature)
	if sig.Recv() != nil || sig.Variadic() {
		return plan9asm.FuncSig{}, 0, false, nil
	}

	args, frameParams, nextOff, err := llvmArgsAndFrameSlotsForTuple(sig.Params(), goarch, sz, 0, false)
	if err != nil {
		return plan9asm.FuncSig{}, 0, false, fmt.Errorf("%s: %w", fn.FullName(), err)
	}
	// Go's TEXT argument size ends at the last declared parameter when a
	// function has no results. The word-aligned gap separates parameters from
	// results, so it exists only when there is a result section.
	if sig.Results() != nil && sig.Results().Len() != 0 {
		nextOff = alignOff(nextOff, int64(wordSize(goarch)))
	}
	retTys, frameResults, argSize, err := llvmArgsAndFrameSlotsForTuple(sig.Results(), goarch, sz, nextOff, true)
	if err != nil {
		return plan9asm.FuncSig{}, 0, false, fmt.Errorf("%s: %w", fn.FullName(), err)
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
	}, argSize, true, nil
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
		name := ""
		if flattenAgg {
			name = tup.At(i).Name()
		}
		t := tup.At(i).Type()
		off = align(off, int64(sz.Alignof(t)))
		if sz.Sizeof(t) == 0 {
			continue
		}

		parts, ok, e := framePartsForType(t, goarch, sz)
		if e != nil {
			return nil, nil, 0, e
		}
		if ok {
			if flattenAgg {
				for _, part := range parts {
					args = append(args, part.Type)
					slots = append(slots, plan9asm.FrameSlot{Offset: off + part.Offset, Type: part.Type, Index: argIdx, Field: -1, Name: name})
					argIdx++
				}
			} else {
				ty, e := llvmTypeForGo(t, goarch)
				if e != nil {
					return nil, nil, 0, e
				}
				args = append(args, ty)
				for _, part := range parts {
					slots = append(slots, plan9asm.FrameSlot{Offset: off + part.Offset, Type: part.Type, Index: argIdx, Field: part.Field, Fields: part.Fields})
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
		slots = append(slots, plan9asm.FrameSlot{Offset: off, Type: ty, Index: argIdx, Field: -1, Name: name})
		argIdx++
		off += int64(sz.Sizeof(t))
	}
	return args, slots, off, nil
}

type framePart struct {
	Offset int64
	Type   plan9asm.LLVMType
	Field  int
	Fields []int
}

func framePartsForType(t types.Type, goarch string, sz types.Sizes) ([]framePart, bool, error) {
	word := int64(wordSize(goarch))
	wordTy := plan9asm.I64
	if word == 4 {
		wordTy = plan9asm.LLVMType("i32")
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Basic:
		switch u.Kind() {
		case types.String:
			return []framePart{
				{Offset: 0, Type: plan9asm.Ptr, Field: 0},
				{Offset: word, Type: wordTy, Field: 1},
			}, true, nil
		case types.Complex64:
			return []framePart{
				{Offset: 0, Type: plan9asm.LLVMType("float"), Field: 0},
				{Offset: 4, Type: plan9asm.LLVMType("float"), Field: 1},
			}, true, nil
		case types.Complex128:
			return []framePart{
				{Offset: 0, Type: plan9asm.LLVMType("double"), Field: 0},
				{Offset: 8, Type: plan9asm.LLVMType("double"), Field: 1},
			}, true, nil
		}
	case *types.Slice:
		return []framePart{
			{Offset: 0, Type: plan9asm.Ptr, Field: 0},
			{Offset: word, Type: wordTy, Field: 1},
			{Offset: 2 * word, Type: wordTy, Field: 2},
		}, true, nil
	case *types.Interface:
		// Both empty and non-empty interfaces occupy two pointers in Go ABI.
		return []framePart{
			{Offset: 0, Type: plan9asm.Ptr, Field: 0},
			{Offset: word, Type: plan9asm.Ptr, Field: 1},
		}, true, nil
	case *types.Array:
		elemParts, elemAggregate, err := framePartsForType(u.Elem(), goarch, sz)
		if err != nil {
			return nil, false, err
		}
		if !elemAggregate {
			elemType, err := llvmTypeForGo(u.Elem(), goarch)
			if err != nil {
				return nil, false, err
			}
			elemParts = []framePart{{Type: elemType, Field: -1}}
		}
		elemSize := int64(sz.Sizeof(u.Elem()))
		parts := make([]framePart, 0, int(u.Len())*len(elemParts))
		for i := int64(0); i < u.Len(); i++ {
			for _, part := range elemParts {
				parts = append(parts, nestedFramePart(part, int(i), i*elemSize))
			}
		}
		return parts, true, nil
	case *types.Struct:
		fields := make([]*types.Var, u.NumFields())
		for i := range fields {
			fields[i] = u.Field(i)
		}
		offsets := sz.Offsetsof(fields)
		var parts []framePart
		for i, field := range fields {
			fieldParts, fieldAggregate, err := framePartsForType(field.Type(), goarch, sz)
			if err != nil {
				return nil, false, err
			}
			if !fieldAggregate {
				fieldType, err := llvmTypeForGo(field.Type(), goarch)
				if err != nil {
					return nil, false, err
				}
				fieldParts = []framePart{{Type: fieldType, Field: -1}}
			}
			for _, part := range fieldParts {
				parts = append(parts, nestedFramePart(part, i, offsets[i]))
			}
		}
		return parts, true, nil
	}
	return nil, false, nil
}

func nestedFramePart(part framePart, field int, offset int64) framePart {
	path := make([]int, 0, 1+len(part.Fields)+1)
	path = append(path, field)
	if len(part.Fields) != 0 {
		path = append(path, part.Fields...)
	} else if part.Field >= 0 {
		path = append(path, part.Field)
	}
	part.Offset += offset
	part.Field = field
	if len(path) > 1 {
		part.Fields = path
	} else {
		part.Fields = nil
	}
	return part
}

func llvmTypeForGo(t types.Type, goarch string) (plan9asm.LLVMType, error) {
	t = types.Unalias(t)
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
		case types.Complex64:
			return plan9asm.LLVMType("{ float, float }"), nil
		case types.Complex128:
			return plan9asm.LLVMType("{ double, double }"), nil
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
		return plan9asm.Ptr, nil
	case *types.Slice:
		if wordSize(goarch) == 8 {
			return plan9asm.LLVMType("{ ptr, i64, i64 }"), nil
		}
		return plan9asm.LLVMType("{ ptr, i32, i32 }"), nil
	case *types.Interface:
		return plan9asm.LLVMType("{ ptr, ptr }"), nil
	case *types.Array:
		elem, err := llvmTypeForGo(tt.Elem(), goarch)
		if err != nil {
			return "", err
		}
		return plan9asm.LLVMType(fmt.Sprintf("[%d x %s]", tt.Len(), elem)), nil
	case *types.Struct:
		if tt.NumFields() == 0 {
			return plan9asm.LLVMType("[0 x i8]"), nil
		}
		fields := make([]string, tt.NumFields())
		for i := range fields {
			fieldType, err := llvmTypeForGo(tt.Field(i).Type(), goarch)
			if err != nil {
				return "", err
			}
			fields[i] = string(fieldType)
		}
		return plan9asm.LLVMType("{ " + strings.Join(fields, ", ") + " }"), nil
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
	if goarch == "386" {
		backendArch = "amd64"
	}
	glob := filepath.Join(repoRoot, backendArch+"_*.go")
	files, err := filepath.Glob(glob)
	if err != nil {
		return nil, err
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
		parsed, err := parser.ParseFile(token.NewFileSet(), f, src, 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s for supported instructions: %w", f, err)
		}
		// Package-level opcode specification maps are dispatch tables even when
		// their variable name does not contain "op" (for example a complete
		// instruction-family Specs table). Restrict this broader inference to
		// package declarations so local maps for predicates, registers, and LLVM
		// spellings cannot accidentally advertise instructions.
		for _, decl := range parsed.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, declared := range gen.Specs {
				spec, ok := declared.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, value := range spec.Values {
					literal, ok := value.(*ast.CompositeLit)
					if !ok {
						continue
					}
					collectSupportedOpcodeMap(supported, literal)
				}
			}
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			// Family lowerers commonly reject everything except their opcode at
			// the top of the function (for example `if op != "VDUP"`).  Those
			// handlers are just as authoritative as switch cases and opcode maps;
			// include only comparisons whose other operand is literally named op
			// so unrelated string predicates cannot advertise false support.
			if comparison, ok := node.(*ast.BinaryExpr); ok &&
				(comparison.Op == token.EQL || comparison.Op == token.NEQ) {
				if candidate, ok := opcodeComparedWithOp(comparison.X, comparison.Y); ok {
					if nop := normalizeOp(candidate); nop != "" {
						supported[nop] = struct{}{}
					}
				}
			}
			if spec, ok := node.(*ast.ValueSpec); ok {
				for i, name := range spec.Names {
					// Several backends keep their complete opcode tables in a
					// map[string]spec rather than map[Op]spec. Limit string-key
					// extraction to declarations explicitly named as opcode maps;
					// otherwise condition-code and register-name tables would be
					// mistaken for supported instructions.
					if !strings.Contains(strings.ToLower(name.Name), "op") || len(spec.Values) == 0 {
						continue
					}
					valueIndex := i
					if len(spec.Values) == 1 {
						valueIndex = 0
					}
					if valueIndex >= len(spec.Values) {
						continue
					}
					literal, ok := spec.Values[valueIndex].(*ast.CompositeLit)
					if !ok {
						continue
					}
					mapType, isMap := literal.Type.(*ast.MapType)
					keyType, stringKeyed := mapTypeKeyIdent(mapType)
					if !isMap || !stringKeyed || keyType != "string" {
						continue
					}
					for _, elt := range literal.Elts {
						pair, ok := elt.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						key, ok := pair.Key.(*ast.BasicLit)
						if !ok || key.Kind != token.STRING {
							continue
						}
						candidate, _ := strconv.Unquote(key.Value)
						if nop := normalizeOp(candidate); nop != "" {
							supported[nop] = struct{}{}
						}
					}
				}
			}
			literal, ok := node.(*ast.CompositeLit)
			if ok {
				mapType, isMap := literal.Type.(*ast.MapType)
				keyType, isOpMap := mapTypeKeyIdent(mapType)
				if isMap && isOpMap && keyType == "Op" {
					for _, elt := range literal.Elts {
						pair, ok := elt.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						key, ok := pair.Key.(*ast.BasicLit)
						if !ok || key.Kind != token.STRING {
							continue
						}
						candidate, _ := strconv.Unquote(key.Value)
						if nop := normalizeOp(candidate); nop != "" {
							supported[nop] = struct{}{}
						}
					}
				}
			}
			clause, ok := node.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, expr := range clause.List {
				candidate := ""
				switch value := expr.(type) {
				case *ast.BasicLit:
					if value.Kind == token.STRING {
						candidate, _ = strconv.Unquote(value.Value)
					}
				case *ast.Ident:
					if strings.HasPrefix(value.Name, "Op") {
						candidate = strings.TrimPrefix(value.Name, "Op")
					}
				}
				if nop := normalizeOp(candidate); nop != "" {
					supported[nop] = struct{}{}
				}
			}
			return true
		})
	}
	return supported, nil
}

func opcodeComparedWithOp(left, right ast.Expr) (string, bool) {
	if ident, ok := left.(*ast.Ident); ok && ident.Name == "op" {
		if literal, ok := right.(*ast.BasicLit); ok && literal.Kind == token.STRING {
			candidate, err := strconv.Unquote(literal.Value)
			return candidate, err == nil
		}
	}
	if ident, ok := right.(*ast.Ident); ok && ident.Name == "op" {
		if literal, ok := left.(*ast.BasicLit); ok && literal.Kind == token.STRING {
			candidate, err := strconv.Unquote(literal.Value)
			return candidate, err == nil
		}
	}
	return "", false
}

func collectSupportedOpcodeMap(supported map[string]struct{}, literal *ast.CompositeLit) {
	mapType, isMap := literal.Type.(*ast.MapType)
	keyType, supportedKey := mapTypeKeyIdent(mapType)
	if !isMap || !supportedKey || keyType != "string" && keyType != "Op" {
		return
	}
	for _, elt := range literal.Elts {
		pair, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := pair.Key.(*ast.BasicLit)
		if !ok || key.Kind != token.STRING {
			continue
		}
		candidate, _ := strconv.Unquote(key.Value)
		if nop := normalizeOp(candidate); nop != "" {
			supported[nop] = struct{}{}
		}
	}
}

func mapTypeKeyIdent(mapType *ast.MapType) (string, bool) {
	if mapType == nil {
		return "", false
	}
	ident, ok := mapType.Key.(*ast.Ident)
	if !ok {
		return "", false
	}
	return ident.Name, true
}

func unsupportedInAsmFile(path, sourceRoot string, arch plan9asm.Arch, supported map[string]struct{}) ([]string, []unsupportedHit) {
	if len(supported) == 0 {
		return nil, nil
	}
	src, err := readAsmSource(path, sourceRoot)
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
