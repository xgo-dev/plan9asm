package main

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/asmsig"
	"github.com/xgo-dev/plan9asm/internal/goabi"
	"github.com/xgo-dev/plan9asm/internal/sdkfrontend"
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
	Op          string `json:"op"`
	Line        int    `json:"line,omitempty"`
	Source      string `json:"source"`
	Function    string `json:"function,omitempty"`
	Instruction int    `json:"instruction,omitempty"`
}

type runReport struct {
	Goos               string                 `json:"goos"`
	Goarch             string                 `json:"goarch"`
	Patterns           []string               `json:"patterns"`
	TotalPkgs          int                    `json:"total_pkgs"`
	AsmPackages        []string               `json:"asm_packages,omitempty"`
	AsmFiles           []string               `json:"asm_files,omitempty"`
	TotalAsm           int                    `json:"total_asm"`
	Success            int                    `json:"success"`
	NotApplicable      int                    `json:"not_applicable"`
	Failed             int                    `json:"failed"`
	Duration           string                 `json:"duration"`
	UnsupportedOps     []opCount              `json:"unsupported_ops,omitempty"`
	Fails              []failItem             `json:"fails,omitempty"`
	NotApplicableItems []notApplicableItem    `json:"not_applicable_items,omitempty"`
	FeatureSelection   *featureSelectionProof `json:"feature_selection,omitempty"`
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
	MaxInstructions      int
	X86TailGroups        []plan9asm.X86TailGroup
	Feature              *featureConsumer
	FeaturePath          string
	Context              context.Context
	emptyAssembly        *gotoolprofile.EmptyAssemblyProof
	nativeListingMode    *instrumentationMetadataConsumer
	SignatureQuery       *gotoolprofile.SignatureQueryProof
	x86CallerSelections  map[*packages.Package]*x86CallerPackageSelection
	numericalOptions     *plan9asm.Options
	ordinaryDeclarations *ordinaryDeclarationSource
	acquireSDKNumerical  bool
	diagnostics          *instructionDiagnostics
}

func main() {
	var (
		goos           = flag.String("goos", runtime.GOOS, "target GOOS")
		goarch         = flag.String("goarch", runtime.GOARCH, "target GOARCH (386/amd64/arm/arm64/wasm)")
		targets        = flag.String("targets", "", "comma-separated GOOS/GOARCH list (e.g. linux/amd64,windows/arm64)")
		allTargets     = flag.Bool("all-targets", false, "run the complete default Plan 9 target matrix")
		patterns       = flag.String("patterns", "std", "comma-separated package patterns")
		asmFiles       = flag.String("asm-files", "", "comma-separated module-relative assembly files to exercise exactly")
		buildTags      = flag.String("tags", "", "comma-separated Go build tags used to expose tagged assembly implementations")
		modulePath     = flag.String("module-path", "", "only include packages owned by this module path")
		outDir         = flag.String("out", "", "output dir for generated .ll files")
		annotate       = flag.Bool("annotate", false, "emit source asm lines as IR comments")
		limit          = flag.Int("limit", 0, "max number of asm files per target (0 means all)")
		keepGoing      = flag.Bool("keep-going", true, "continue on per-file failures")
		listOnly       = flag.Bool("list-only", false, "only print asm task list and exit")
		compile        = flag.Bool("compile", false, "compile generated .ll to .o via llc")
		llcPath        = flag.String("llc", "", "path to llc executable (auto-detect when empty)")
		llcOptLevel    = flag.Int("llc-opt-level", 2, "LLVM llc optimization level (0-3)")
		keepObj        = flag.Bool("keep-obj", false, "keep generated .o files when -compile is set")
		strictLoad     = flag.Bool("strict-load", false, "fail when go/packages reports any package loading error")
		reportOut      = flag.String("report", "", "optional report json path")
		repoRoot       = flag.String("repo-root", "../..", "repo root for extracting supported instruction set")
		featureProfile = flag.String("feature-profile", "", "explicit actual Go CPU profile and source proof (single target, ordinary external module only)")
		featureTimeout = flag.Duration("feature-timeout", time.Hour, "deadline for the explicit feature-profile consumer")
		metadataOnly   = flag.Bool("metadata-only", false, "private actual Go generated-header query; never translates assembly")
		signatureQuery = flag.Bool("signature-source-query", false, "private ordinary-type/CPP missing-reference query; never emits LLVM")
	)
	instrumentationProfile := flag.String("instrumentation-profile", "", "private actual Go instrumentation source context; cannot supply ordinary profile evidence")
	instrumentationDirectory := flag.String("instrumentation-package-dir", ".", "exact module-relative original instrumentation package directory")
	instrumentationMetadata := flag.String("instrumentation-metadata", "", "independently captured same-mode metadata required for instrumentation object consumption")
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
	if requestedInstrumentationCLI(flag.CommandLine) {
		if *featureTimeout <= 0 || *reportOut == "" {
			fatalf("instrumentation consumption requires a positive deadline and its separate report")
		}
		ctx, cancel := context.WithTimeout(context.Background(), *featureTimeout)
		defer cancel()
		result, err := runInstrumentationCLI(ctx, instrumentationCLIOptions{
			Profile: *instrumentationProfile, Directory: *instrumentationDirectory, Metadata: *instrumentationMetadata,
			OrdinaryProfile: *featureProfile, Targets: specs, Patterns: pats, Tags: tags, AsmFiles: exactAsmFiles,
			Module: *modulePath, Output: *outDir, MetadataOnly: *metadataOnly, SignatureQuery: *signatureQuery,
			Compile: *compile, KeepObject: *keepObj, OptLevel: *llcOptLevel, LLC: *llcPath,
			AllTargets: *allTargets, ExplicitTargets: *targets != "", ListOnly: *listOnly, Limit: *limit,
			StrictLoad: *strictLoad, KeepGoing: *keepGoing, Annotate: *annotate,
		})
		if err != nil {
			fatalf("instrumentation consumer: %v", err)
		}
		writeReport(*reportOut, result)
		return
	}
	if (*metadataOnly || *signatureQuery) && (*featureProfile == "" || *reportOut == "" || len(specs) != 1 || *compile || *listOnly || *limit != 0 || *allTargets || *metadataOnly && *signatureQuery) {
		fatalf("metadata-only requires one explicit ordinary profile and cannot emit translation/list/matrix evidence")
	}
	ccfg, err := resolveCompileConfig(*compile, *llcPath, *keepObj, *llcOptLevel)
	if err != nil {
		fatalf("%v", err)
	}
	if *featureProfile == "" {
		if *featureTimeout <= 0 {
			fatalf("ordinary source consumption requires a positive deadline")
		}
		ctx, cancel := context.WithTimeout(context.Background(), *featureTimeout)
		defer cancel()
		ccfg.Context = ctx
	}
	if *featureProfile != "" {
		if len(specs) != 1 || *featureTimeout <= 0 {
			fatalf("explicit feature profile requires one target and a positive deadline")
		}
		ctx, cancel := context.WithTimeout(context.Background(), *featureTimeout)
		defer cancel()
		ccfg.FeaturePath, ccfg.Context = *featureProfile, ctx
	}

	baseOut := *outDir
	if baseOut == "" {
		if len(specs) == 1 {
			baseOut = filepath.Join("_out", "plan9asmll", targetID(specs[0]))
		} else {
			baseOut = filepath.Join("_out", "plan9asmll")
		}
	}
	if *metadataOnly {
		metadata, err := queryGeneratedHeaders(specs[0], pats, tags, exactAsmFiles, *modulePath, baseOut, ccfg)
		if err != nil {
			fatalf("generated-header metadata: %v", err)
		}
		writeReport(*reportOut, metadata)
		return
	}
	if *signatureQuery {
		ccfg.SignatureQuery = &gotoolprofile.SignatureQueryProof{Protocol: gotoolprofile.SignatureQueryProtocol}
		report, _, err := runOneTarget(specs[0], pats, tags, exactAsmFiles, *modulePath, baseOut, false, 0, false, false, true, *repoRoot, ccfg)
		if err != nil || report.Failed != 0 {
			fatalf("missing-signature preflight: %v (failed=%d)", err, report.Failed)
		}
		writeReport(*reportOut, ccfg.SignatureQuery)
		return
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
	if ccfg.FeaturePath != "" {
		if listOnly || limit != 0 {
			return runReport{}, nil, fmt.Errorf("feature consumer requires the complete ordinary non-test package scope")
		}
		ccfg.Feature, err = loadFeatureConsumer(ccfg.Context, ccfg.FeaturePath, outDir, spec.Goos+"/"+spec.Goarch, modulePath, buildTags)
		if err != nil {
			return runReport{}, nil, err
		}
		strictLoad = true
	}
	var pkgs []*packages.Package
	var loadEnvironment []string
	if ccfg.Feature != nil && ccfg.Feature.Input.GeneratedHeaders != nil {
		pkgs, err = loadGeneratedHeaderPackages(ccfg.Feature, pats, buildTags)
		loadEnvironment = ccfg.Feature.Env
	} else {
		// Go treats _test.go specially, not similarly named assembly files.
		// An explicit ordinary profile always loads non-test packages and
		// proves their actual role below. Keep the legacy test-declaration
		// lookup heuristic separate from that evidence-producing path.
		includeTests := ccfg.Feature == nil && containsTestAssembly(exactAsmFiles)
		pkgs, loadEnvironment, err = loadPkgsInEnvironment(spec.Goos, spec.Goarch, pats, buildTags, modulePath, strictLoad, includeTests, ccfg.Feature)
	}
	if err != nil {
		return runReport{}, nil, fmt.Errorf("load packages: %w", err)
	}
	ccfg.x86CallerSelections = captureX86CallerSelectionsInEnvironment(pkgs, spec.Goos+"/"+spec.Goarch, loadEnvironment)
	if ccfg.Feature != nil {
		if err := ccfg.Feature.capturePackages(pkgs); err != nil {
			return runReport{}, nil, err
		}
		if ccfg.Feature.Input.GeneratedHeaders != nil {
			if err := ccfg.Feature.captureGeneratedMetadata(pkgs, buildTags, outDir); err != nil {
				return runReport{}, nil, err
			}
		}
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
	if ccfg.Feature != nil {
		var actual []string
		for _, task := range tasks {
			name, err := ccfg.Feature.sourceName(task.AsmFile)
			if err != nil {
				return runReport{}, nil, err
			}
			actual = append(actual, name)
		}
		sort.Strings(actual)
		if len(actual) == 0 || !reflect.DeepEqual(actual, ccfg.Feature.Input.AsmFiles) {
			return runReport{}, nil, fmt.Errorf("actual selected assembly differs from the exact profile scope")
		}
	}
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
	if ccfg.Feature != nil {
		rep.FeatureSelection = ccfg.Feature.Proof
		if ccfg.SignatureQuery != nil {
			ccfg.SignatureQuery.Selection = ccfg.Feature.Proof
		}
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
		diagnostics := instructionDiagnostics{supported: supportedOps}
		fileConfig := ccfg
		fileConfig.diagnostics = &diagnostics
		err := compileOne(pkg, arch, spec.Goos, spec.Goarch, triple, t, annotate, fileConfig)
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
			unsupported, hits := diagnostics.ops, diagnostics.hits
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
		if ccfg.SignatureQuery == nil {
			fmt.Fprintf(os.Stderr, "[%d/%d] OK   %s\n", idx, len(tasks), t.AsmFile)
			rep.Success++
		} else {
			fmt.Fprintf(os.Stderr, "[%d/%d] QUERY %s (no LLVM output)\n", idx, len(tasks), t.AsmFile)
		}
	}

	rep.Duration = time.Since(start).String()
	rep.UnsupportedOps = flattenUnsupportedAgg(unsupportedAgg)
	if ccfg.Feature != nil {
		binary, err := exec.LookPath("go")
		if err != nil {
			return rep, nil, err
		}
		binary, err = filepath.Abs(binary)
		if err != nil {
			return rep, nil, err
		}
		if err := ccfg.Feature.reobserve(binary, outDir); err != nil {
			return rep, nil, err
		}
		if ccfg.SignatureQuery != nil {
			sort.Slice(ccfg.SignatureQuery.Requests, func(i, j int) bool {
				a, b := ccfg.SignatureQuery.Requests[i], ccfg.SignatureQuery.Requests[j]
				return a.File+"\x00"+a.Symbol < b.File+"\x00"+b.Symbol
			})
			if err := gotoolprofile.ValidateSignatureQuery(ccfg.Feature.Input, ccfg.SignatureQuery, buildTags); err != nil {
				return rep, nil, err
			}
		}
	}
	if rep.Failed != 0 {
		fmt.Fprintf(os.Stderr, "finished with failures: success=%d not_applicable=%d failed=%d total=%d\n", rep.Success, rep.NotApplicable, rep.Failed, rep.TotalAsm)
	} else {
		fmt.Fprintf(os.Stderr, "finished: success=%d not_applicable=%d total=%d\n", rep.Success, rep.NotApplicable, rep.TotalAsm)
	}
	return rep, nil, nil
}

func compileOne(pkg *packages.Package, arch plan9asm.Arch, goos, goarch, triple string, t asmTask, annotate bool, ccfg compileConfig) error {
	err := compileOneAttempt(pkg, arch, goos, goarch, triple, t, annotate, ccfg)
	retry, retryable := x86SDKNumericalRetryCause(err)
	if !retryable {
		return err
	}
	ccfg.acquireSDKNumerical = true
	if err := compileOneAttempt(pkg, arch, goos, goarch, triple, t, annotate, ccfg); err != nil {
		return errors.Join(retry, err)
	}
	return nil
}

func compileOneAttempt(pkg *packages.Package, arch plan9asm.Arch, goos, goarch, triple string, t asmTask, annotate bool, ccfg compileConfig) (compileErr error) {
	var continuationSource *continuationReferenceSource
	var outputStage *compileOutputStage
	// Registered first: every source guard and owner Close runs before any
	// public output changes. Chunk outputs share this attempt's one stage.
	defer func() {
		if outputStage != nil {
			if compileErr == nil && continuationSource != nil {
				compileErr = continuationSource.verify(ccfg.Context, plan9asm.GoAssemblerDefines(goos, goarch), ccfg.Feature)
			}
			if compileErr == nil {
				compileErr = outputStage.publish()
			}
			compileErr = errors.Join(compileErr, outputStage.close())
		}
	}()
	if ccfg.diagnostics != nil {
		ccfg.diagnostics.ops, ccfg.diagnostics.hits = nil, nil
	}
	defines := plan9asm.GoAssemblerDefines(goos, goarch)
	var cppProof *featureCPPProof
	var src []byte
	var originalInputs []string
	var originalReads *plan9asm.GoAssemblySourceReadReport
	var originalSearchMisses []string
	if ccfg.Feature != nil {
		if ccfg.Feature.Observed == nil || ccfg.Feature.Observed.Target != goos+"/"+goarch || ccfg.Feature.ID != gotoolprofile.ProfileID(ccfg.Feature.Observed) {
			return fmt.Errorf("assembler profile identity differs from the actual compilation target")
		}
		macros, err := ccfg.Feature.packageMacros(pkg)
		if err != nil {
			return err
		}
		if macros.PackageRole == "allow_asm_abi_path" {
			return fmt.Errorf("explicit ordinary CPU consumer does not cover special assembler package roles")
		}
		defines = macros.Defines
		if ccfg.Feature.Proof != nil {
			var inputs map[string]string
			var readReport plan9asm.GoAssemblySourceReadReport
			src, inputs, err = ccfg.Feature.preprocessCPPWithReadReport(t.AsmFile, pkg.PkgPath, defines, &readReport)
			if err != nil {
				return err
			}
			originalInputs, err = compileCPPInputFiles(ccfg.Feature, inputs)
			if err != nil {
				return err
			}
			originalSearchMisses = readReport.SearchMisses
			name, err := ccfg.Feature.sourceName(t.AsmFile)
			if err != nil {
				return err
			}
			cppProof = &featureCPPProof{File: name, Emission: "assembly", Inputs: inputs}
			if original := ccfg.Feature.Input.CPPOriginals; original != nil {
				cppProof.ExpandedSearchMisses = append([]gotoolprofile.CPPPackageSearchMiss{}, original.RequiredExpandedOperands[name]...)
			}
			expandedSource := append([]byte(nil), src...)
			defer func() {
				afterSource, after, err := ccfg.Feature.preprocessCPP(t.AsmFile, pkg.PkgPath, defines)
				if err == nil && (!reflect.DeepEqual(inputs, after) || !bytes.Equal(expandedSource, afterSource)) {
					err = fmt.Errorf("actual CPP input graph changed during translation")
				}
				_, macroErr := ccfg.Feature.packageMacros(pkg)
				compileErr = errors.Join(compileErr, err, macroErr)
			}()
		}
	}
	if src == nil {
		var err error
		var inputs *plan9asm.GoAssemblySourceReadReport
		src, inputs, err = plan9asm.ReadGoAssemblySourceWithReport(t.AsmFile, asmSourceRoot(pkg, t.AsmFile))
		if err != nil {
			return fmt.Errorf("read asm: %w", err)
		}
		for filename := range inputs.Inputs {
			originalInputs = append(originalInputs, filename)
		}
		originalSearchMisses = inputs.SearchMisses
		originalReads = inputs
	}
	originalSource := append([]byte(nil), src...)
	if cppProof != nil {
		cppProof.ExpandedSHA256 = featureBytesSHA256(src)
	}
	imports := make(map[string]*types.Package, len(pkg.Imports))
	for path, imported := range pkg.Imports {
		if imported != nil && imported.Types != nil {
			imports[path] = imported.Types
		}
	}
	goPackage := plan9asm.GoPackage{
		Path:    pkg.PkgPath,
		Types:   pkg.Types,
		Imports: imports,
	}
	src = plan9asm.ExpandGoAssemblySource(goPackage, src, goarch)
	if cppProof != nil {
		cppProof.TypedExpandedSHA256 = featureBytesSHA256(src)
		ccfg.Feature.Proof.CPP = append(ccfg.Feature.Proof.CPP, *cppProof)
	}
	file, err := parseCompleteCLIAssembly(arch, string(src), defines, goarch, &goPackage)
	if err != nil {
		if err.Error() == "no TEXT directive found" {
			proof, err := proveEmptyAssembly(pkg, t, goos+"/"+goarch, defines, ccfg)
			if err != nil {
				return err
			}
			if cppProof != nil {
				// The CPP entry was appended before parsing; retain the
				// separate native emptiness witness on that exact entry.
				ccfg.Feature.Proof.CPP[len(ccfg.Feature.Proof.CPP)-1].EmptyAssembly = proof
				ccfg.Feature.Proof.CPP[len(ccfg.Feature.Proof.CPP)-1].Emission = "symbol_free"
			}
			file = &plan9asm.File{Arch: arch}
			ccfg.emptyAssembly = proof
		} else {
			return fmt.Errorf("parse asm: %w", err)
		}
	}

	file, numericalSource, err := captureX86SDKNumericalSource(pkg, file, t.AsmFile, goos+"/"+goarch, ccfg)
	if err != nil {
		return fmt.Errorf("capture actual SDK numerical source: %w", err)
	}
	if numericalSource != nil {
		defer func() {
			compileErr = errors.Join(compileErr, numericalSource.verify(ccfg.Context), numericalSource.close())
		}()
		pkg = numericalSource.pkg
		ccfg.x86CallerSelections = map[*packages.Package]*x86CallerPackageSelection{pkg: numericalSource.selected}
	}

	if ccfg.diagnostics != nil {
		ccfg.diagnostics.collect(file)
	}

	// Use the Go-module frontend's complete-file continuation proof before
	// signature queries or bounded modules can discard a helper or its uses.
	resolve := resolveSymFunc(pkg.PkgPath)
	if numericalSource != nil {
		resolve = numericalSource.resolve
	}
	file, tailSource, tailSigs, err := prepareARM64ABI0TailSource(pkg, file, t.AsmFile, src,
		goos+"/"+goarch, defines, ccfg, resolve)
	if err != nil {
		return fmt.Errorf("prove ARM64 private source continuations: %w", err)
	}
	if tailSource != nil {
		defer func() {
			ctx := ccfg.Context
			if ctx == nil {
				ctx = context.Background()
			}
			compileErr = errors.Join(compileErr, tailSource.verify(ctx, defines, ccfg.Feature))
		}()
	}

	signaturePackage := pkg
	if tailSource != nil {
		signaturePackage = tailSource.actual
	}
	var testDeclarations asmDeclarationLookup
	if cppProof != nil {
		testDeclarations = func(original, symbol string) (plan9asm.FuncSig, int64, bool, error) {
			return ccfg.Feature.testDeclarationSignature(signaturePackage, filepath.Dir(t.AsmFile), original, symbol, goarch)
		}
	}
	var sigs map[string]plan9asm.FuncSig
	var declaredArgSizes map[string]int64
	registerFallbacks := make(map[string]plan9asm.FuncSig)
	if numericalSource != nil {
		sigs, declaredArgSizes, _, err = x86SDKDirectTailDeclarationInventory(numericalSource.goPackage, file,
			plan9asm.Options{Goarch: goarch, ResolveSym: resolve})
		if err != nil {
			return fmt.Errorf("collect actual SDK tail declarations: %w", err)
		}
	}
	if sigs == nil {
		sigs, declaredArgSizes, err = inferSigsForAsmFile(signaturePackage, file, resolve, goarch, testDeclarations, registerFallbacks)
		if err != nil {
			return fmt.Errorf("infer signatures: %w", err)
		}
	}
	if err := rebindARM64ABI0TailSignatures(sigs, tailSigs); err != nil {
		return err
	}
	if cppProof != nil {
		// A missing-signature query shares the exact parsed source role with
		// final consumption. Authenticate native data symbols before returning
		// query metadata, but never emit or count an LLVM output for a query.
		if len(file.Funcs) == 0 && ccfg.emptyAssembly == nil && ccfg.Feature.Input.SignatureSourceProtocol == gotoolprofile.SignatureSourceProtocol {
			dataOnly, err := proveDataOnlyAssembly(pkg, t, file, goos+"/"+goarch, defines, ccfg)
			if err != nil {
				return fmt.Errorf("authenticate data-only assembly: %w", err)
			}
			cpp := &ccfg.Feature.Proof.CPP[len(ccfg.Feature.Proof.CPP)-1]
			cpp.Emission, cpp.DataOnlyAssembly = "data_only", dataOnly
		}
		if ccfg.SignatureQuery != nil {
			requests, err := ccfg.Feature.queryMissingSignatureSources(pkg, file, t.AsmFile, resolve, goarch)
			if err != nil {
				return err
			}
			ccfg.SignatureQuery.Requests = append(ccfg.SignatureQuery.Requests, requests...)
			return nil
		}
		sources, err := ccfg.Feature.bindSignatureSources(pkg, file, t.AsmFile, resolve, goarch, sigs, declaredArgSizes)
		if err != nil {
			return fmt.Errorf("authenticate signature sources: %w", err)
		}
		ccfg.Feature.Proof.CPP[len(ccfg.Feature.Proof.CPP)-1].Signatures = sources
		ccfg.Feature.refreshTestDeclarationReferences()
	}
	if err := validateDeclaredTextArgSizes(file, resolve, declaredArgSizes, goarch); err != nil {
		return fmt.Errorf("target applicability: %w", err)
	}
	sigs, callerSource, err := bindX86CallerRegions(pkg, file, goos+"/"+goarch, goarch, t.AsmFile, defines, ccfg, resolve, sigs)
	if err != nil {
		return fmt.Errorf("prove actual Go raw-return callers: %w", err)
	}
	if callerSource != nil {
		defer func() {
			ctx := ccfg.Context
			if ctx == nil {
				ctx = context.Background()
			}
			compileErr = errors.Join(compileErr, callerSource.verify(ctx, defines, ccfg.Feature))
		}()
	}
	ccfg.X86TailGroups, continuationSource, err = inferX86TailGroups(pkg, file, t.AsmFile, goarch, resolve, sigs, defines, ccfg)
	if err != nil {
		return fmt.Errorf("prove private continuation entries: %w", err)
	}
	if continuationSource != nil {
		defer func() {
			ctx := ccfg.Context
			if ctx == nil {
				ctx = context.Background()
			}
			compileErr = errors.Join(compileErr, continuationSource.verify(ctx, defines, ccfg.Feature))
		}()
	}
	if ccfg.ordinaryDeclarations == nil && ccfg.numericalOptions == nil {
		options := compileTranslationOptions(triple, goarch, annotate, ccfg, resolve, sigs)
		if err := rejectUnboundCallerFrame(file, options, declaredArgSizes); err != nil {
			return err
		}
	}
	sigs, fixedLocalSource, err := prepareAMD64FixedLocalSource(pkg, file, t.AsmFile, goos+"/"+goarch,
		triple, goarch, ccfg, resolve, sigs, registerFallbacks)
	if err != nil {
		return fmt.Errorf("prove original fixed local backing: %w", err)
	}
	if fixedLocalSource != nil {
		defer func() {
			if err := fixedLocalSource.verify(ccfg.Context); err != nil {
				compileErr = errors.Join(compileErr, err)
			}
			if err := fixedLocalSource.close(); err != nil {
				compileErr = errors.Join(compileErr, err)
			}
		}()
	}
	sigs, scratchSource, err := prepareARM64NativeScratchSource(pkg, file, t.AsmFile,
		goos+"/"+goarch, triple, ccfg, resolve, sigs)
	if err != nil {
		return fmt.Errorf("prove actual native scratch closure: %w", err)
	}
	if scratchSource != nil {
		defer func() {
			compileErr = errors.Join(compileErr, scratchSource.Verify(ccfg.Context), scratchSource.Close())
		}()
	}
	if numericalSource != nil {
		options, err := numericalSource.bindNumericalReads(ccfg.Context, file,
			compileTranslationOptions(triple, goarch, annotate, ccfg, resolve, sigs))
		if err != nil {
			return fmt.Errorf("bind actual SDK numerical source: %w", err)
		}
		ccfg.numericalOptions = &options
		sigs = options.Sigs
	}
	// Ordinary declarations grant only the GoModule frontend's existing typed
	// read roles. Do not mix them with independently owned native/source roles.
	if ccfg.Feature == nil && !ccfg.acquireSDKNumerical && numericalSource == nil && tailSource == nil &&
		callerSource == nil && continuationSource == nil && fixedLocalSource == nil && scratchSource == nil && len(ccfg.X86TailGroups) == 0 {
		ccfg.ordinaryDeclarations, err = captureOrdinaryDeclarations(pkg, file, originalSource, originalReads, goos, goarch, ccfg)
		if err != nil {
			return fmt.Errorf("ordinary declarations: %w", err)
		}
		if source := ccfg.ordinaryDeclarations; source != nil {
			defer func() {
				compileErr = errors.Join(compileErr, source.verify(ccfg.Context))
				source.close()
			}()
		}
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
	outputStage, err = newCompileOutputStage(t, pkg, ccfg.Feature)
	if err != nil {
		return err
	}
	if err := outputStage.protectInputs(pkg, originalInputs, originalSearchMisses); err != nil {
		return err
	}
	// A continuation and the initializer taking its block address must remain
	// in one LLVM module, just as an oversized ordinary function stays intact.
	if ccfg.Enabled && !ccfg.KeepObj && len(ccfg.X86TailGroups) == 0 && fixedLocalSource == nil && scratchSource == nil && numericalSource == nil && ccfg.ordinaryDeclarations == nil &&
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
			stagedTask, err := outputStage.stageTask(partTask, ccfg)
			if err != nil {
				return err
			}
			if err := translateAndCompileModule(&part, triple, goarch, stagedTask, annotate, ccfg, resolve, sigs); err != nil {
				err = annotateUnboundCallerFrame(&part, resolve, sigs, declaredArgSizes, err)
				return fmt.Errorf("functions %d-%d/%d: %w", first+1, last, len(file.Funcs), err)
			}
			if err := outputStage.seal(); err != nil {
				return err
			}
			first = last
		}
		return nil
	}
	compileTask, err := outputStage.stageTask(t, ccfg)
	if err != nil {
		return err
	}
	err = translateAndCompileModule(file, triple, goarch, compileTask, annotate, ccfg, resolve, sigs)
	if err == nil {
		err = outputStage.seal()
	}
	// Only a complete-file translation rejected before writing IR/object may
	// request an independent SDK observation. A partially translated chunked
	// compilation never reaches this seam, and non-context errors stay errors.
	if !ccfg.acquireSDKNumerical && ccfg.Feature == nil && errors.Is(err, plan9asm.ErrProbeNeedsContext) &&
		x86SDKNumericalOwnerRequested(pkg, file, goos+"/"+goarch) {
		return &x86SDKNumericalRetryError{cause: err}
	}
	return annotateUnboundCallerFrame(file, resolve, sigs, declaredArgSizes, err)
}

func compileTranslationOptions(triple, goarch string, annotate bool, ccfg compileConfig,
	resolve func(string) string, sigs map[string]plan9asm.FuncSig,
) plan9asm.Options {
	return plan9asm.Options{
		TargetTriple: triple, ResolveSym: resolve, Sigs: sigs, Goarch: goarch,
		WASMABI: wasmABIForGoPackageTarget(goarch), AnnotateSource: annotate, X86TailGroups: ccfg.X86TailGroups,
	}
}

func translateAndCompileModule(file *plan9asm.File, triple, goarch string, t asmTask, annotate bool,
	ccfg compileConfig, resolve func(string) string, sigs map[string]plan9asm.FuncSig,
) error {
	ctx := llvm.NewContext()
	var mod llvm.Module
	var err error
	if ccfg.emptyAssembly != nil {
		if ccfg.emptyAssembly.Protocol != gotoolprofile.EmptyAssemblyProtocol ||
			len(file.Funcs) != 0 || len(file.Data) != 0 || len(file.Globl) != 0 {
			ctx.Dispose()
			return fmt.Errorf("symbol-free emission contradicts its native proof")
		}
		// Do not broaden the public translator's empty-file contract. Only
		// this CLI's actual successful Go object/listing check grants this.
		mod = ctx.NewModule("plan9asm-empty-assembly")
		mod.SetTarget(triple)
	} else if ccfg.ordinaryDeclarations != nil {
		mod, err = ccfg.ordinaryDeclarations.translate(ctx, file, triple, goarch, annotate, resolve)
	} else {
		options := compileTranslationOptions(triple, goarch, annotate, ccfg, resolve, sigs)
		if ccfg.numericalOptions != nil {
			requested, bound := options, *ccfg.numericalOptions
			requested.ResolveSym, bound.ResolveSym = nil, nil
			bound.NumericalReads = nil
			if !reflect.DeepEqual(requested, bound) {
				ctx.Dispose()
				return fmt.Errorf("%w: SDK numerical translation options changed after binding", plan9asm.ErrProbeNeedsContext)
			}
			options = *ccfg.numericalOptions
		}
		mod, err = plan9asm.TranslateModuleInContext(ctx, file, options)
	}
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
		if ccfg.Context != nil {
			cmd = exec.CommandContext(ccfg.Context, ccfg.LLC, args...)
			cmd.WaitDelay = 2 * time.Second
		}
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
		if ccfg.Feature != nil && ccfg.Feature.Proof != nil {
			object, err := gotoolprofile.FileSHA256(objPath)
			if err != nil {
				return err
			}
			name, err := ccfg.Feature.sourceName(t.AsmFile)
			if err != nil {
				return err
			}
			ccfg.Feature.Proof.Outputs = append(ccfg.Feature.Proof.Outputs, featureOutputProof{File: name, Part: filepath.Base(t.OutLL), IR: featureBytesSHA256([]byte(ll)), Object: object})
		}
		if !ccfg.KeepObj {
			if err := os.Remove(objPath); err != nil {
				return fmt.Errorf("remove generated object: %w", err)
			}
		}
	}
	if !ccfg.Enabled && ccfg.Feature != nil && ccfg.Feature.Proof != nil {
		name, err := ccfg.Feature.sourceName(t.AsmFile)
		if err != nil {
			return err
		}
		ccfg.Feature.Proof.Outputs = append(ccfg.Feature.Proof.Outputs, featureOutputProof{File: name, Part: filepath.Base(t.OutLL), IR: featureBytesSHA256([]byte(ll))})
	}
	return nil
}

func featureBytesSHA256(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }

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
	return loadPkgsForFeature(goos, goarch, patterns, buildTags, modulePath, strict, includeTests, nil)
}

func loadPkgsForFeature(goos, goarch string, patterns, buildTags []string, modulePath string, strict, includeTests bool, feature *featureConsumer) ([]*packages.Package, error) {
	pkgs, _, err := loadPkgsInEnvironment(goos, goarch, patterns, buildTags, modulePath, strict, includeTests, feature)
	return pkgs, err
}

func loadPkgsInEnvironment(goos, goarch string, patterns, buildTags []string, modulePath string, strict, includeTests bool, feature *featureConsumer) ([]*packages.Package, []string, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedEmbedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedModule |
			packages.NeedDeps |
			packages.NeedImports |
			packages.NeedTypes |
			packages.NeedTypesSizes,
		Tests: includeTests,
	}
	if feature != nil {
		cfg.Context, cfg.Env, cfg.Dir = feature.Context, feature.Env, feature.WorkDir
		cfg.Mode |= packages.NeedCompiledGoFiles
		// The producer's export/vet gates use this explicit module mode too.
		// Do not pass it through GOFLAGS, where it could hide selection tags.
		cfg.BuildFlags = append(cfg.BuildFlags, "-mod=mod")
	} else {
		var err error
		cfg.Env, err = ordinaryPackageEnvironment(goos, goarch, os.Environ())
		if err != nil {
			return nil, nil, err
		}
		cfg.Dir, err = sdkfrontend.WorkingDirectory("")
		if err != nil {
			return nil, nil, err
		}
	}
	if len(buildTags) != 0 {
		cfg.BuildFlags = append(cfg.BuildFlags, "-tags="+strings.Join(buildTags, ","))
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, nil, err
	}
	pkgs = filterPackagesByModule(pkgs, modulePath)
	if count := packages.PrintErrors(pkgs); strict && count != 0 {
		return nil, nil, fmt.Errorf("%d package loading error(s)", count)
	}
	for _, pkg := range pkgs {
		if err := loadLinknameSyntax(pkg); err != nil {
			return nil, nil, err
		}
	}
	return pkgs, append([]string(nil), cfg.Env...), nil
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
		var files []string
		if len(allow) == 0 {
			files = asmFilesOfPkg(p)
		} else {
			// An explicit profile scope must consume selected nonzero original
			// files even when their only content is whitespace or comments.
			// Only Go's actual selected OtherFiles can become tasks; the
			// subsequent profile match and object proof remain mandatory.
			for _, file := range p.OtherFiles {
				if !isAsmFile(file) {
					continue
				}
				rel, ok := moduleRelativeAsmPath(p, file)
				if !ok || !allow[rel] {
					continue
				}
				data, err := os.ReadFile(file)
				if err != nil || len(data) != 0 {
					files = append(files, file)
				}
			}
			sort.Strings(files)
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

type asmDeclarationLookup func(original, symbol string) (plan9asm.FuncSig, int64, bool, error)

func sigsForAsmFile(pkg *packages.Package, file *plan9asm.File, resolve func(string) string, goarch string) (map[string]plan9asm.FuncSig, map[string]int64, error) {
	return sigsForAsmFileWithDeclarations(pkg, file, resolve, goarch, nil)
}

func sigsForAsmFileWithDeclarations(pkg *packages.Package, file *plan9asm.File, resolve func(string) string, goarch string, declarations asmDeclarationLookup) (map[string]plan9asm.FuncSig, map[string]int64, error) {
	return inferSigsForAsmFile(pkg, file, resolve, goarch, declarations, nil)
}

func inferSigsForAsmFile(pkg *packages.Package, file *plan9asm.File, resolve func(string) string, goarch string,
	declarations asmDeclarationLookup, registerFallbacks map[string]plan9asm.FuncSig,
) (map[string]plan9asm.FuncSig, map[string]int64, error) {
	sigs := map[string]plan9asm.FuncSig{}
	declaredArgSizes := map[string]int64{}
	declaredSigs := map[string]bool{}
	knownABISigs := map[string]bool{}
	fallbackAsmSigs := map[string]bool{}
	if pkg == nil || pkg.Types == nil || pkg.Types.Scope() == nil {
		for _, fn := range file.Funcs {
			fs := fallbackSigForAsmFunc(fn, resolve(stripABISuffix(fn.Sym)), goarch)
			if err := validateInferredX86FrameExtent(fn, fs, goarch); err != nil {
				return nil, nil, err
			}
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
		fs, argSize, ok, err := tryDeclSig(scope, sym, resolved, linknames, goarch, sz, strings.HasSuffix(fn.Sym, "<ABIInternal>"))
		if err == nil && !ok && declarations != nil {
			fs, argSize, ok, err = declarations(fn.Sym, resolved)
		}
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

	var targetSigErr error
	addTargetSig := func(sym string, caller plan9asm.FuncSig, tail bool) {
		if sym == "" {
			return
		}
		internal := goarch == "arm64" && strings.HasSuffix(sym, "<ABIInternal>")
		sym = stripABISuffix(sym)
		resolved := resolve(sym)
		if resolved == "" {
			return
		}
		if existing, ok := sigs[resolved]; ok {
			if internal && declaredSigs[resolved] && existing.ARM64GoRegisterABI == nil {
				fs, _, _, err := tryDeclSig(scope, sym, resolved, linknames, goarch, sz, true)
				if err != nil {
					targetSigErr = err
				} else {
					sigs[resolved] = fs
				}
			}
			return
		}
		if goarch == "wasm" {
			if fs, ok := plan9asm.LookupGoWASMNativeFuncSig(resolved); ok {
				sigs[resolved] = fs
				knownABISigs[resolved] = true
				return
			}
		}
		fs, _, ok, err := tryDeclSig(scope, sym, resolved, linknames, goarch, sz, internal)
		if err == nil && !ok && declarations != nil {
			fs, _, ok, err = declarations(sym, resolved)
			if err != nil {
				targetSigErr = err
				return
			}
		}
		if internal && err != nil {
			targetSigErr = err
			return
		}
		if err == nil && ok {
			sigs[resolved] = fs
			declaredSigs[resolved] = true
			knownABISigs[resolved] = true
			return
		}
		if tail && caller.Name != "" {
			copySig := caller
			copySig.Name = resolved
			copySig.ARM64GoRegisterABI = nil
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
				candidate.ARM64GoRegisterABI = nil
				declaredTailCallers[targetResolved] = append(declaredTailCallers[targetResolved], candidate)
				declaredTailCallerFuncs[targetResolved] = append(declaredTailCallerFuncs[targetResolved], fn)
			}
		}
	}

	if targetSigErr != nil {
		return nil, nil, targetSigErr
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
	for _, fn := range file.Funcs {
		name := resolve(stripABISuffix(fn.Sym))
		if fallbackAsmSigs[name] && !knownABISigs[name] {
			if err := validateInferredX86FrameExtent(fn, sigs[name], goarch); err != nil {
				return nil, nil, err
			}
			// Record only this producer's plain register-entry guesses. The
			// value has no mutable slices or source capabilities to borrow.
			sig := sigs[name]
			plain := plan9asm.FuncSig{Name: name, Ret: sig.Ret, Args: sig.Args, Frame: sig.Frame}
			if registerFallbacks != nil && goarch == "amd64" && len(sig.Args)+len(sig.Frame.Params)+len(sig.Frame.Results) == 0 &&
				reflect.DeepEqual(sig, plain) {
				registerFallbacks[name] = plain
			}
		}
	}

	return sigs, declaredArgSizes, nil
}

// A fallback's observed FP offsets suggest types, not an argument envelope.
// Only the original explicit TEXT bounds those heuristic words. An actual Go
// declaration (including an independently established tail ABI) has its own
// layout and is deliberately not routed through this check.
func validateInferredX86FrameExtent(fn plan9asm.Func, sig plan9asm.FuncSig, goarch string) error {
	if goarch != "386" && goarch != "amd64" || len(sig.Frame.Params)+len(sig.Frame.Results) == 0 {
		return nil
	}
	readsFrame := false
	for _, ins := range fn.Instrs {
		for _, operand := range ins.Args {
			readsFrame = readsFrame || operand.Kind == plan9asm.OpFP || operand.Kind == plan9asm.OpFPAddr
		}
	}
	if !readsFrame {
		return nil // Pure tail forwarders borrow a separately proved ABI, not inferred source slots.
	}
	word := int64(8)
	if goarch == "386" {
		word = 4
	}
	for _, slots := range [][]plan9asm.FrameSlot{sig.Frame.Params, sig.Frame.Results} {
		for _, slot := range slots {
			if !hasExplicitTextArgSize(fn) || slot.Offset < 0 || slot.Offset > fn.ArgSize-word {
				return fmt.Errorf("%w: %s inferred FP word lacks its original explicit TEXT extent", plan9asm.ErrProbeNeedsContext, fn.Sym)
			}
		}
	}
	return nil
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
		// wildcard. A nonzero size must match either the declared data end or
		// the ABI0 allocation; trailing alignment does not create FP slots.
		if fn.ArgSize == 0 {
			continue
		}
		resolved := resolve(stripABISuffix(fn.Sym))
		expected, ok := declaredArgSizes[resolved]
		if !ok || fn.ArgSize == expected {
			continue
		}
		if !strings.Contains(fn.Sym, "<ABIInternal>") && goabi.MatchesABI0TextSize(goarch, fn.ArgSize, expected) {
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
	if goarch == "arm" {
		if native, ok := plan9asm.ARMKernelHelperFuncSig(fn, resolved); ok {
			return native
		}
	}
	paramOff := map[int64]struct{}{}
	retOff := map[int64]struct{}{}

	for _, ins := range fn.Instrs {
		op := strings.ToUpper(string(ins.Op))
		for i, a := range ins.Args {
			if a.Kind != plan9asm.OpFP && a.Kind != plan9asm.OpFPAddr {
				continue
			}
			offsets := paramOff
			if isLikelyResultSlot(op, i, len(ins.Args), a.FPName) {
				offsets = retOff
			}
			offsets[a.FPOffset] = struct{}{}
			if goarch == "arm64" {
				// Wide source accesses consume all of their words. This only
				// supplies the assembly-only fallback; actual Go declarations
				// retain their exact scalar fields and unaddressable padding.
				for byteOffset := int64(8); byteOffset < plan9asm.ARM64FPAccessBytes(ins, i); byteOffset += 8 {
					offsets[a.FPOffset+byteOffset] = struct{}{}
				}
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

func tryDeclSig(scope *types.Scope, sym, resolved string, linknames map[string]string, goarch string, sz types.Sizes, internal bool) (plan9asm.FuncSig, int64, bool, error) {
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
	fs := plan9asm.FuncSig{
		Name: resolved,
		Args: args,
		Ret:  ret,
		Frame: plan9asm.FrameLayout{
			Params:  frameParams,
			Results: frameResults,
		},
	}
	if goarch == "arm64" && internal {
		fs.ARM64GoRegisterABI, err = plan9asm.DeriveARM64GoRegisterABI(fn, fs)
		if err != nil {
			return plan9asm.FuncSig{}, 0, false, err
		}
	} else if goarch == "arm64" {
		// The common actual-declaration builder also retains its private FP
		// bit-use input, but only for an identical existing CLI transport. In
		// particular the CLI's omitted zero-size inputs remain unclosed; this
		// read-only proof cannot silently add an argument or change its index.
		actual, err := plan9asm.DeriveGoFuncABI0Signature(resolved, fn, goarch, sz)
		if err != nil {
			return plan9asm.FuncSig{}, 0, false, err
		}
		if reflect.DeepEqual(fs.Args, actual.Args) && fs.Ret == actual.Ret && reflect.DeepEqual(fs.Frame, actual.Frame) {
			fs = actual
		}
	}
	return fs, argSize, true, nil
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
	return plan9asm.SplitSymbolOffset(s)
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
	case "TEXT", "DATA", "GLOBL", "BYTE", "WORD", "LONG", "QUAD", "PCALIGN", "PCALIGNMAX", "FUNCDATA", "PCDATA":
		return true
	default:
		return false
	}
}

func extractSupportedOps(repoRoot, goarch string) (map[string]struct{}, error) {
	supported := map[string]struct{}{
		"RET":        {},
		"TEXT":       {},
		"GLOBL":      {},
		"DATA":       {},
		"BYTE":       {},
		"WORD":       {},
		"LONG":       {},
		"QUAD":       {},
		"PCALIGN":    {},
		"PCALIGNMAX": {},
		"FUNCDATA":   {},
		"PCDATA":     {},
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
	if goarch == "386" || goarch == "amd64" {
		shared, err := filepath.Glob(filepath.Join(repoRoot, "x86_*.go"))
		if err != nil {
			return nil, err
		}
		files = append(files, shared...)
	}
	sort.Strings(files)
	var sharedFiles []*ast.File
	var extractionFiles []*ast.File

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
		extractionFiles = append(extractionFiles, parsed)
		if strings.HasPrefix(filepath.Base(f), "x86_") {
			sharedFiles = append(sharedFiles, parsed)
			continue
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
	if len(sharedFiles) != 0 {
		types, err := loadSharedX86OpcodeTypes(repoRoot, extractionFiles)
		if err != nil {
			return nil, err
		}
		for _, file := range sharedFiles {
			collectSharedX86OpcodeDispatch(supported, file, types)
		}
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

func printUnsupportedHits(hits []unsupportedHit) {
	for _, h := range hits {
		fmt.Fprintf(os.Stderr, "    %s instruction %d: %-12s %s\n", h.Function, h.Instruction, h.Op, h.Source)
	}
}
