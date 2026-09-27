package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
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
	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

type pkgJSON struct {
	ImportPath string   `json:"ImportPath"`
	Dir        string   `json:"Dir"`
	SFiles     []string `json:"SFiles"`
}

type opStat struct {
	Count int
	Files map[string]int
	Pkgs  map[string]int
}

type formStat struct {
	Descriptor       plan9asm.InstructionDescriptor
	Count            int
	Files            map[string]int
	Examples         []string
	SupportedCount   int
	ContextCount     int
	UnsupportedCount int
	Errors           map[string]int
	ProbeKeys        map[string]struct{}
}

type parseErr struct {
	File string
	Err  string
}

type report struct {
	Corpus               string `json:"corpus"`
	GoVersion            string `json:"go_version"`
	Goos                 string `json:"goos"`
	Goarch               string `json:"goarch"`
	StdPkgs              int    `json:"std_pkgs"`
	StdPkgsWithSFile     int    `json:"std_pkgs_with_sfile"`
	AsmFiles             int    `json:"asm_files"`
	UniqueOps            int    `json:"unique_ops"`
	ParseErrCount        int    `json:"parse_err_count"`
	UniqueForms          int    `json:"unique_forms"`
	SupportedForms       int    `json:"supported_forms"`
	ContextForms         int    `json:"context_forms"`
	UnsupportedForms     int    `json:"unsupported_forms"`
	OfficialOpcodes      int    `json:"official_opcodes"`
	RuntimeVerifiedForms int    `json:"runtime_verified_forms"`
	CompileOnlyForms     int    `json:"compile_only_forms,omitempty"`
	EncoderOpcodes       int    `json:"encoder_opcodes"`
	EncoderForms         int    `json:"encoder_forms"`
	EncoderOpsObserved   int    `json:"encoder_opcodes_observed_in_corpus"`
	CoverageFingerprint  string `json:"coverage_fingerprint"`
	EncoderFingerprint   string `json:"encoder_fingerprint"`

	OpsByFreq         []opReport            `json:"ops_by_freq"`
	ClusterStats      []clusterReport       `json:"cluster_stats"`
	FamilyStats       []familyReport        `json:"unsupported_family_stats"`
	FormFamilies      []formFamilyReport    `json:"form_family_stats"`
	Forms             []formReport          `json:"forms"`
	Unsupported       []opReport            `json:"unsupported"`
	UnsupportedByForm []formReport          `json:"unsupported_by_form"`
	OpcodeCatalog     []opcodeCatalogReport `json:"opcode_catalog,omitempty"`
	EncoderCatalog    []encoderFormReport   `json:"encoder_form_catalog,omitempty"`
	ParseErrs         []parseErr            `json:"parse_errs,omitempty"`
}

type opReport struct {
	Op      string   `json:"op"`
	Cluster string   `json:"cluster"`
	Count   int      `json:"count"`
	Files   []string `json:"files,omitempty"`
}

type clusterReport struct {
	Cluster   string `json:"cluster"`
	UniqueOps int    `json:"unique_ops"`
	Hits      int    `json:"hits"`
}

type familyReport struct {
	Family    string   `json:"family"`
	UniqueOps int      `json:"unique_ops"`
	Hits      int      `json:"hits"`
	Examples  []string `json:"examples,omitempty"`
}

type formReport struct {
	plan9asm.InstructionDescriptor
	Status          string   `json:"status"`
	Count           int      `json:"count"`
	Files           []string `json:"files,omitempty"`
	Examples        []string `json:"examples,omitempty"`
	Errors          []string `json:"errors,omitempty"`
	RuntimeVerified bool     `json:"runtime_verified"`
	CompileOnly     bool     `json:"compile_only,omitempty"`
}

type formFamilyReport struct {
	Family      string `json:"family"`
	Forms       int    `json:"forms"`
	Supported   int    `json:"supported"`
	Context     int    `json:"context_required"`
	Unsupported int    `json:"unsupported"`
	Hits        int    `json:"hits"`
}

type opcodeCatalogReport struct {
	Opcode           string `json:"opcode"`
	Family           string `json:"family"`
	Observed         bool   `json:"observed_in_corpus"`
	NameClaimed      bool   `json:"name_claimed_by_lowerer"`
	SupportedForms   int    `json:"supported_forms"`
	ContextForms     int    `json:"context_forms"`
	UnsupportedForms int    `json:"unsupported_forms"`
	EncoderForms     int    `json:"encoder_forms"`
}

type conformanceManifest struct {
	Cases []struct {
		Goarch     string   `json:"goarch"`
		Forms      []string `json:"forms"`
		Validation string   `json:"validation"`
	} `json:"cases"`
}

var (
	reOpcodeName = regexp.MustCompile("(?m)^\\s*(?:obj\\.A_ARCHSPECIFIC:\\s*)?\"([A-Z][A-Za-z0-9.]*)\",\\s*$")
)

func main() {
	var (
		goos     = flag.String("goos", runtime.GOOS, "target GOOS")
		goarch   = flag.String("goarch", runtime.GOARCH, "target GOARCH (386/amd64/arm64/arm/wasm)")
		out      = flag.String("out", "", "write report to file (default stdout)")
		format   = flag.String("format", "md", "output format: md|json")
		repoRoot = flag.String("repo-root", ".", "plan9asm repository root for lowerers and conformance data")
		corpus   = flag.String("corpus", "std", "corpus to scan: std|go-asm|arm64-plan9")
		goroot   = flag.String("goroot", "", "Go root containing official assembler testdata (default: active Go toolchain)")
		input    = flag.String("input", "", "input file for corpora that require one")
	)
	flag.Parse()
	if *goroot == "" {
		root, err := gotoolchain.Root()
		if err != nil {
			fatalf("resolve active Go toolchain: %v", err)
		}
		*goroot = root
	}

	if *goarch != "386" && *goarch != "amd64" && *goarch != "arm64" && *goarch != "arm" && *goarch != "wasm" {
		fatalf("unsupported -goarch %q (expect 386/amd64/arm64/arm/wasm)", *goarch)
	}
	if err := validateCorpusTarget(*corpus, *goarch); err != nil {
		fatalf("%v", err)
	}
	arch, err := toPlan9Arch(*goarch)
	if err != nil {
		fatalf("%v", err)
	}

	var (
		pkgs          []pkgJSON
		ops           map[string]*opStat
		forms         map[string]*formStat
		parseErrs     []parseErr
		pkgWithSFiles int
		asmFiles      int
	)
	switch *corpus {
	case "std":
		pkgs, err = listStdPackages(*goos, *goarch)
		if err != nil {
			fatalf("list std packages: %v", err)
		}
		ops, forms, parseErrs, pkgWithSFiles, asmFiles, err = scanPackages(pkgs, arch, *goarch, *goroot)
	case "go-asm":
		if *goarch == "wasm" {
			// Go has no cmd/asm end-to-end testdata or operand-class encoder
			// table for wasm. Its official positive Plan 9 corpus is the wasm
			// assembly selected from GOROOT itself; the opcode namespace still
			// comes from cmd/internal/obj/wasm below.
			pkgs, err = listStdPackagesAtGOROOT(*goos, *goarch, *goroot)
			if err == nil {
				ops, forms, parseErrs, pkgWithSFiles, asmFiles, err = scanPackages(pkgs, arch, *goarch, *goroot)
			}
		} else {
			ops, forms, parseErrs, asmFiles, err = scanGoAssemblerTestdata(*goroot, arch, *goarch)
		}
	case "arm64-plan9":
		if strings.TrimSpace(*input) == "" {
			fatalf("-corpus arm64-plan9 requires -input")
		}
		ops, forms, parseErrs, asmFiles, err = scanARM64Plan9Cases(*input)
	default:
		fatalf("unsupported -corpus %q (expect std|go-asm|arm64-plan9)", *corpus)
	}
	if err != nil {
		fatalf("scan %s corpus: %v", *corpus, err)
	}

	supported, err := extractSupportedOps(*repoRoot, *goarch)
	if err != nil {
		fatalf("extract supported ops: %v", err)
	}

	var catalog []opcodeCatalogReport
	var encoderCatalog []encoderFormReport
	if *corpus == "go-asm" {
		encoderCatalog, err = loadEncoderForms(*goroot, *goarch)
		if err != nil {
			fatalf("load official encoder forms: %v", err)
		}
		catalog, err = buildOpcodeCatalog(*goroot, arch, *goarch, ops, forms, supported)
		if err != nil {
			fatalf("build official opcode catalog: %v", err)
		}
	}
	verified, compileOnly, err := loadConformanceForms(*repoRoot)
	if err != nil {
		fatalf("load executable conformance manifest: %v", err)
	}
	rep := buildReport(*corpus, goVersion(*goroot), *goos, *goarch, len(pkgs), pkgWithSFiles, asmFiles, ops, forms, supported, catalog, verified, compileOnly, parseErrs)
	attachEncoderCatalog(&rep, ops, encoderCatalog)

	var content []byte
	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "json":
		content, err = json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fatalf("marshal report json: %v", err)
		}
		content = append(content, '\n')
	case "md":
		content = renderMarkdown(rep)
	default:
		fatalf("unsupported -format %q (expect md|json)", *format)
	}

	if *out == "" {
		_, _ = os.Stdout.Write(content)
		return
	}
	if err := os.WriteFile(*out, content, 0644); err != nil {
		fatalf("write %s: %v", *out, err)
	}
}

func validateCorpusTarget(corpus, goarch string) error {
	if corpus == "arm64-plan9" && goarch != "arm64" {
		return errors.New("-corpus arm64-plan9 requires -goarch arm64")
	}
	return nil
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
		return "", fmt.Errorf("unsupported arch: %s", goarch)
	}
}

func listStdPackages(goos, goarch string) ([]pkgJSON, error) {
	return listStdPackagesWithCommand("go", goos, goarch, nil)
}

func listStdPackagesAtGOROOT(goos, goarch, goroot string) ([]pkgJSON, error) {
	goName := "go"
	if runtime.GOOS == "windows" {
		goName += ".exe"
	}
	goCommand := filepath.Join(goroot, "bin", goName)
	if _, err := os.Stat(goCommand); err != nil {
		return nil, fmt.Errorf("Go command for GOROOT %s: %w", goroot, err)
	}
	return listStdPackagesWithCommand(goCommand, goos, goarch, []string{"GOROOT=" + goroot})
}

func listStdPackagesWithCommand(goCommand, goos, goarch string, extraEnv []string) ([]pkgJSON, error) {
	cmd := exec.Command(goCommand, "list", "-json", "std")
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS="+goos,
		"GOARCH="+goarch,
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.Output()
	if err != nil {
		var msg string
		if ee, ok := err.(*exec.ExitError); ok {
			msg = strings.TrimSpace(string(ee.Stderr))
		}
		if msg != "" {
			return nil, fmt.Errorf("go list -json std: %w: %s", err, msg)
		}
		return nil, fmt.Errorf("go list -json std: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(out))
	var outPkgs []pkgJSON
	for {
		var p pkgJSON
		err := dec.Decode(&p)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode go list output: %w", err)
		}
		outPkgs = append(outPkgs, p)
	}
	return outPkgs, nil
}

func scanPackages(pkgs []pkgJSON, arch plan9asm.Arch, goarch, goRoot string) (map[string]*opStat, map[string]*formStat, []parseErr, int, int, error) {
	ops := map[string]*opStat{}
	forms := map[string]*formStat{}
	var parseErrs []parseErr
	pkgWithSFiles := 0
	asmFiles := 0

	for _, p := range pkgs {
		if len(p.SFiles) == 0 || p.Dir == "" {
			continue
		}
		sfiles := packageSFiles(p)
		if len(sfiles) == 0 {
			continue
		}
		pkgWithSFiles++
		for _, path := range sfiles {
			src, err := os.ReadFile(path)
			if err != nil {
				return nil, nil, nil, 0, 0, fmt.Errorf("read %s: %w", path, err)
			}
			asmFiles++
			rel := shortStdPath(path, goRoot)

			file, err := plan9asm.Parse(arch, string(src))
			if err != nil {
				if strings.Contains(err.Error(), "no TEXT directive found") {
					continue
				}
				parseErrs = append(parseErrs, parseErr{File: rel, Err: err.Error()})
				continue
			}
			for _, fn := range file.Funcs {
				for i := 0; i < len(fn.Instrs); {
					ins := fn.Instrs[i]
					if ins.Op == plan9asm.OpLABEL {
						i++
						continue
					}
					if isX86RawDirective(arch, ins) {
						end := i + 1
						for end < len(fn.Instrs) && isX86RawDirective(arch, fn.Instrs[end]) {
							end++
						}
						sequence := fn.Instrs[i:end]
						probeErr := plan9asm.ProbeInstructionSequence(arch, goarch, sequence)
						probeKey := instructionSequenceProbeKey(sequence)
						for _, raw := range sequence {
							addFormStatWithProbeResult(forms, arch, goarch, raw, rel, probeKey, probeErr)
							addOpStat(ops, string(raw.Op), rel, p.ImportPath, 1)
						}
						i = end
						continue
					}
					nop := normalizeOp(string(ins.Op))
					if nop == "" {
						i++
						continue
					}
					addFormStat(forms, arch, goarch, ins, rel)
					addOpStat(ops, nop, rel, p.ImportPath, 1)
					i++
				}
			}
			if len(file.Data) > 0 {
				addOpStat(ops, "DATA", rel, p.ImportPath, len(file.Data))
			}
			if len(file.Globl) > 0 {
				addOpStat(ops, "GLOBL", rel, p.ImportPath, len(file.Globl))
			}
		}
	}
	return ops, forms, parseErrs, pkgWithSFiles, asmFiles, nil
}

func addFormStat(forms map[string]*formStat, arch plan9asm.Arch, goarch string, ins plan9asm.Instr, file string) {
	probeKey := fmt.Sprintf("%s %#v", ins.Op, ins.Args)
	st, fresh := prepareFormStat(forms, arch, goarch, ins, file, probeKey)
	if st == nil || !fresh {
		return
	}
	classifyFormProbe(st, plan9asm.ProbeInstruction(arch, goarch, ins))
}

func addFormStatWithProbeResult(forms map[string]*formStat, arch plan9asm.Arch, goarch string, ins plan9asm.Instr, file, probeKey string, probeErr error) {
	st, fresh := prepareFormStat(forms, arch, goarch, ins, file, probeKey)
	if st == nil || !fresh {
		return
	}
	classifyFormProbe(st, probeErr)
}

func prepareFormStat(forms map[string]*formStat, arch plan9asm.Arch, goarch string, ins plan9asm.Instr, file, probeKey string) (*formStat, bool) {
	desc := plan9asm.DescribeInstruction(arch, goarch, ins)
	if desc.Opcode == "" || desc.Opcode == string(plan9asm.OpLABEL) {
		return nil, false
	}
	st := forms[desc.Form]
	if st == nil {
		st = &formStat{
			Descriptor: desc,
			Files:      map[string]int{},
			Errors:     map[string]int{},
			ProbeKeys:  map[string]struct{}{},
		}
		forms[desc.Form] = st
	}
	st.Count++
	st.Files[file]++
	if len(st.Examples) < 3 && !containsString(st.Examples, strings.TrimSpace(ins.Raw)) {
		st.Examples = append(st.Examples, strings.TrimSpace(ins.Raw))
	}
	// Descriptor forms intentionally collapse concrete register numbers and
	// immediate values. Those values can still select different lowerer paths,
	// so cache exact instructions and aggregate their outcomes into the form.
	if _, ok := st.ProbeKeys[probeKey]; ok {
		return st, false
	}
	st.ProbeKeys[probeKey] = struct{}{}
	return st, true
}

func classifyFormProbe(st *formStat, err error) {
	switch {
	case err == nil:
		st.SupportedCount++
	case errors.Is(err, plan9asm.ErrProbeNeedsContext):
		st.ContextCount++
	default:
		st.UnsupportedCount++
		if len(st.Errors) < 3 {
			st.Errors[err.Error()]++
		}
	}
}

func isX86RawDirective(arch plan9asm.Arch, ins plan9asm.Instr) bool {
	if arch != plan9asm.ArchAMD64 {
		return false
	}
	switch normalizeOp(string(ins.Op)) {
	case "BYTE", "WORD", "LONG", "QUAD":
		return true
	default:
		return false
	}
}

func instructionSequenceProbeKey(instrs []plan9asm.Instr) string {
	var b strings.Builder
	b.WriteString("sequence")
	for _, ins := range instrs {
		fmt.Fprintf(&b, " %s %#v;", ins.Op, ins.Args)
	}
	return b.String()
}

func scanGoAssemblerTestdata(goroot string, arch plan9asm.Arch, goarch string) (map[string]*opStat, map[string]*formStat, []parseErr, int, error) {
	files, err := goAssemblerTestdataFiles(goroot, goarch)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	ops := map[string]*opStat{}
	forms := map[string]*formStat{}
	var parseErrs []parseErr
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, nil, 0, fmt.Errorf("read %s: %w", path, err)
		}
		rel, _ := filepath.Rel(filepath.Join(goroot, "src", "cmd", "asm", "internal", "asm", "testdata"), path)
		rel = filepath.ToSlash(rel)
		for lineno, line := range strings.Split(string(src), "\n") {
			trimmed := strings.TrimSpace(line)
			if !goAsmInstructionLine(trimmed) {
				continue
			}
			probeSrc := "TEXT plan9asm_probe(SB),NOSPLIT,$0\n" + trimmed + "\nRET\n"
			file, err := plan9asm.Parse(arch, probeSrc)
			if err != nil {
				parseErrs = append(parseErrs, parseErr{
					File: fmt.Sprintf("%s:%d", rel, lineno+1),
					Err:  err.Error(),
				})
				continue
			}
			for _, fn := range file.Funcs {
				for i, ins := range fn.Instrs {
					if i == len(fn.Instrs)-1 && ins.Op == plan9asm.OpRET {
						continue
					}
					if ins.Op == plan9asm.OpLABEL || ins.Op == plan9asm.OpTEXT {
						continue
					}
					addOpStat(ops, string(ins.Op), rel, "go-asm-testdata", 1)
					addFormStat(forms, arch, goarch, ins, rel)
				}
			}
		}
	}
	return ops, forms, parseErrs, len(files), nil
}

func scanARM64Plan9Cases(path string) (map[string]*opStat, map[string]*formStat, []parseErr, int, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, 0, fmt.Errorf("read ARM64 Plan 9 cases: %w", err)
	}
	ops := map[string]*opStat{}
	forms := map[string]*formStat{}
	var parseErrs []parseErr
	for lineno, line := range strings.Split(string(src), "\n") {
		_, asm, ok := strings.Cut(line, "|")
		if !ok {
			continue
		}
		asm = strings.TrimSpace(asm)
		if !goAsmInstructionLine(asm) {
			continue
		}
		probeSrc := "TEXT plan9asm_probe(SB),NOSPLIT,$0\n" + asm + "\nRET\n"
		file, err := plan9asm.Parse(plan9asm.ArchARM64, probeSrc)
		if err != nil {
			parseErrs = append(parseErrs, parseErr{File: fmt.Sprintf("%s:%d", filepath.Base(path), lineno+1), Err: err.Error()})
			continue
		}
		for _, fn := range file.Funcs {
			for _, ins := range fn.Instrs {
				if ins.Op == plan9asm.OpRET || ins.Op == plan9asm.OpLABEL || ins.Op == plan9asm.OpTEXT {
					continue
				}
				addOpStat(ops, string(ins.Op), filepath.Base(path), "golang.org/x/arch/arm64asm", 1)
				addFormStat(forms, plan9asm.ArchARM64, "arm64", ins, filepath.Base(path))
			}
		}
	}
	return ops, forms, parseErrs, 1, nil
}

func goAssemblerTestdataFiles(goroot, goarch string) ([]string, error) {
	root := filepath.Join(goroot, "src", "cmd", "asm", "internal", "asm", "testdata")
	var names []string
	switch goarch {
	case "386":
		names = []string{"386.s", "386enc.s"}
	case "amd64":
		names = []string{"amd64.s", "amd64enc.s", "amd64enc_extra.s"}
	case "arm":
		names = []string{"arm.s", "armv6.s"}
	case "arm64":
		names = []string{"arm64.s", "arm64enc.s", "arm64sveenc.s"}
	default:
		return nil, fmt.Errorf("unsupported goarch %q", goarch)
	}
	files := make([]string, 0, len(names)+20)
	for _, name := range names {
		path := filepath.Join(root, name)
		if _, err := os.Stat(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("official assembler testdata %s: %w", path, err)
		}
		files = append(files, path)
	}
	if goarch == "amd64" {
		avx, err := filepath.Glob(filepath.Join(root, "avx512enc", "*.s"))
		if err != nil {
			return nil, err
		}
		sort.Strings(avx)
		files = append(files, avx...)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no official assembler testdata for %s under %s", goarch, root)
	}
	return files, nil
}

func goAsmInstructionLine(line string) bool {
	if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
		return false
	}
	code := strings.TrimSpace(strings.SplitN(line, "//", 2)[0])
	if code == "" || strings.HasSuffix(code, ":") {
		return false
	}
	fields := strings.Fields(code)
	if len(fields) == 0 {
		return false
	}
	switch strings.ToUpper(fields[0]) {
	case "TEXT", "DATA", "GLOBL":
		return false
	default:
		return true
	}
}

func goVersion(goroot string) string {
	data, err := os.ReadFile(filepath.Join(goroot, "VERSION"))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
}

func buildOpcodeCatalog(
	goroot string,
	arch plan9asm.Arch,
	goarch string,
	ops map[string]*opStat,
	forms map[string]*formStat,
	claimed map[string]struct{},
) ([]opcodeCatalogReport, error) {
	dir := goarch
	if goarch == "386" || goarch == "amd64" {
		dir = "x86"
	}
	pattern := filepath.Join(goroot, "src", "cmd", "internal", "obj", dir, "anames*.go")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no official opcode tables match %s", pattern)
	}
	sort.Strings(files)
	var names [][][]byte
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		names = append(names, reOpcodeName.FindAllSubmatch(src, -1)...)
	}
	out := make([]opcodeCatalogReport, 0, len(names))
	seen := map[string]struct{}{}
	formsByOpcode := make(map[string][]*formStat, len(forms))
	for _, st := range forms {
		formsByOpcode[st.Descriptor.Opcode] = append(formsByOpcode[st.Descriptor.Opcode], st)
	}
	for _, match := range names {
		op := normalizeOp(string(match[1]))
		if op == "" || op == "LAST" || strings.HasPrefix(op, "RESERVED") {
			continue
		}
		if _, ok := seen[op]; ok {
			continue
		}
		seen[op] = struct{}{}
		item := opcodeCatalogReport{
			Opcode:   op,
			Family:   plan9asm.InstructionFamily(arch, op),
			Observed: ops[op] != nil,
		}
		_, item.NameClaimed = claimed[op]
		for _, st := range formsByOpcode[op] {
			switch {
			case st.UnsupportedCount > 0:
				item.UnsupportedForms++
			case st.ContextCount > 0 && st.SupportedCount == 0:
				item.ContextForms++
			default:
				item.SupportedForms++
			}
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Opcode < out[j].Opcode })
	return out, nil
}

func loadConformanceForms(repoRoot string) (map[string]struct{}, map[string]struct{}, error) {
	path := filepath.Join(repoRoot, "testdata", "conformance", "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]struct{}{}, map[string]struct{}{}, nil
		}
		return nil, nil, err
	}
	var manifest conformanceManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	runtimeForms := map[string]struct{}{}
	compileOnlyForms := map[string]struct{}{}
	for _, tc := range manifest.Cases {
		for _, form := range tc.Forms {
			key := tc.Goarch + "\x00" + form
			switch tc.Validation {
			case "execute":
				if _, conflict := compileOnlyForms[key]; conflict {
					return nil, nil, fmt.Errorf("conformance form %q is both executable and compile-only", form)
				}
				runtimeForms[key] = struct{}{}
			case "compile-only":
				if _, conflict := runtimeForms[key]; conflict {
					return nil, nil, fmt.Errorf("conformance form %q is both executable and compile-only", form)
				}
				compileOnlyForms[key] = struct{}{}
			default:
				return nil, nil, fmt.Errorf("conformance case for %q has invalid validation %q", form, tc.Validation)
			}
		}
	}
	return runtimeForms, compileOnlyForms, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func packageSFiles(p pkgJSON) []string {
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

func addOpStat(ops map[string]*opStat, op, relFile, pkg string, count int) {
	nop := normalizeOp(op)
	if nop == "" || count <= 0 {
		return
	}
	s := ops[nop]
	if s == nil {
		s = &opStat{
			Files: map[string]int{},
			Pkgs:  map[string]int{},
		}
		ops[nop] = s
	}
	s.Count += count
	s.Files[relFile] += count
	s.Pkgs[pkg] += count
}

func normalizeOp(op string) string {
	op = strings.ToUpper(strings.TrimSpace(op))
	if op == "" {
		return ""
	}
	if strings.ContainsAny(op, "(),;*/") {
		return ""
	}
	if strings.Contains(op, "_") {
		return ""
	}
	if i := strings.IndexByte(op, '.'); i >= 0 {
		op = op[:i]
	}
	if op == "" {
		return ""
	}
	return op
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

	loweringArch := goarch
	if loweringArch == "386" {
		loweringArch = "amd64"
	}
	files, err := filepath.Glob(filepath.Join(repoRoot, loweringArch+"_*.go"))
	if err != nil {
		return nil, err
	}
	parserPath := filepath.Join(repoRoot, "parser.go")
	if _, err := os.Stat(parserPath); err == nil {
		files = append(files, parserPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat %s: %w", parserPath, err)
	}
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
					if ok {
						collectSupportedOpcodeMap(supported, literal)
					}
				}
			}
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			// A single-family lowerer often starts with `if op != "VEXT"` rather
			// than a switch. This is an implementation-backed support claim just
			// like an opcode switch case. Only accept a literal compared directly
			// with an identifier named op so unrelated strings cannot leak into
			// the supported-instruction inventory.
			if comparison, ok := node.(*ast.BinaryExpr); ok &&
				(comparison.Op == token.EQL || comparison.Op == token.NEQ) {
				if candidate, ok := opcodeComparedWithOp(comparison.X, comparison.Y); ok {
					if op := normalizeOp(candidate); op != "" {
						supported[op] = struct{}{}
					}
				}
			}
			if spec, ok := node.(*ast.ValueSpec); ok {
				for i, name := range spec.Names {
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
					collectSupportedOpcodeMap(supported, literal)
				}
			}
			if literal, ok := node.(*ast.CompositeLit); ok {
				mapType, isMap := literal.Type.(*ast.MapType)
				keyType, opKeyed := mapTypeKeyIdent(mapType)
				if isMap && opKeyed && keyType == "Op" {
					collectSupportedOpcodeMap(supported, literal)
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
				if op := normalizeOp(candidate); op != "" {
					supported[op] = struct{}{}
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
		if op := normalizeOp(candidate); op != "" {
			supported[op] = struct{}{}
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

func attachEncoderCatalog(rep *report, ops map[string]*opStat, catalog []encoderFormReport) {
	rep.EncoderCatalog = catalog
	rep.EncoderForms = len(catalog)
	opcodes := map[string]struct{}{}
	observed := map[string]struct{}{}
	byOpcode := map[string]int{}
	fingerprintEntries := make([]string, 0, len(catalog))
	for _, form := range catalog {
		opcodes[form.Opcode] = struct{}{}
		byOpcode[form.Opcode]++
		if ops[form.Opcode] != nil {
			observed[form.Opcode] = struct{}{}
		}
		fingerprintEntries = append(fingerprintEntries, form.Form)
	}
	rep.EncoderOpcodes = len(opcodes)
	rep.EncoderOpsObserved = len(observed)
	sort.Strings(fingerprintEntries)
	rep.EncoderFingerprint = fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(fingerprintEntries, "\n"))))
	for i := range rep.OpcodeCatalog {
		rep.OpcodeCatalog[i].EncoderForms = byOpcode[rep.OpcodeCatalog[i].Opcode]
	}
}

func buildReport(
	corpus, goVersion, goos, goarch string,
	stdPkgs, stdPkgsWithSFile, asmFiles int,
	ops map[string]*opStat,
	forms map[string]*formStat,
	supported map[string]struct{},
	catalog []opcodeCatalogReport,
	verified map[string]struct{},
	compileOnly map[string]struct{},
	parseErrs []parseErr,
) report {
	rep := report{
		Corpus:            corpus,
		GoVersion:         goVersion,
		Goos:              goos,
		Goarch:            goarch,
		StdPkgs:           stdPkgs,
		StdPkgsWithSFile:  stdPkgsWithSFile,
		AsmFiles:          asmFiles,
		UniqueOps:         len(ops),
		UniqueForms:       len(forms),
		OfficialOpcodes:   len(catalog),
		ParseErrCount:     len(parseErrs),
		OpsByFreq:         []opReport{},
		ClusterStats:      []clusterReport{},
		FamilyStats:       []familyReport{},
		FormFamilies:      []formFamilyReport{},
		Forms:             []formReport{},
		Unsupported:       []opReport{},
		UnsupportedByForm: []formReport{},
		OpcodeCatalog:     catalog,
		ParseErrs:         parseErrs,
	}

	clusterAgg := map[string]*clusterReport{}
	familyAgg := map[string]*familyReport{}

	all := []opReport{}
	unsupported := []opReport{}
	for op, st := range ops {
		cl := clusterOf(goarch, op)
		files := topFiles(st.Files, 4)
		item := opReport{
			Op:      op,
			Cluster: cl,
			Count:   st.Count,
			Files:   files,
		}
		all = append(all, item)

		agg := clusterAgg[cl]
		if agg == nil {
			agg = &clusterReport{Cluster: cl}
			clusterAgg[cl] = agg
		}
		agg.UniqueOps++
		agg.Hits += st.Count

		if isDirective(op) {
			continue
		}
		if _, ok := supported[op]; !ok {
			unsupported = append(unsupported, item)
			fam := familyOf(goarch, op)
			agg := familyAgg[fam]
			if agg == nil {
				agg = &familyReport{Family: fam}
				familyAgg[fam] = agg
			}
			agg.UniqueOps++
			agg.Hits += st.Count
			if len(agg.Examples) < 6 {
				agg.Examples = append(agg.Examples, op)
			}
		}
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].Count != all[j].Count {
			return all[i].Count > all[j].Count
		}
		return all[i].Op < all[j].Op
	})
	sort.Slice(unsupported, func(i, j int) bool {
		if unsupported[i].Count != unsupported[j].Count {
			return unsupported[i].Count > unsupported[j].Count
		}
		return unsupported[i].Op < unsupported[j].Op
	})
	rep.OpsByFreq = all
	rep.Unsupported = unsupported

	formFamilies := map[string]*formFamilyReport{}
	for _, st := range forms {
		status := "supported"
		switch {
		case st.UnsupportedCount > 0:
			status = "unsupported"
			rep.UnsupportedForms++
		case st.ContextCount > 0 && st.SupportedCount == 0:
			status = "context-required"
			rep.ContextForms++
		default:
			rep.SupportedForms++
		}
		item := formReport{
			InstructionDescriptor: st.Descriptor,
			Status:                status,
			Count:                 st.Count,
			Files:                 topFiles(st.Files, 4),
			Examples:              append([]string(nil), st.Examples...),
			Errors:                topFiles(st.Errors, 3),
		}
		_, item.RuntimeVerified = verified[goarch+"\x00"+st.Descriptor.Form]
		if item.RuntimeVerified {
			rep.RuntimeVerifiedForms++
		}
		_, item.CompileOnly = compileOnly[goarch+"\x00"+st.Descriptor.Form]
		if item.CompileOnly {
			rep.CompileOnlyForms++
		}
		rep.Forms = append(rep.Forms, item)
		if status == "unsupported" {
			rep.UnsupportedByForm = append(rep.UnsupportedByForm, item)
		}
		fam := formFamilies[st.Descriptor.Family]
		if fam == nil {
			fam = &formFamilyReport{Family: st.Descriptor.Family}
			formFamilies[st.Descriptor.Family] = fam
		}
		fam.Forms++
		fam.Hits += st.Count
		switch status {
		case "supported":
			fam.Supported++
		case "context-required":
			fam.Context++
		case "unsupported":
			fam.Unsupported++
		}
	}
	sort.Slice(rep.Forms, func(i, j int) bool {
		if rep.Forms[i].Family != rep.Forms[j].Family {
			return rep.Forms[i].Family < rep.Forms[j].Family
		}
		if rep.Forms[i].Opcode != rep.Forms[j].Opcode {
			return rep.Forms[i].Opcode < rep.Forms[j].Opcode
		}
		return rep.Forms[i].Form < rep.Forms[j].Form
	})
	sort.Slice(rep.UnsupportedByForm, func(i, j int) bool {
		if rep.UnsupportedByForm[i].Count != rep.UnsupportedByForm[j].Count {
			return rep.UnsupportedByForm[i].Count > rep.UnsupportedByForm[j].Count
		}
		return rep.UnsupportedByForm[i].Form < rep.UnsupportedByForm[j].Form
	})
	for _, fam := range formFamilies {
		rep.FormFamilies = append(rep.FormFamilies, *fam)
	}
	sort.Slice(rep.FormFamilies, func(i, j int) bool {
		return rep.FormFamilies[i].Family < rep.FormFamilies[j].Family
	})

	for _, c := range clusterAgg {
		rep.ClusterStats = append(rep.ClusterStats, *c)
	}
	for _, f := range familyAgg {
		rep.FamilyStats = append(rep.FamilyStats, *f)
	}
	sort.Slice(rep.ClusterStats, func(i, j int) bool {
		if rep.ClusterStats[i].Hits != rep.ClusterStats[j].Hits {
			return rep.ClusterStats[i].Hits > rep.ClusterStats[j].Hits
		}
		return rep.ClusterStats[i].Cluster < rep.ClusterStats[j].Cluster
	})
	sort.Slice(rep.FamilyStats, func(i, j int) bool {
		if rep.FamilyStats[i].Hits != rep.FamilyStats[j].Hits {
			return rep.FamilyStats[i].Hits > rep.FamilyStats[j].Hits
		}
		return rep.FamilyStats[i].Family < rep.FamilyStats[j].Family
	})

	sort.Slice(rep.ParseErrs, func(i, j int) bool {
		if rep.ParseErrs[i].File != rep.ParseErrs[j].File {
			return rep.ParseErrs[i].File < rep.ParseErrs[j].File
		}
		return rep.ParseErrs[i].Err < rep.ParseErrs[j].Err
	})
	fingerprintEntries := make([]string, 0, len(rep.Forms)+len(rep.ParseErrs))
	for _, form := range rep.Forms {
		fingerprintEntries = append(fingerprintEntries, "form\t"+form.Form+"\t"+form.Status)
	}
	for _, pe := range rep.ParseErrs {
		fingerprintEntries = append(fingerprintEntries, "parse\t"+pe.File+"\t"+pe.Err)
	}
	sort.Strings(fingerprintEntries)
	rep.CoverageFingerprint = fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(fingerprintEntries, "\n"))))
	return rep
}

func renderMarkdown(rep report) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Plan9 Asm Scan Report (%s/%s)\n\n", rep.Goos, rep.Goarch)
	fmt.Fprintf(&b, "- corpus: `%s`\n", rep.Corpus)
	fmt.Fprintf(&b, "- Go version: `%s`\n", rep.GoVersion)
	fmt.Fprintf(&b, "- std packages: `%d`\n", rep.StdPkgs)
	fmt.Fprintf(&b, "- std packages with `.s`: `%d`\n", rep.StdPkgsWithSFile)
	fmt.Fprintf(&b, "- asm files scanned: `%d`\n", rep.AsmFiles)
	fmt.Fprintf(&b, "- unique ops: `%d`\n", rep.UniqueOps)
	fmt.Fprintf(&b, "- unique operand forms: `%d`\n", rep.UniqueForms)
	fmt.Fprintf(&b, "- form lowering: `%d` supported, `%d` context-required, `%d` unsupported\n",
		rep.SupportedForms, rep.ContextForms, rep.UnsupportedForms)
	fmt.Fprintf(&b, "- executable conformance forms observed in this corpus: `%d`\n", rep.RuntimeVerifiedForms)
	if rep.CompileOnlyForms > 0 {
		fmt.Fprintf(&b, "- explicit compile-only forms observed in this corpus: `%d`\n", rep.CompileOnlyForms)
	}
	if rep.EncoderForms > 0 {
		if rep.Goarch == "wasm" {
			fmt.Fprintf(&b, "- official wasm opcode entries: `%d` (`%d` observed in the official GOROOT corpus)\n",
				rep.EncoderOpcodes, rep.EncoderOpsObserved)
		} else {
			fmt.Fprintf(&b, "- official encoder-table forms: `%d` across `%d` opcodes (`%d` opcodes observed in positive testdata)\n",
				rep.EncoderForms, rep.EncoderOpcodes, rep.EncoderOpsObserved)
		}
	}
	if rep.OfficialOpcodes > 0 {
		fmt.Fprintf(&b, "- official opcode names: `%d`\n", rep.OfficialOpcodes)
	}
	fmt.Fprintf(&b, "- parser failures: `%d`\n\n", rep.ParseErrCount)

	if len(rep.OpcodeCatalog) > 0 {
		type catalogSummary struct {
			total, observed, claimed, encoderForms, supportedForms, unsupportedForms int
		}
		byFamily := map[string]*catalogSummary{}
		for _, op := range rep.OpcodeCatalog {
			sum := byFamily[op.Family]
			if sum == nil {
				sum = &catalogSummary{}
				byFamily[op.Family] = sum
			}
			sum.total++
			if op.Observed {
				sum.observed++
			}
			if op.NameClaimed {
				sum.claimed++
			}
			sum.supportedForms += op.SupportedForms
			sum.unsupportedForms += op.UnsupportedForms
			sum.encoderForms += op.EncoderForms
		}
		families := make([]string, 0, len(byFamily))
		for family := range byFamily {
			families = append(families, family)
		}
		sort.Strings(families)
		b.WriteString("## Official Opcode Catalog\n\n")
		b.WriteString("| family | official names | encoder forms | observed names | lowerer name claims | supported forms | unsupported forms |\n")
		b.WriteString("|---|---:|---:|---:|---:|---:|---:|\n")
		for _, family := range families {
			sum := byFamily[family]
			fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d | %d |\n",
				family, sum.total, sum.encoderForms, sum.observed, sum.claimed, sum.supportedForms, sum.unsupportedForms)
		}
		b.WriteString("\nThe JSON report contains the complete opcode list. A name claim is not semantic verification; operand-form probes and executable conformance cases are tracked separately.\n\n")
	}

	b.WriteString("## Operand Form Coverage By Family\n\n")
	b.WriteString("| family | forms | supported | context required | unsupported | hits |\n")
	b.WriteString("|---|---:|---:|---:|---:|---:|\n")
	for _, fam := range rep.FormFamilies {
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d |\n",
			fam.Family, fam.Forms, fam.Supported, fam.Context, fam.Unsupported, fam.Hits)
	}

	b.WriteString("## Cluster Summary\n\n")
	b.WriteString("| cluster | unique ops | hits |\n")
	b.WriteString("|---|---:|---:|\n")
	for _, c := range rep.ClusterStats {
		fmt.Fprintf(&b, "| %s | %d | %d |\n", c.Cluster, c.UniqueOps, c.Hits)
	}

	b.WriteString("\n## Unsupported Families\n\n")
	if len(rep.FamilyStats) == 0 {
		b.WriteString("_none_\n")
	} else {
		b.WriteString("| family | unique ops | hits | examples |\n")
		b.WriteString("|---|---:|---:|---|\n")
		for _, fam := range rep.FamilyStats {
			fmt.Fprintf(&b, "| %s | %d | %d | %s |\n",
				fam.Family, fam.UniqueOps, fam.Hits, strings.Join(fam.Examples, ", "))
		}
	}

	b.WriteString("\n## Unsupported Ops (vs current lowerers)\n\n")
	if len(rep.Unsupported) == 0 {
		b.WriteString("_none_\n")
	} else {
		b.WriteString("| op | cluster | hits | example files |\n")
		b.WriteString("|---|---|---:|---|\n")
		for _, it := range rep.Unsupported {
			fmt.Fprintf(&b, "| %s | %s | %d | %s |\n",
				it.Op, it.Cluster, it.Count, strings.Join(it.Files, ", "))
		}
	}

	b.WriteString("\n## Unsupported Operand Forms (real lowering probe)\n\n")
	if len(rep.UnsupportedByForm) == 0 {
		b.WriteString("_none_\n")
	} else {
		b.WriteString("| family | form | hits | examples | errors |\n")
		b.WriteString("|---|---|---:|---|---|\n")
		limit := rep.UnsupportedByForm
		if len(limit) > 120 {
			limit = limit[:120]
		}
		for _, it := range limit {
			fmt.Fprintf(&b, "| %s | `%s` | %d | `%s` | `%s` |\n",
				it.Family, it.Form, it.Count, strings.Join(it.Examples, "; "), strings.Join(it.Errors, "; "))
		}
	}

	b.WriteString("\n## Top Ops\n\n")
	b.WriteString("| op | cluster | hits |\n")
	b.WriteString("|---|---|---:|\n")
	top := rep.OpsByFreq
	if len(top) > 40 {
		top = top[:40]
	}
	for _, it := range top {
		fmt.Fprintf(&b, "| %s | %s | %d |\n", it.Op, it.Cluster, it.Count)
	}

	if len(rep.ParseErrs) > 0 {
		b.WriteString("\n## Parser Failures (first 40)\n\n")
		limit := rep.ParseErrs
		if len(limit) > 40 {
			limit = limit[:40]
		}
		for _, pe := range limit {
			fmt.Fprintf(&b, "- `%s`: `%s`\n", pe.File, pe.Err)
		}
	}

	return []byte(b.String())
}

func clusterOf(goarch, op string) string {
	if isDirective(op) {
		return "directive"
	}

	switch goarch {
	case "386", "amd64":
		switch {
		case strings.HasPrefix(op, "J") || op == "RET" || op == "CALL" || op == "JMP" || strings.HasPrefix(op, "SET") || strings.HasPrefix(op, "CMOV"):
			return "x86-control"
		case strings.HasPrefix(op, "V") || strings.HasPrefix(op, "P"):
			return "x86-simd"
		case strings.Contains(op, "CRC32"):
			return "x86-crc"
		case strings.Contains(op, "XCHG") || strings.Contains(op, "CMPXCHG") || strings.Contains(op, "LOCK") || strings.Contains(op, "FENCE"):
			return "x86-atomic"
		case strings.HasPrefix(op, "BS") || strings.HasPrefix(op, "BT") || strings.HasPrefix(op, "SH") || strings.HasPrefix(op, "RO") || strings.HasPrefix(op, "POPCNT"):
			return "x86-bit-shift"
		default:
			return "x86-scalar"
		}
	case "arm64":
		switch {
		case strings.HasPrefix(op, "V"):
			return "arm64-neon"
		case op == "B" || op == "BL" || strings.HasPrefix(op, "B.") || strings.HasPrefix(op, "CB") || strings.HasPrefix(op, "TB") || op == "RET":
			return "arm64-control"
		case strings.Contains(op, "XR") || strings.Contains(op, "CAS") || strings.Contains(op, "SWP") || op == "DMB" || op == "DSB" || op == "ISB":
			return "arm64-atomic"
		case strings.HasPrefix(op, "LS") || strings.HasPrefix(op, "ASR") || strings.HasPrefix(op, "ROR") || strings.HasPrefix(op, "RBIT") || strings.HasPrefix(op, "REV") || strings.HasPrefix(op, "CLZ"):
			return "arm64-bit-shift"
		default:
			return "arm64-scalar"
		}
	default:
		return "other"
	}
}

func familyOf(goarch, op string) string {
	switch goarch {
	case "386", "amd64":
		switch {
		case strings.HasPrefix(op, "AES"):
			return "aes"
		case strings.HasPrefix(op, "SHA1") || strings.HasPrefix(op, "SHA256"):
			return "sha"
		case strings.HasPrefix(op, "VGF2P8") || strings.Contains(op, "GF2P8"):
			return "gfni"
		case strings.HasPrefix(op, "KMOV") || strings.HasPrefix(op, "KXOR") || strings.HasPrefix(op, "KAND") || strings.HasPrefix(op, "KOR"):
			return "avx512-mask"
		case strings.HasPrefix(op, "VP") || strings.HasPrefix(op, "VMOV") || strings.HasPrefix(op, "VPERM") || strings.HasPrefix(op, "VEXTRACT") || strings.HasPrefix(op, "VPCOMPRESS") || strings.HasPrefix(op, "VPOPCNT") || strings.HasPrefix(op, "VZERO"):
			return "avx-vector"
		case strings.HasPrefix(op, "P") || op == "MOVO" || op == "MOVOA" || op == "MOVUPS" || op == "MOVAPS":
			return "sse-simd"
		case strings.HasPrefix(op, "ADCX") || strings.HasPrefix(op, "ADOX") || strings.HasPrefix(op, "MULX") || strings.HasPrefix(op, "RORX") || strings.HasPrefix(op, "SHLX") || strings.HasPrefix(op, "SARX") || strings.HasPrefix(op, "SHRX"):
			return "bmi2-adx"
		case strings.HasPrefix(op, "CMPXCHG") || strings.HasPrefix(op, "XADD") || strings.HasSuffix(op, "FENCE") || op == "PAUSE":
			return "atomic-memory"
		case strings.HasPrefix(op, "J") || strings.HasPrefix(op, "CMOV") || op == "CALL":
			return "branch-alias"
		case strings.HasPrefix(op, "ROR") || strings.HasPrefix(op, "ROL") || strings.HasPrefix(op, "SHL") || strings.HasPrefix(op, "SHR") || strings.HasPrefix(op, "SAL") || strings.HasPrefix(op, "BSWAP") || strings.HasPrefix(op, "POPCNT"):
			return "bit-rotate-shift"
		case strings.HasPrefix(op, "MOV") || strings.HasPrefix(op, "LEA") || op == "REP" || op == "CLD" || op == "STD" || op == "NOP" || op == "ADJSP":
			return "move-pseudo"
		default:
			return "scalar-misc"
		}
	case "arm64":
		switch {
		case strings.HasPrefix(op, "AES") || strings.HasPrefix(op, "SHA"):
			return "crypto"
		case strings.HasPrefix(op, "V"):
			return "neon"
		case op == "B" || op == "BL" || strings.HasPrefix(op, "B.") || strings.HasPrefix(op, "CB") || strings.HasPrefix(op, "TB") || op == "RET":
			return "branch"
		case strings.Contains(op, "XR") || strings.Contains(op, "CAS") || strings.Contains(op, "SWP") || op == "DMB" || op == "DSB" || op == "ISB":
			return "atomic-memory"
		default:
			return "scalar-misc"
		}
	default:
		return "other"
	}
}

func isDirective(op string) bool {
	switch op {
	case "TEXT", "DATA", "GLOBL", "BYTE", "WORD", "LONG", "QUAD", "PCALIGN", "FUNCDATA", "PCDATA":
		return true
	default:
		return false
	}
}

func topFiles(m map[string]int, n int) []string {
	type kv struct {
		K string
		V int
	}
	arr := make([]kv, 0, len(m))
	for k, v := range m {
		arr = append(arr, kv{K: k, V: v})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].V != arr[j].V {
			return arr[i].V > arr[j].V
		}
		return arr[i].K < arr[j].K
	})
	if len(arr) > n {
		arr = arr[:n]
	}
	out := make([]string, 0, len(arr))
	for _, it := range arr {
		out = append(out, it.K)
	}
	return out
}

func shortStdPath(path, goRoot string) string {
	if goRoot == "" {
		return filepath.ToSlash(path)
	}
	root := filepath.ToSlash(filepath.Join(goRoot, "src")) + "/"
	p := filepath.ToSlash(path)
	if strings.HasPrefix(p, root) {
		return strings.TrimPrefix(p, root)
	}
	return p
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
