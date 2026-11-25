package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/xgo-dev/plan9asm"
)

type auditSummary struct {
	FilesAudited      int                       `json:"files_audited"`
	ParseErrors       int                       `json:"parse_errors"`
	TotalInstructions int                       `json:"total_instructions"`
	UniqueForms       int                       `json:"unique_forms"`
	SupportedForms    int                       `json:"supported_forms"`
	ContextForms      int                       `json:"context_forms"`
	UnsupportedForms  int                       `json:"unsupported_forms"`
	ByArch            map[string]archAuditStats `json:"by_arch,omitempty"`
	TopGaps           []auditGap                `json:"top_gaps,omitempty"`
	ParseErrorSamples []string                  `json:"parse_error_samples,omitempty"`
}

type archAuditStats struct {
	Files             int `json:"files"`
	ParseErrors       int `json:"parse_errors"`
	TotalInstructions int `json:"total_instructions"`
	UniqueForms       int `json:"unique_forms"`
	SupportedForms    int `json:"supported_forms"`
	ContextForms      int `json:"context_forms"`
	UnsupportedForms  int `json:"unsupported_forms"`
}

type auditGap struct {
	Arch        string   `json:"arch"`
	Opcode      string   `json:"opcode"`
	Family      string   `json:"family,omitempty"`
	Form        string   `json:"form"`
	Error       string   `json:"error"`
	Hits        int      `json:"hits"`
	ModuleCount int      `json:"module_count"`
	Modules     []string `json:"modules,omitempty"`
	Example     string   `json:"example"`
	ExampleFile string   `json:"example_file,omitempty"`
}

type probeStatus uint8

const (
	probeSupported probeStatus = iota + 1
	probeContext
	probeUnsupported
)

type probeOutcome struct {
	status probeStatus
	errMsg string
}

type formAgg struct {
	arch        string
	opcode      string
	family      string
	form        string
	supported   int
	context     int
	unsupported int
	hits        int
	errMsg      string
	example     string
	exampleFile string
	modules     map[string]struct{}
}

type auditCollector struct {
	mu          sync.Mutex
	probeMu     sync.RWMutex
	probeCache  map[string]probeOutcome
	files       int
	parseErrors int
	totalIns    int
	byArchFiles map[string]int
	byArchErrs  map[string]int
	byArchIns   map[string]int
	forms       map[string]*formAgg
	parseErrs   []string
}

func newAuditCollector() *auditCollector {
	return &auditCollector{
		probeCache:  make(map[string]probeOutcome),
		byArchFiles: make(map[string]int),
		byArchErrs:  make(map[string]int),
		byArchIns:   make(map[string]int),
		forms:       make(map[string]*formAgg),
	}
}

func (a *auditCollector) auditFile(modulePath, relPath string, data []byte) {
	arch, goarch, ok := inferAuditArch(relPath, data)
	if !ok {
		return
	}
	parsed, err := plan9asm.Parse(arch, string(data))
	if err != nil {
		a.mu.Lock()
		a.files++
		a.parseErrors++
		a.byArchFiles[goarch]++
		a.byArchErrs[goarch]++
		if len(a.parseErrs) < 20 {
			a.parseErrs = append(a.parseErrs, fmt.Sprintf("%s/%s: %v", modulePath, relPath, err))
		}
		a.mu.Unlock()
		return
	}

	type localForm struct {
		desc        plan9asm.InstructionDescriptor
		supported   int
		context     int
		unsupported int
		hits        int
		errMsg      string
		example     string
	}
	local := make(map[string]*localForm)
	insCount := 0

	for _, fn := range parsed.Funcs {
		for _, ins := range fn.Instrs {
			if ins.Op == plan9asm.OpLABEL || ins.Op == "" || ins.Op == plan9asm.OpTEXT || ins.Op == "DATA" || ins.Op == "GLOBL" {
				continue
			}
			insCount++
			desc := plan9asm.DescribeInstruction(arch, goarch, ins)
			out := a.probeCached(arch, goarch, desc, ins)
			f := local[desc.Form]
			if f == nil {
				f = &localForm{desc: desc, example: strings.TrimSpace(ins.Raw)}
				local[desc.Form] = f
			}
			f.hits++
			switch out.status {
			case probeSupported:
				f.supported++
			case probeContext:
				f.context++
			case probeUnsupported:
				f.unsupported++
				if f.errMsg == "" {
					f.errMsg = out.errMsg
					f.example = strings.TrimSpace(ins.Raw)
				}
			}
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.files++
	a.totalIns += insCount
	a.byArchFiles[goarch]++
	a.byArchIns[goarch] += insCount
	for formKey, lf := range local {
		k := goarch + "\x00" + formKey
		agg := a.forms[k]
		if agg == nil {
			agg = &formAgg{
				arch:        goarch,
				opcode:      lf.desc.Opcode,
				family:      lf.desc.Family,
				form:        lf.desc.Form,
				example:     lf.example,
				exampleFile: modulePath + "/" + relPath,
				modules:     make(map[string]struct{}),
			}
			a.forms[k] = agg
		}
		agg.hits += lf.hits
		agg.supported += lf.supported
		agg.context += lf.context
		agg.unsupported += lf.unsupported
		agg.modules[modulePath] = struct{}{}
		if agg.errMsg == "" && lf.errMsg != "" {
			agg.errMsg = lf.errMsg
			agg.example = lf.example
			agg.exampleFile = modulePath + "/" + relPath
		}
	}
}

func (a *auditCollector) probeCached(arch plan9asm.Arch, goarch string, desc plan9asm.InstructionDescriptor, ins plan9asm.Instr) probeOutcome {
	// Forms without immediates have operand-value-independent lowering; cache by
	// (goarch, form). Immediate-bearing forms cache by (goarch, trimmed raw) so
	// immediate-sensitive instructions (e.g. PCMPESTRI, VPTERNLOGD) stay exact.
	hasImm := false
	for _, opKind := range desc.Operands {
		if strings.Contains(opKind, "immediate") {
			hasImm = true
			break
		}
	}
	cacheKey := goarch + "\x00F\x00" + desc.Form
	if hasImm {
		cacheKey = goarch + "\x00R\x00" + strings.TrimSpace(ins.Raw)
	}
	a.probeMu.RLock()
	if cached, ok := a.probeCache[cacheKey]; ok {
		a.probeMu.RUnlock()
		return cached
	}
	a.probeMu.RUnlock()

	err := plan9asm.ProbeInstruction(arch, goarch, ins)
	var out probeOutcome
	switch {
	case err == nil:
		out = probeOutcome{status: probeSupported}
	case errors.Is(err, plan9asm.ErrProbeNeedsContext):
		out = probeOutcome{status: probeContext, errMsg: err.Error()}
	default:
		out = probeOutcome{status: probeUnsupported, errMsg: err.Error()}
	}
	a.probeMu.Lock()
	a.probeCache[cacheKey] = out
	a.probeMu.Unlock()
	return out
}

func (a *auditCollector) summarize(topN int) *auditSummary {
	a.mu.Lock()
	defer a.mu.Unlock()
	sum := &auditSummary{
		FilesAudited:      a.files,
		ParseErrors:       a.parseErrors,
		TotalInstructions: a.totalIns,
		ByArch:            make(map[string]archAuditStats),
		ParseErrorSamples: append([]string(nil), a.parseErrs...),
	}
	for arch, files := range a.byArchFiles {
		sum.ByArch[arch] = archAuditStats{
			Files:             files,
			ParseErrors:       a.byArchErrs[arch],
			TotalInstructions: a.byArchIns[arch],
		}
	}
	gaps := make([]auditGap, 0)
	for _, agg := range a.forms {
		sum.UniqueForms++
		st := sum.ByArch[agg.arch]
		st.UniqueForms++
		switch {
		case agg.unsupported > 0:
			sum.UnsupportedForms++
			st.UnsupportedForms++
			mods := make([]string, 0, len(agg.modules))
			for m := range agg.modules {
				mods = append(mods, m)
			}
			sort.Strings(mods)
			sampleMods := mods
			if len(sampleMods) > 5 {
				sampleMods = sampleMods[:5]
			}
			gaps = append(gaps, auditGap{
				Arch:        agg.arch,
				Opcode:      agg.opcode,
				Family:      agg.family,
				Form:        agg.form,
				Error:       agg.errMsg,
				Hits:        agg.unsupported,
				ModuleCount: len(mods),
				Modules:     sampleMods,
				Example:     agg.example,
				ExampleFile: agg.exampleFile,
			})
		case agg.supported > 0:
			sum.SupportedForms++
			st.SupportedForms++
		default:
			sum.ContextForms++
			st.ContextForms++
		}
		sum.ByArch[agg.arch] = st
	}
	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].Hits != gaps[j].Hits {
			return gaps[i].Hits > gaps[j].Hits
		}
		if gaps[i].ModuleCount != gaps[j].ModuleCount {
			return gaps[i].ModuleCount > gaps[j].ModuleCount
		}
		if gaps[i].Arch != gaps[j].Arch {
			return gaps[i].Arch < gaps[j].Arch
		}
		return gaps[i].Form < gaps[j].Form
	})
	if topN > 0 && len(gaps) > topN {
		gaps = gaps[:topN]
	}
	sum.TopGaps = gaps
	return sum
}

func inferAuditArch(name string, src []byte) (plan9asm.Arch, string, bool) {
	if arch := inferAssemblyArchitecture(name); arch != "unknown" {
		if a, ok := goarchToPlan9Arch(arch); ok {
			return a, arch, true
		}
	}
	base := strings.ToLower(strings.TrimSuffix(path.Base(name), ".s"))
	tokens := strings.Split(base, "_")
	for i := len(tokens) - 1; i >= 1; i-- {
		if a, ok := goarchToPlan9Arch(tokens[i]); ok {
			return a, tokens[i], true
		}
	}
	// Fallback: inspect //go:build or // +build header directives.
	sc := bufio.NewScanner(bytes.NewReader(src))
	for lines := 0; lines < 25 && sc.Scan(); lines++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "//") {
			break
		}
		var expr string
		switch {
		case strings.HasPrefix(line, "//go:build "):
			expr = strings.TrimPrefix(line, "//go:build ")
		case strings.HasPrefix(line, "// +build "):
			expr = strings.TrimPrefix(line, "// +build ")
		default:
			continue
		}
		found := ""
		ambiguous := false
		for _, cand := range []string{"amd64", "arm64", "386", "arm", "wasm"} {
			if hasBuildArchToken(expr, cand) {
				if found != "" && found != cand {
					ambiguous = true
					break
				}
				found = cand
			}
		}
		if found != "" && !ambiguous {
			if a, ok := goarchToPlan9Arch(found); ok {
				return a, found, true
			}
		}
	}
	return "", "", false
}

func hasBuildArchToken(expr, arch string) bool {
	for i := 0; i < len(expr); {
		if !isIdentChar(expr[i]) {
			i++
			continue
		}
		neg := i > 0 && expr[i-1] == '!'
		j := i
		for j < len(expr) && isIdentChar(expr[j]) {
			j++
		}
		if !neg && expr[i:j] == arch {
			return true
		}
		i = j
	}
	return false
}

func isIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

func goarchToPlan9Arch(goarch string) (plan9asm.Arch, bool) {
	switch goarch {
	case "amd64", "386":
		return plan9asm.ArchAMD64, true
	case "arm64":
		return plan9asm.ArchARM64, true
	case "arm":
		return plan9asm.ArchARM, true
	case "wasm":
		return plan9asm.ArchWASM, true
	default:
		return "", false
	}
}

func readZipAssemblyBytes(file *zip.File) ([]byte, bool, error) {
	if file.UncompressedSize64 > maxAsmProbeSize {
		return nil, true, nil
	}
	r, err := file.Open()
	if err != nil {
		return nil, false, err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, maxAsmProbeSize+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > maxAsmProbeSize {
		return nil, true, nil
	}
	return data, assemblySourceHasContent(data), nil
}

func parseModuleSpecs(spec string) ([]moduleVersion, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	var rawItems []string
	if strings.HasPrefix(spec, "@") {
		data, err := os.ReadFile(strings.TrimPrefix(spec, "@"))
		if err != nil {
			return nil, fmt.Errorf("read -modules file: %w", err)
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if idx := strings.IndexByte(line, '#'); idx >= 0 {
				line = strings.TrimSpace(line[:idx])
			}
			if line != "" {
				rawItems = append(rawItems, line)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("scan -modules file: %w", err)
		}
	} else {
		for _, part := range strings.Split(spec, ",") {
			if p := strings.TrimSpace(part); p != "" {
				rawItems = append(rawItems, p)
			}
		}
	}
	out := make([]moduleVersion, 0, len(rawItems))
	seen := make(map[string]struct{}, len(rawItems))
	for _, item := range rawItems {
		modPath, ver := item, ""
		if at := strings.LastIndexByte(item, '@'); at > 0 {
			modPath = strings.TrimSpace(item[:at])
			ver = strings.TrimSpace(item[at+1:])
		}
		if modPath == "" {
			return nil, fmt.Errorf("invalid module spec %q", item)
		}
		mv := moduleVersion{Path: modPath, Version: ver, Pinned: ver != ""}
		k := scanKey(mv)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, mv)
	}
	return out, nil
}
