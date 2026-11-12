package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

type initializedContextSource struct {
	File             string `json:"file"`
	Function         string `json:"function"`
	InstructionIndex int    `json:"instruction_index"`
	Line             int    `json:"line,omitempty"`
}

type initializedContextCase struct {
	OriginalInstruction   plan9asm.Instr           `json:"original_instruction"`
	OriginalStatus        string                   `json:"original_status"`
	Source                initializedContextSource `json:"source"`
	Initialization        []plan9asm.Instr         `json:"initialization"`
	IRTextGeneration      scanEvidenceStage        `json:"ir_text_generation"`
	LLVMObjectCompilation scanEvidenceStage        `json:"llvm_object_compilation"`
	RuntimeExecution      scanEvidenceStage        `json:"runtime_execution"`
}

type initializedContextObject struct {
	Status       string   `json:"status"`
	Error        string   `json:"error,omitempty"`
	CaseIndexes  []int    `json:"case_indexes"`
	ObjectSize   int64    `json:"object_size"`
	ObjectSHA256 string   `json:"object_sha256"`
	Command      []string `json:"command"`
}

type initializedContextReport struct {
	Profile           string                     `json:"profile"`
	Status            string                     `json:"status"`
	Error             string                     `json:"error,omitempty"`
	LLVMVersion       string                     `json:"llvm_version,omitempty"`
	EligibleCases     int                        `json:"eligible_cases"`
	Cases             []initializedContextCase   `json:"cases"`
	UnregisteredCases []initializedContextCase   `json:"unregistered_cases"`
	ObjectBatches     []initializedContextObject `json:"object_batches"`
}

// Retain occurrences, not the capped display Examples or form-level status.
// An isolated successful constant and an unknown-input instruction can share
// a descriptor; only the actual cached context outcome selects this record.
func captureContextSource(
	forms map[string]*formStat, arch plan9asm.Arch, goarch string,
	ins plan9asm.Instr, source initializedContextSource, probeErr error,
) {
	if !errors.Is(probeErr, plan9asm.ErrProbeNeedsContext) {
		return
	}
	descriptor := plan9asm.DescribeInstruction(arch, goarch, ins)
	st := forms[descriptor.Form]
	if st == nil {
		return
	}
	ins.Args = append([]plan9asm.Operand(nil), ins.Args...)
	for i := range ins.Args {
		if ins.Args[i].RegList != nil {
			ins.Args[i].RegList = append([]plan9asm.Reg(nil), ins.Args[i].RegList...)
		}
	}
	notRun := scanEvidenceStage{Status: "not_run"}
	st.contextSources = append(st.contextSources, initializedContextCase{
		OriginalInstruction: ins, OriginalStatus: "context-required", Source: source,
		IRTextGeneration: notRun, LLVMObjectCompilation: notRun, RuntimeExecution: notRun,
	})
}

func runInitializedContextReprobe(forms map[string]*formStat, goarch, llc string) (result *initializedContextReport, resultErr error) {
	result = &initializedContextReport{Profile: "mask-logical", Status: "failed",
		Cases: []initializedContextCase{}, UnregisteredCases: []initializedContextCase{}, ObjectBatches: []initializedContextObject{}}
	defer func() {
		if resultErr != nil {
			result.Error = resultErr.Error()
		} else if result.EligibleCases == 0 {
			result.Status = "not_run"
		} else {
			result.Status = "pass"
		}
	}()
	var sources []initializedContextCase
	for _, form := range forms {
		sources = append(sources, form.contextSources...)
	}
	sort.Slice(sources, func(i, j int) bool {
		a, b := sources[i].Source, sources[j].Source
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Function != b.Function {
			return a.Function < b.Function
		}
		return a.InstructionIndex < b.InstructionIndex
	})
	for _, source := range sources {
		sequence, known, err := plan9asm.InitializedMaskLogicalProbeSequence(goarch, source.OriginalInstruction)
		if !known {
			result.UnregisteredCases = append(result.UnregisteredCases, source)
			continue
		}
		if err != nil {
			return result, err
		}
		source.Initialization = sequence[:len(sequence)-1]
		result.Cases = append(result.Cases, source)
	}
	result.EligibleCases = len(result.Cases)
	llc, err := initializedContextLLC(llc)
	if err != nil {
		return result, err
	}
	version, err := initializedContextCommand(llc, "--version")
	if err != nil {
		return result, fmt.Errorf("LLVM22 version observation: %w", err)
	}
	result.LLVMVersion = strings.TrimSpace(string(version))
	match := regexp.MustCompile(`\bLLVM version ([0-9]+)\.`).FindStringSubmatch(result.LLVMVersion)
	if len(match) != 2 || match[1] != "22" {
		return result, fmt.Errorf("LLVM22 required, %s reported %q", llc, result.LLVMVersion)
	}
	for start := 0; start < len(result.Cases); start += 32 {
		end := start + 32
		if end > len(result.Cases) {
			end = len(result.Cases)
		}
		batch, err := compileInitializedContextBatch(result.Cases[start:end], goarch, llc, start)
		if err != nil {
			batch.Status, batch.Error = "failed", err.Error()
			result.ObjectBatches = append(result.ObjectBatches, batch)
			for i := start; i < end; i++ {
				if result.Cases[i].IRTextGeneration.Status == "pass" {
					result.Cases[i].LLVMObjectCompilation = scanEvidenceStage{Status: "failed"}
				} else {
					result.Cases[i].IRTextGeneration = scanEvidenceStage{Status: "failed"}
				}
			}
			return result, err
		}
		result.ObjectBatches = append(result.ObjectBatches, batch)
		for i := start; i < end; i++ {
			one := 1
			result.Cases[i].IRTextGeneration = scanEvidenceStage{Status: "pass", Forms: &one}
			result.Cases[i].LLVMObjectCompilation = scanEvidenceStage{Status: "pass", Forms: &one}
		}
	}
	return result, nil
}

func initializedContextLLC(name string) (string, error) {
	if name == "" {
		var err error
		name, err = exec.LookPath("llc-22")
		if err != nil {
			name, err = exec.LookPath("llc")
		}
		if err != nil {
			return "", fmt.Errorf("LLVM22 llc is required: %w", err)
		}
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("LLVM22 llc %q: %w", name, err)
	}
	return filepath.Abs(path)
}

// Observe owns and joins the actual process tree, preserves separate streams,
// and bounds each stream at 4 MiB. No retry or compiler-version fallback occurs.
func initializedContextCommand(command string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return goasmcmd.Run(ctx, "", os.Environ(), command, args...)
}

func compileInitializedContextBatch(cases []initializedContextCase, goarch, llc string, start int) (batch initializedContextObject, resultErr error) {
	file := &plan9asm.File{Arch: plan9asm.ArchAMD64}
	sigs := make(map[string]plan9asm.FuncSig)
	for index := range cases {
		batch.CaseIndexes = append(batch.CaseIndexes, start+index)
	}
	for index, test := range cases {
		sequence := append(append([]plan9asm.Instr(nil), test.Initialization...), test.OriginalInstruction)
		if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, goarch, sequence); err != nil {
			return batch, fmt.Errorf("initialized context %s/%s/%d: %w", test.Source.File, test.Source.Function, test.Source.InstructionIndex, err)
		}
		name := fmt.Sprintf("initialized.mask.%d", start+index)
		sequence = append(sequence, plan9asm.Instr{Op: "RET", Raw: "RET"})
		file.Funcs = append(file.Funcs, plan9asm.Func{Sym: name, Instrs: sequence})
		sigs[name] = plan9asm.FuncSig{Name: name, Ret: plan9asm.Void}
	}
	triple, machine, class := "x86_64-unknown-linux-gnu", elf.EM_X86_64, elf.ELFCLASS64
	if goarch == "386" {
		triple, machine, class = "i386-unknown-linux-gnu", elf.EM_386, elf.ELFCLASS32
	}
	ir, err := plan9asm.Translate(file, plan9asm.Options{Goarch: goarch, TargetTriple: triple, Sigs: sigs})
	if err != nil {
		return batch, fmt.Errorf("initialized-context LLVM IR: %w", err)
	}
	if len(ir) == 0 || len(ir) > 4<<20 {
		return batch, fmt.Errorf("initialized-context LLVM IR size %d exceeds nonempty 4 MiB bound", len(ir))
	}
	for i := range cases {
		one := 1
		cases[i].IRTextGeneration = scanEvidenceStage{Status: "pass", Forms: &one}
	}
	dir, err := os.MkdirTemp("", "plan9asmscan-initialized-context-")
	if err != nil {
		return batch, err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(dir)) }()
	input, output := filepath.Join(dir, "batch.ll"), filepath.Join(dir, "batch.o")
	if err := os.WriteFile(input, []byte(ir), 0o600); err != nil {
		return batch, err
	}
	batch.Command = []string{llc, "-O0", "-filetype=obj", "-mtriple=" + triple, input, "-o", output}
	if _, err := initializedContextCommand(llc, batch.Command[1:]...); err != nil {
		return batch, fmt.Errorf("initialized-context LLVM object compilation: %w", err)
	}
	info, err := os.Lstat(output)
	if err != nil {
		return batch, fmt.Errorf("initialized-context LLVM object is missing: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16<<20 {
		return batch, fmt.Errorf("initialized-context LLVM object must be a nonempty regular file within 16 MiB")
	}
	object, err := os.Open(output)
	if err != nil {
		return batch, err
	}
	data, readErr := io.ReadAll(io.LimitReader(object, (16<<20)+1))
	if err := errors.Join(readErr, object.Close()); err != nil {
		return batch, err
	}
	if len(data) == 0 || len(data) > 16<<20 {
		return batch, fmt.Errorf("initialized-context LLVM object changed beyond its size bound")
	}
	parsed, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return batch, fmt.Errorf("initialized-context LLVM output is not an ELF object: %w", err)
	}
	if parsed.Type != elf.ET_REL || parsed.Machine != machine || parsed.Class != class {
		return batch, fmt.Errorf("initialized-context LLVM object has a foreign target/type")
	}
	batch.ObjectSize, batch.ObjectSHA256 = int64(len(data)), fmt.Sprintf("%x", sha256.Sum256(data))
	batch.Status = "pass"
	return batch, nil
}
