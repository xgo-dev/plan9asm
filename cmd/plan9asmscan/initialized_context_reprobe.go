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
	OriginalInstruction    plan9asm.Instr           `json:"original_instruction"`
	OriginalStatus         string                   `json:"original_status"`
	Source                 initializedContextSource `json:"source"`
	Initialization         []plan9asm.Instr         `json:"initialization"`
	Cleanup                []plan9asm.Instr         `json:"cleanup,omitempty"`
	MemoryPointerArgument  bool                     `json:"memory_pointer_argument,omitempty"`
	NumericAddressArgument bool                     `json:"numeric_address_argument,omitempty"`
	FrameSize              int64                    `json:"frame_size,omitempty"`
	IRTextGeneration       scanEvidenceStage        `json:"ir_text_generation"`
	LLVMObjectCompilation  scanEvidenceStage        `json:"llvm_object_compilation"`
	RuntimeExecution       scanEvidenceStage        `json:"runtime_execution"`
	Error                  string                   `json:"error,omitempty"`
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

type initializedContextArgument uint8

const (
	initializedNoArgument initializedContextArgument = iota
	initializedPointerArgument
	initializedNumericArgument
)

type initializedContextBuilder func(string, *initializedContextCase) (bool, error)

var initializedContextProfiles = map[string]initializedContextBuilder{
	"mask-logical":          initializedSequenceBuilder(plan9asm.InitializedMaskLogicalProbeSequence, initializedNoArgument),
	"scalar-register":       initializedSequenceBuilder(plan9asm.InitializedScalarRegisterProbeSequence, initializedNoArgument),
	"scalar-memory":         initializedSequenceBuilder(plan9asm.InitializedScalarMemoryProbeSequence, initializedPointerArgument),
	"scalar-numeric-memory": initializedSequenceBuilder(plan9asm.InitializedScalarNumericMemoryProbeSequence, initializedNumericArgument),
	"vector-memory":         initializedSequenceBuilder(plan9asm.InitializedVectorMemoryProbeSequence, initializedPointerArgument),
	"vector-numeric-memory": initializedSequenceBuilder(plan9asm.InitializedVectorNumericMemoryProbeSequence, initializedNumericArgument),
	"vector-register":       initializedSequenceBuilder(plan9asm.InitializedVectorRegisterProbeSequence, initializedNoArgument),
	"mmx":                   initializedMMXBuilder,
}

func initializedSequenceBuilder(prepare func(string, plan9asm.Instr) ([]plan9asm.Instr, bool, error),
	argument initializedContextArgument) initializedContextBuilder {
	return func(goarch string, source *initializedContextCase) (bool, error) {
		sequence, known, err := prepare(goarch, source.OriginalInstruction)
		if !known || err != nil {
			return known, err
		}
		source.Initialization = sequence[:len(sequence)-1]
		source.MemoryPointerArgument = argument == initializedPointerArgument
		source.NumericAddressArgument = argument == initializedNumericArgument
		return true, nil
	}
}

func initializedMMXBuilder(goarch string, source *initializedContextCase) (bool, error) {
	probe, known := plan9asm.BuildInitializedMMXProbe(goarch, source.OriginalInstruction)
	if known {
		source.Initialization = probe.Before
		source.Cleanup = probe.After
		source.MemoryPointerArgument = probe.MemoryPointerArgument
		source.FrameSize = probe.FrameSize
	}
	return known, nil
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

func runInitializedContextReprobe(forms map[string]*formStat, profile, goarch, llc string) (result *initializedContextReport, resultErr error) {
	result = &initializedContextReport{Profile: profile, Status: "failed",
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
	prepare := initializedContextProfiles[profile]
	if prepare == nil {
		return result, fmt.Errorf("unknown initialized-context profile %q", profile)
	}
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
		known, err := prepare(goarch, &source)
		if err != nil {
			return result, err
		}
		if !known {
			result.UnregisteredCases = append(result.UnregisteredCases, source)
			continue
		}
		if goarch == "amd64" && source.MemoryPointerArgument {
			for _, ins := range source.Initialization {
				if ins.Op == "MOVQ" && len(ins.Args) == 2 && ins.Args[0].Kind == plan9asm.OpFP &&
					ins.Args[1].Kind == plan9asm.OpReg && ins.Args[1].Reg == "BP" {
					// The complete NOSPLIT function must preserve its caller BP.
					source.FrameSize = 8
					break
				}
			}
		}
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
	var firstProbeErr error
	failedProbes := 0
	for i := range result.Cases {
		test := &result.Cases[i]
		if err := test.probe(goarch); err != nil {
			where := test.Source
			if firstProbeErr == nil {
				firstProbeErr = fmt.Errorf("%s:%d (%s instruction %d): %w", where.File, where.Line, where.Function, where.InstructionIndex, err)
			}
			test.Error = err.Error()
			test.IRTextGeneration.Status = "failed"
			failedProbes++
			continue
		}
		one := 1
		test.IRTextGeneration = scanEvidenceStage{Status: "pass", Forms: &one}
	}
	for start := 0; start < len(result.Cases); start += 32 {
		end := start + 32
		if end > len(result.Cases) {
			end = len(result.Cases)
		}
		batch, err := compileInitializedContextBatch(result.Cases[start:end], goarch, llc, start)
		if len(batch.CaseIndexes) == 0 {
			continue
		}
		if err != nil {
			batch.Status, batch.Error = "failed", err.Error()
			result.ObjectBatches = append(result.ObjectBatches, batch)
			if len(batch.Command) != 0 {
				for _, i := range batch.CaseIndexes {
					result.Cases[i].LLVMObjectCompilation.Status = "failed"
				}
			}
			return result, err
		}
		result.ObjectBatches = append(result.ObjectBatches, batch)
		for _, i := range batch.CaseIndexes {
			one := 1
			result.Cases[i].LLVMObjectCompilation = scanEvidenceStage{Status: "pass", Forms: &one}
		}
	}
	if firstProbeErr != nil {
		return result, fmt.Errorf("%d of %d initialized probes failed, first: %w", failedProbes, result.EligibleCases, firstProbeErr)
	}
	return result, nil
}

func (test initializedContextCase) sequence() []plan9asm.Instr {
	sequence := make([]plan9asm.Instr, 0, len(test.Initialization)+len(test.Cleanup)+2)
	sequence = append(sequence, test.Initialization...)
	sequence = append(sequence, test.OriginalInstruction)
	return append(sequence, test.Cleanup...)
}

func (test initializedContextCase) probe(goarch string) error {
	if !test.MemoryPointerArgument && !test.NumericAddressArgument && test.FrameSize == 0 {
		return plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, goarch, test.sequence())
	}
	fn, sig := test.function("initialized.memory", goarch)
	file := &plan9asm.File{Arch: plan9asm.ArchAMD64, Funcs: []plan9asm.Func{fn}}
	triple, _, _ := initializedContextTarget(goarch)
	_, err := plan9asm.Translate(file, plan9asm.Options{Goarch: goarch, TargetTriple: triple,
		Sigs: map[string]plan9asm.FuncSig{sig.Name: sig}})
	return err
}

func (test initializedContextCase) function(name, goarch string) (plan9asm.Func, plan9asm.FuncSig) {
	sequence := append(test.sequence(), plan9asm.Instr{Op: "RET", Raw: "RET"})
	fn := plan9asm.Func{Sym: name, FrameSize: test.FrameSize, Instrs: sequence}
	sig := plan9asm.FuncSig{Name: name, Ret: plan9asm.Void}
	if test.MemoryPointerArgument || test.NumericAddressArgument {
		fn.ArgSize = 8
		if goarch == "386" {
			fn.ArgSize = 4
		}
		argType := plan9asm.Ptr
		if test.NumericAddressArgument {
			argType = plan9asm.I64
			if goarch == "386" {
				argType = plan9asm.I32
			}
		}
		sig.Args = []plan9asm.LLVMType{argType}
		sig.Frame.Params = []plan9asm.FrameSlot{{Name: "memory", Type: argType, Field: -1}}
	}
	if test.FrameSize != 0 {
		header := plan9asm.Instr{Op: plan9asm.OpTEXT, Raw: fmt.Sprintf("TEXT %s(SB),4,$%d-%d", name, fn.FrameSize, fn.ArgSize)}
		fn.Instrs = append([]plan9asm.Instr{header}, fn.Instrs...)
	}
	return fn, sig
}

func initializedContextTarget(goarch string) (string, elf.Machine, elf.Class) {
	if goarch == "386" {
		return "i386-unknown-linux-gnu", elf.EM_386, elf.ELFCLASS32
	}
	return "x86_64-unknown-linux-gnu", elf.EM_X86_64, elf.ELFCLASS64
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
	for index, test := range cases {
		if test.IRTextGeneration.Status != "pass" {
			continue
		}
		batch.CaseIndexes = append(batch.CaseIndexes, start+index)
		name := fmt.Sprintf("initialized.%d", start+index)
		fn, sig := test.function(name, goarch)
		file.Funcs = append(file.Funcs, fn)
		sigs[name] = sig
	}
	if len(batch.CaseIndexes) == 0 {
		return batch, nil
	}
	triple, machine, class := initializedContextTarget(goarch)
	ir, err := plan9asm.Translate(file, plan9asm.Options{Goarch: goarch, TargetTriple: triple, Sigs: sigs})
	if err != nil {
		return batch, fmt.Errorf("initialized-context LLVM IR: %w", err)
	}
	if len(ir) == 0 || len(ir) > 4<<20 {
		return batch, fmt.Errorf("initialized-context LLVM IR size %d exceeds nonempty 4 MiB bound", len(ir))
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
	if err := checkInitializedContextFunctions(parsed, batch.CaseIndexes); err != nil {
		return batch, err
	}
	batch.ObjectSize, batch.ObjectSHA256 = int64(len(data)), fmt.Sprintf("%x", sha256.Sum256(data))
	batch.Status = "pass"
	return batch, nil
}

func checkInitializedContextFunctions(object *elf.File, cases []int) error {
	symbols, err := object.Symbols()
	if err != nil {
		return fmt.Errorf("read initialized-context LLVM object functions: %w", err)
	}
	executable := make(map[string]bool, len(cases))
	for _, symbol := range symbols {
		if elf.ST_TYPE(symbol.Info) != elf.STT_FUNC || symbol.Size == 0 ||
			symbol.Section == elf.SHN_UNDEF || int(symbol.Section) >= len(object.Sections) {
			continue
		}
		section := object.Sections[symbol.Section]
		if section.Type != elf.SHT_PROGBITS || section.Flags&elf.SHF_EXECINSTR == 0 || symbol.Value < section.Addr {
			continue
		}
		offset := symbol.Value - section.Addr
		if offset <= section.Size && symbol.Size <= section.Size-offset {
			executable[symbol.Name] = true
		}
	}
	for _, index := range cases {
		name := fmt.Sprintf("initialized.%d", index)
		if !executable[name] {
			return fmt.Errorf("initialized-context LLVM object missing executable function %s", name)
		}
	}
	return nil
}
