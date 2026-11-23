package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

// Only go-list transport is synthetic. Parsing, isolated/context probes and
// LLVM22 object compilation in the positive test are the actual implementations.
// No fixture below supplies an executed-instruction or original-Go certificate.
func init() {
	if os.Getenv("PLAN9ASMSCAN_REPROBE_TEST_PROCESS") != "1" {
		return
	}
	switch strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe") {
	case "go":
		if !reflect.DeepEqual(os.Args[1:], []string{"list", "-json", "std"}) {
			fmt.Fprintln(os.Stderr, "unexpected fixture go command", os.Args[1:])
			os.Exit(2)
		}
		fmt.Println(os.Getenv("PLAN9ASMSCAN_REPROBE_TEST_PACKAGE"))
		os.Exit(0)
	case "reprobe-llc-fixture":
		version := "22.1.8"
		if os.Getenv("PLAN9ASMSCAN_REPROBE_TEST_LLC") == "wrong-version" {
			version = "23.1.0"
		}
		if len(os.Args) == 2 && os.Args[1] == "--version" {
			fmt.Println("LLVM version " + version)
			os.Exit(0)
		}
		if os.Getenv("PLAN9ASMSCAN_REPROBE_TEST_LLC") == "nonzero" {
			fmt.Fprintln(os.Stderr, "deliberate object compiler failure")
			os.Exit(7)
		}
		if os.Getenv("PLAN9ASMSCAN_REPROBE_TEST_LLC") == "wrong-functions" {
			if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "-o" {
				fmt.Fprintln(os.Stderr, "test fixture expected an output path")
				os.Exit(2)
			}
			data, err := os.ReadFile(os.Getenv("PLAN9ASMSCAN_REPROBE_TEST_WRONG_OBJECT"))
			if err == nil {
				err = os.WriteFile(os.Args[len(os.Args)-1], data, 0o600)
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
		}
		// A successful exit with no object must not become compilation evidence.
		os.Exit(0)
	default:
		var args []string
		if err := json.Unmarshal([]byte(os.Getenv("PLAN9ASMSCAN_REPROBE_TEST_ARGS")), &args); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Args = append([]string{"plan9asmscan"}, args...)
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		main()
		os.Exit(0)
	}
}

type initializedReprobeTestCase struct {
	OriginalInstruction plan9asm.Instr `json:"original_instruction"`
	OriginalStatus      string         `json:"original_status"`
	Source              struct {
		File             string `json:"file"`
		Function         string `json:"function"`
		InstructionIndex int    `json:"instruction_index"`
	} `json:"source"`
	Initialization        []plan9asm.Instr  `json:"initialization"`
	IRTextGeneration      scanEvidenceStage `json:"ir_text_generation"`
	LLVMObjectCompilation scanEvidenceStage `json:"llvm_object_compilation"`
	RuntimeExecution      scanEvidenceStage `json:"runtime_execution"`
}

type initializedReprobeTestReport struct {
	Profile           string                       `json:"profile"`
	EligibleCases     int                          `json:"eligible_cases"`
	Cases             []initializedReprobeTestCase `json:"cases"`
	UnregisteredCases []initializedReprobeTestCase `json:"unregistered_cases"`
	ObjectBatches     []struct {
		CaseIndexes  []int  `json:"case_indexes"`
		ObjectSize   int64  `json:"object_size"`
		ObjectSHA256 string `json:"object_sha256"`
	} `json:"object_batches"`
}

func initializedReprobeTestFixture(t *testing.T) (string, pkgJSON, map[string]plan9asm.Instr) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "src", "maskfixture")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var instructions []string
	// This independent oracle is the complete existing 8 x 4 typed family.
	for _, stem := range []string{"KAND", "KANDN", "KOR", "KXNOR", "KXOR", "KNOT", "KTEST", "KORTEST"} {
		for _, suffix := range []string{"B", "W", "D", "Q"} {
			args := "K0,K7,K3"
			if stem == "KNOT" {
				args = "K0,K3"
			} else if strings.Contains(stem, "TEST") {
				args = "K0,K7"
			}
			instructions = append(instructions, stem+suffix+" "+args)
		}
	}
	// More concrete cases than the three display Examples, including a repeated
	// instruction in a distinct owner. Source occurrences must not disappear.
	instructions = append(instructions,
		"KANDQ K0,K1,K2", "KANDQ K2,K3,K4", "KANDQ K4,K5,K6",
		"KANDQ K7,K6,K0", "KANDQ K0,K7,K3",
	)
	var source strings.Builder
	for i, instruction := range instructions {
		fmt.Fprintf(&source, "TEXT ·Case%02d(SB),4,$0-0\n\t%s\n\tRET\n\n", i, instruction)
	}
	// An unrelated context-required family is not initialized by this profile.
	source.WriteString("TEXT ·Other(SB),4,$0-0\n\tDIVL BX\n\tRET\n")
	// Same-source constants already have sufficient numerical inputs. A mixed
	// form-level classification must not hide its other context-required cases.
	source.WriteString("TEXT ·Constant(SB),4,$0-0\n\tKXORQ K1,K1,K3\n\tRET\n")
	file, err := plan9asm.Parse(plan9asm.ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Funcs) != len(instructions)+2 {
		t.Fatal("fixture lost a complete source owner", len(file.Funcs))
	}
	for _, arch := range []string{"386", "amd64"} {
		other := file.Funcs[len(instructions)].Instrs[1]
		if err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, arch, other); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
			t.Fatalf("unregistered fixture must need initialized division inputs on %s: %v", arch, err)
		}
	}
	want := make(map[string]plan9asm.Instr)
	for _, fn := range file.Funcs[:len(instructions)] {
		if len(fn.Instrs) != 3 || fn.Instrs[0].Op != "TEXT" || fn.Instrs[2].Op != "RET" {
			t.Fatal("fixture instruction locator changed", fn)
		}
		want[fn.Sym] = fn.Instrs[1]
	}
	if len(want) != 37 {
		t.Fatalf("fixture has %d owners, want 32 rows + 5 occurrence controls", len(want))
	}
	if err := os.WriteFile(filepath.Join(dir, "fixture.s"), []byte(source.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte("go1.27.2-synthetic-list-fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	goName := "go"
	if filepath.Ext(os.Args[0]) == ".exe" {
		goName += ".exe"
	}
	initializedReprobeTestLink(t, filepath.Join(root, "bin", goName))
	return root, pkgJSON{ImportPath: "maskfixture", Dir: dir, SFiles: []string{"fixture.s"}}, want
}

func initializedReprobeTestLink(t *testing.T, target string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(os.Args[0], target); err != nil {
		t.Fatal("link test-only transport executable", err)
	}
}

func initializedReprobeTestRun(t *testing.T, root string, pkg pkgJSON, arch, llc, mode string, profile bool) (map[string]json.RawMessage, []byte, error) {
	t.Helper()
	args := []string{"-corpus=std", "-format=json", "-goos=linux", "-goarch=" + arch,
		"-repo-root=../..", "-goroot=" + root}
	if profile {
		args = append(args, "-initialized-context-reprobe=mask-logical", "-llc="+llc)
	}
	argsJSON, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	pkgData, err := json.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "PLAN9ASMSCAN_REPROBE_TEST_PROCESS=1",
		"PLAN9ASMSCAN_REPROBE_TEST_ARGS="+string(argsJSON),
		"PLAN9ASMSCAN_REPROBE_TEST_PACKAGE="+string(pkgData),
		"PLAN9ASMSCAN_REPROBE_TEST_LLC="+mode)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	observed, runErr := goasmcmd.Observe(ctx, "", env, os.Args[0])
	var report map[string]json.RawMessage
	if runErr == nil {
		if err := json.Unmarshal(observed.Stdout, &report); err != nil {
			t.Fatalf("scanner did not emit a complete JSON report: %v\n%s\n%s", err, observed.Stdout, observed.Stderr)
		}
	}
	return report, observed.Stderr, runErr
}

func TestInitializedContextReprobeMaskLogicalExactSourcesAndObjects(t *testing.T) {
	llc, err := exec.LookPath("llc-22")
	if err != nil {
		llc, err = exec.LookPath("llc")
	}
	if err != nil {
		t.Fatal("LLVM22 is required for actual initialized-context object evidence", err)
	}
	for _, arch := range []string{"386", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			root, pkg, want := initializedReprobeTestFixture(t)
			baseline, stderr, err := initializedReprobeTestRun(t, root, pkg, arch, "", "", false)
			if err != nil {
				t.Fatalf("original classification: %v\n%s", err, stderr)
			}
			if _, ok := baseline["initialized_context_reprobe"]; ok {
				t.Fatal("default scan unexpectedly opted into initialized-context evidence")
			}
			actual, stderr, err := initializedReprobeTestRun(t, root, pkg, arch, llc, "", true)
			if err != nil {
				t.Fatalf("explicit initialized mask-logical profile: %v\n%s", err, stderr)
			}
			var evidence initializedReprobeTestReport
			if err := json.Unmarshal(actual["initialized_context_reprobe"], &evidence); err != nil {
				t.Fatal("missing independent initialized-context evidence", err)
			}
			delete(actual, "initialized_context_reprobe")
			if !reflect.DeepEqual(actual, baseline) {
				t.Fatal("counterfactual reprobe changed original report/classifications/fingerprints")
			}
			if evidence.Profile != "mask-logical" || evidence.EligibleCases != len(want) || len(evidence.Cases) != len(want) {
				t.Fatalf("profile denominator = %s/%d/%d, want mask-logical/%d/%d", evidence.Profile,
					evidence.EligibleCases, len(evidence.Cases), len(want), len(want))
			}
			seen := make(map[string]bool)
			for _, test := range evidence.Cases {
				instruction, ok := want[test.Source.Function]
				if !ok || seen[test.Source.Function] || test.Source.File != "maskfixture/fixture.s" || test.Source.InstructionIndex != 1 {
					t.Fatalf("missing, duplicate or foreign source locator: %+v", test.Source)
				}
				seen[test.Source.Function] = true
				if !reflect.DeepEqual(test.OriginalInstruction, instruction) || test.OriginalStatus != "context-required" {
					t.Fatalf("original concrete instruction/status changed: %+v", test)
				}
				if err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, arch, instruction); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
					t.Fatal("fixture no longer independently requires context", instruction, err)
				}
				sequence := append(append([]plan9asm.Instr(nil), test.Initialization...), instruction)
				if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch, sequence); err != nil {
					t.Fatal("recorded initialization is not actually sufficient", instruction, err)
				}
				initializedReprobeTestInputs(t, arch, test)
				for _, stage := range []scanEvidenceStage{test.IRTextGeneration, test.LLVMObjectCompilation} {
					if stage.Status != "pass" || stage.Forms == nil || *stage.Forms != 1 {
						t.Fatalf("missing per-case IR/object evidence: %+v", test)
					}
				}
				if test.RuntimeExecution.Status != "not_run" || test.RuntimeExecution.Forms != nil {
					t.Fatal("IR/object reprobe invented runtime evidence", test.RuntimeExecution)
				}
			}
			if len(evidence.UnregisteredCases) != 1 {
				t.Fatal("unregistered precise context source was discarded", evidence.UnregisteredCases)
			}
			other := evidence.UnregisteredCases[0]
			wantOther := compactProbeInstructions(t, "DIVL BX")[0]
			if other.Source.File != "maskfixture/fixture.s" || other.Source.Function != "·Other" || other.Source.InstructionIndex != 1 ||
				!reflect.DeepEqual(other.OriginalInstruction, wantOther) || other.OriginalStatus != "context-required" || len(other.Initialization) != 0 {
				t.Fatalf("unregistered context acquired synthetic input authority: %+v", other)
			}
			for _, stage := range []scanEvidenceStage{other.IRTextGeneration, other.LLVMObjectCompilation, other.RuntimeExecution} {
				if stage.Status != "not_run" || stage.Forms != nil {
					t.Fatal("unregistered context acquired reprobe evidence", stage)
				}
			}
			covered := make(map[int]bool)
			for _, batch := range evidence.ObjectBatches {
				digest, err := hex.DecodeString(batch.ObjectSHA256)
				if len(batch.CaseIndexes) == 0 || len(batch.CaseIndexes) > 32 || batch.ObjectSize <= 0 || err != nil || len(digest) != 32 {
					t.Fatalf("missing actual bounded object artifact: %+v", batch)
				}
				for _, index := range batch.CaseIndexes {
					if index < 0 || index >= len(want) || covered[index] {
						t.Fatalf("duplicate/foreign compiled case index %d", index)
					}
					covered[index] = true
				}
			}
			if len(covered) != len(want) {
				t.Fatalf("compiled %d/%d concrete source occurrences", len(covered), len(want))
			}
		})
	}
}

func initializedReprobeTestInputs(t *testing.T, arch string, test initializedReprobeTestCase) {
	t.Helper()
	inputs := test.OriginalInstruction.Args[:2]
	if strings.HasPrefix(string(test.OriginalInstruction.Op), "KNOT") {
		inputs = inputs[:1]
	}
	if len(test.Initialization) != 1+len(inputs) || test.Initialization[0].Raw != "MOVL $3,AX" {
		t.Fatal("profile did not retain a minimal explicit synthetic initialization", test.Initialization)
	}
	for i, input := range inputs {
		setup := test.Initialization[i+1]
		if setup.Op != "KMOVD" || len(setup.Args) != 2 || setup.Args[0].Reg != "AX" || setup.Args[1].Reg != input.Reg {
			t.Fatal("initializer broadened or omitted actual mask inputs", setup, input)
		}
		missing := append([]plan9asm.Instr(nil), test.Initialization[:i+1]...)
		missing = append(missing, test.Initialization[i+2:]...)
		missing = append(missing, test.OriginalInstruction)
		if err := plan9asm.ProbeInstructionSequence(plan9asm.ArchAMD64, arch, missing); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
			t.Fatal("removing an actual input initializer must retain context rejection", err)
		}
	}
}

func TestInitializedContextReprobeDoesNotCreditBrokenLLVM(t *testing.T) {
	for _, mode := range []string{"missing", "wrong-version", "no-object", "nonzero", "wrong-functions"} {
		t.Run(mode, func(t *testing.T) {
			root, pkg, _ := initializedReprobeTestFixture(t)
			llc := filepath.Join(t.TempDir(), "reprobe-llc-fixture")
			if filepath.Ext(os.Args[0]) == ".exe" {
				llc += ".exe"
			}
			if mode != "missing" {
				initializedReprobeTestLink(t, llc)
			}
			if mode == "wrong-functions" {
				t.Setenv("PLAN9ASMSCAN_REPROBE_TEST_WRONG_OBJECT", initializedReprobeUnrelatedObject(t))
			}
			_, stderr, err := initializedReprobeTestRun(t, root, pkg, "amd64", llc, mode, true)
			if err == nil || !strings.Contains(strings.ToLower(string(stderr)), "llvm") || strings.Contains(string(stderr), "flag provided but not defined") {
				t.Fatalf("LLVM %s must fail closed, not report a profile pass: %v\n%s", mode, err, stderr)
			}
			if mode == "wrong-functions" && !strings.Contains(string(stderr), "missing executable function initialized.0") {
				t.Fatalf("valid ELF with unrelated code must fail at the function identity check:\n%s", stderr)
			}
		})
	}
}

func initializedReprobeUnrelatedObject(t *testing.T) string {
	t.Helper()
	llc, err := initializedContextLLC("")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source, object := filepath.Join(dir, "unrelated.ll"), filepath.Join(dir, "unrelated.o")
	if err := os.WriteFile(source, []byte("define void @unrelated() { ret void }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := initializedContextCommand(llc, "-filetype=obj", "-mtriple=x86_64-unknown-linux-gnu", source, "-o", object); err != nil {
		t.Fatal(err)
	}
	return object
}

func TestInitializedContextReprobeVectorRegistersAndImplicitMemory(t *testing.T) {
	const arch = "amd64"
	instructions := []string{
		"ADDSUBPD X2, X2",
		"VADDSUBPD Y2, Y15, Y2",
		"VCVTPS2PH $2, Z21, K4, Y2",
		"MASKMOVOU X0,X2",
	}
	forms := make(map[string]*formStat)
	for i, line := range instructions {
		ins := compactProbeInstructions(t, line)[0]
		err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, arch, ins)
		if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
			t.Fatalf("%s: expected missing inputs in the original probe, got %v", line, err)
		}
		form := plan9asm.DescribeInstruction(plan9asm.ArchAMD64, arch, ins).Form
		forms[form] = &formStat{}
		captureContextSource(forms, plan9asm.ArchAMD64, arch, ins,
			initializedContextSource{File: "vectors.s", Function: "case", Line: i + 1}, err)
	}
	evidence, err := runInitializedContextReprobe(forms, "vector-register", arch, "")
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Status != "pass" || evidence.EligibleCases != 3 || len(evidence.UnregisteredCases) != 1 ||
		evidence.UnregisteredCases[0].OriginalInstruction.Op != "MASKMOVOU" {
		t.Fatalf("register profile did not distinguish the implicit DI memory store: %+v", evidence)
	}
	if len(evidence.ObjectBatches) != 1 || !reflect.DeepEqual(evidence.ObjectBatches[0].CaseIndexes, []int{0, 1, 2}) ||
		evidence.ObjectBatches[0].ObjectSize == 0 {
		t.Fatalf("missing LLVM22 object: %+v", evidence.ObjectBatches)
	}
	for i, test := range evidence.Cases {
		original := compactProbeInstructions(t, instructions[i])[0]
		if !reflect.DeepEqual(test.OriginalInstruction, original) || len(test.Initialization) == 0 ||
			test.IRTextGeneration.Status != "pass" || test.LLVMObjectCompilation.Status != "pass" ||
			test.RuntimeExecution.Status != "not_run" {
			t.Fatalf("wrong evidence for %s: %+v", instructions[i], test)
		}
	}
}

func TestInitializedContextReprobeVectorMemoryUsesDeclaredPointer(t *testing.T) {
	const arch = "amd64"
	instructions := []string{
		"CMPPS (BX), X2, $7",
		"VPMINUD (AX), X14, K7, X7",
		"VCVTPS2PH $126, X7, K5, -7(CX)(DX*8)",
		"VSHUFPS $13, 15(R8)(R14*4), X0, K6, X1",
		"VPSRAW $79, 15(DX)(BX*2), K4, X15",
		"VPSRLQ (BX), Y15, Y2",
		"VPBROADCASTD -7(DI)(R8*8), K1, X26",
		"VMAXPD.BCST (AX), Z2, K1, Z1",
		"VMOVUPS X22, K3, 7(SI)(DI*4)",
		"KMOVB K0, (AX)",
		"KMOVQ 7(AX), K6",
		"VPMADDWD -15(R14)(R15*1), X28, K3, X0",
		"VPACKUSWB (SI), Y8, K2, Y27",
		"VUNPCKHPD (R14), X7, K3, X20",
		"VMOVDDUP 15(R8)(R14*1), K2, X14",
		"VCVTDQ2PD (CX), K2, Z31",
		"VSQRTPD 7(SI)(DI*4), K4, Y0",
		"VPERMB (DI), Z8, K1, Z3",
		"VDBPSADBW $65, 7(AX)(CX*4), X17, K3, X5",
		"VMOVNTDQ Y26, 15(DX)(BX*4)",
		"VEXTRACTF128 $7, Y2, (BX)",
		"VEXTRACTI128 $7, Y2, (BX)",
		"VEXTRACTF32X4 $1, Y5, K3, 7(AX)",
		"VEXTRACTF64X2 $0, Z21, K7, 7(SI)(DI*8)",
		"VEXTRACTI32X4 $0, Y9, K5, 7(SI)(DI*1)",
		"VEXTRACTI64X2 $0, Y31, K2, 15(DX)(BX*4)",
		"VEXTRACTF32X8 $0, Z12, K4, 15(R8)",
		"VEXTRACTF64X4 $0, Z2, K2, 15(R8)(R14*8)",
		"VEXTRACTI32X8 $1, Z23, K4, -15(BX)",
		"VEXTRACTI64X4 $1, Z3, K3, 7(AX)(CX*4)",
		"VEXTRACTPS $7, X2, (BX)",
		"VPEXTRB $79, X26, 7(SI)(DI*1)",
		"VPEXTRW $17, X20, -15(R11)(CX*1)",
		"VPEXTRD $64, X22, -7(DI)",
		"VPEXTRQ $27, X30, -15(R14)(R15*1)",
		"VMOVQ X20, -15(R11)(CX*1)",
		"VMOVSD -7(CX)(DX*1), K3, X11",
		"VMOVSD X0, K2, 15(DX)(BX*1)",
		"VMOVSS -7(CX)(DX*8), K7, X27",
		"VMOVSS X2, (BX)",
		"MOVSS X2, (BX)",
		"MOVSD X2, (BX)",
		"VPMINUD 99(R15)(R15*4), Z9, K5, Z0",
		"VSHUFPS $67, (SP), Z9, K7, Z9",
		"MASKMOVOU X0,X2",
		"ADDSUBPD X2,X3",
	}
	forms := make(map[string]*formStat)
	for i, line := range instructions {
		ins := compactProbeInstructions(t, line)[0]
		err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, arch, ins)
		if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
			t.Fatalf("%s: expected missing inputs in the original probe, got %v", line, err)
		}
		form := plan9asm.DescribeInstruction(plan9asm.ArchAMD64, arch, ins).Form
		forms[form] = &formStat{}
		captureContextSource(forms, plan9asm.ArchAMD64, arch, ins,
			initializedContextSource{File: "memory.s", Function: "case", Line: i + 1}, err)
	}
	evidence, err := runInitializedContextReprobe(forms, "vector-memory", arch, "")
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Status != "pass" || evidence.EligibleCases != 42 || len(evidence.UnregisteredCases) != 4 {
		t.Fatalf("unexpected fixed-span selection: status=%s eligible=%d unregistered=%d",
			evidence.Status, evidence.EligibleCases, len(evidence.UnregisteredCases))
	}
	for i, row := range evidence.Cases {
		original := compactProbeInstructions(t, instructions[i])[0]
		if !row.MemoryPointerArgument || !reflect.DeepEqual(row.OriginalInstruction, original) ||
			row.IRTextGeneration.Status != "pass" || row.LLVMObjectCompilation.Status != "pass" ||
			row.RuntimeExecution.Status != "not_run" {
			t.Fatalf("wrong memory evidence for %s: %+v", instructions[i], row)
		}
	}
}

func TestInitializedContextReprobeVectorMemory386(t *testing.T) {
	const arch = "386"
	ins := compactProbeInstructions(t, "CMPPS 16(BP)(CX*2), X2, $7")[0]
	err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, arch, ins)
	if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatalf("expected the uninitialized address to require context: %v", err)
	}
	form := plan9asm.DescribeInstruction(plan9asm.ArchAMD64, arch, ins).Form
	forms := map[string]*formStat{form: {}}
	captureContextSource(forms, plan9asm.ArchAMD64, arch, ins,
		initializedContextSource{File: "memory_386.s", Function: "case", Line: 1}, err)
	evidence, err := runInitializedContextReprobe(forms, "vector-memory", arch, "")
	if err != nil || evidence.Status != "pass" || evidence.EligibleCases != 1 {
		t.Fatalf("initialized 386 vector memory did not compile: %v %+v", err, evidence)
	}
	row := evidence.Cases[0]
	fn, sig := row.function("initialized.0", arch)
	if fn.ArgSize != 4 || !reflect.DeepEqual(sig.Args, []plan9asm.LLVMType{plan9asm.Ptr}) ||
		row.Initialization[len(row.Initialization)-1].Op != "MOVL" ||
		row.LLVMObjectCompilation.Status != "pass" || row.RuntimeExecution.Status != "not_run" {
		t.Fatalf("wrong 386 memory declaration or object evidence: %+v %+v", sig, row)
	}
}

func TestInitializedContextReprobeVectorNumericMemory(t *testing.T) {
	for _, mode := range []struct {
		arch         string
		argSize      int64
		argType      plan9asm.LLVMType
		instructions []string
	}{
		{"amd64", 8, plan9asm.I64, []string{
			"VPMINUD 99(R15)(R15*4), Z9, K5, Z0",
			"VEXPANDPS 99(R15)(R15*2), K6, Z7",
			"VCOMPRESSPS Z17, K1, 99(R15)(R15*4)",
			"VEXTRACTF32X4 $3, Z14, K7, 99(R15)(R15*1)",
			"VMOVDQU32 99(R15)(R15*2), K3, Z20",
			"VMOVDQU32 Z20, K3, 99(R15)(R15*2)",
			"VPMOVQD Z2, K4, 99(R15)(R15*1)",
			"VPMOVSDB Y26, K7, 99(R15)(R15*1)",
			"VPMOVUSWB X6, K1, 99(R15)(R15*2)",
		}},
		{"386", 4, plan9asm.I32, []string{
			"VPADDQ 8(BX)(BX*2), Y2, Y3",
			"VMOVUPS Y2, 8(BX)(BX*2)",
			"VPEXTRW $7, X2, 8(BX)(BX*2)",
			"VMOVQ X2, 8(BX)(BX*2)",
		}},
	} {
		t.Run(mode.arch, func(t *testing.T) {
			forms := make(map[string]*formStat)
			for i, source := range mode.instructions {
				ins := compactProbeInstructions(t, source)[0]
				err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, mode.arch, ins)
				if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
					t.Fatalf("%s: original form requires inputs, got %v", source, err)
				}
				form := plan9asm.DescribeInstruction(plan9asm.ArchAMD64, mode.arch, ins).Form
				forms[form] = &formStat{}
				captureContextSource(forms, plan9asm.ArchAMD64, mode.arch, ins,
					initializedContextSource{File: "alias.s", Function: "case", Line: i + 1}, err)
			}
			evidence, err := runInitializedContextReprobe(forms, "vector-numeric-memory", mode.arch, "")
			if err != nil {
				t.Fatal(err)
			}
			if evidence.Status != "pass" || evidence.EligibleCases != len(mode.instructions) {
				t.Fatalf("typed numerical address probe lost rows: %s, %d/%d",
					evidence.Status, evidence.EligibleCases, len(mode.instructions))
			}
			for i, row := range evidence.Cases {
				fn, sig := row.function("aliased.memory", mode.arch)
				original := compactProbeInstructions(t, mode.instructions[i])[0]
				if !row.NumericAddressArgument || row.MemoryPointerArgument || fn.ArgSize != mode.argSize ||
					!reflect.DeepEqual(sig.Args, []plan9asm.LLVMType{mode.argType}) ||
					!reflect.DeepEqual(row.OriginalInstruction, original) ||
					row.LLVMObjectCompilation.Status != "pass" || row.RuntimeExecution.Status != "not_run" {
					t.Fatalf("wrong numerical address or object evidence: %+v, %+v", sig, row)
				}
				row.NumericAddressArgument, row.MemoryPointerArgument = false, true
				if err := row.probe(mode.arch); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
					t.Fatalf("opaque base was reused as a numerical index: %s: %v", original.Raw, err)
				}
			}
		})
	}
}

func TestInitializedContextReprobeVectorMemoryCompactExpand(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			forms := make(map[string]*formStat)
			eligible := make(map[int]plan9asm.Instr)
			line := 0
			add := func(source string, ordinary bool) {
				t.Helper()
				line++
				ins := compactProbeInstructions(t, source)[0]
				err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, arch, ins)
				if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
					t.Fatalf("%s: expected missing inputs in the original probe, got %v", source, err)
				}
				form := plan9asm.DescribeInstruction(plan9asm.ArchAMD64, arch, ins).Form
				if forms[form] == nil {
					forms[form] = &formStat{}
				}
				captureContextSource(forms, plan9asm.ArchAMD64, arch, ins,
					initializedContextSource{File: "compact.s", Function: "case", Line: line}, err)
				if ordinary {
					eligible[line] = ins
				}
			}

			// Go's compact/expand tables pair an unmasked and masked memory
			// row for every vector width. Only expand allows a zeroing memory
			// form with an ordinary continuation.
			for _, bank := range []string{"X", "Y", "Z"} {
				reg := bank + "2"
				for _, suffix := range []string{"PS", "PD", "B", "W", "D", "Q"} {
					prefix := "VP"
					if suffix == "PS" || suffix == "PD" {
						prefix = "V"
					}
					compress, expand := prefix+"COMPRESS"+suffix, prefix+"EXPAND"+suffix
					add(compress+" "+reg+", (BX)", true)
					add(compress+" "+reg+", K7, 7(BX)(SI*2)", true)
					terminal := compactProbeInstructions(t, compress+".Z "+reg+", K7, (BX)")[0]
					if seq, known, err := plan9asm.InitializedVectorMemoryProbeSequence(arch, terminal); known || err != nil || seq != nil {
						t.Fatalf("terminal encoding acquired a memory continuation: %s", terminal.Raw)
					}
					add(expand+" (BX), "+reg, true)
					add(expand+" 7(BX)(SI*2), K7, "+reg, true)
					add(expand+".Z (BX), K7, "+reg, true)
				}
			}
			add("VPEXPANDQ 16(SP), K7, Z2", false)
			add("VPCOMPRESSQ Z2, K7, 99(SI)(SI*4)", false)

			evidence, err := runInitializedContextReprobe(forms, "vector-memory", arch, "")
			if err != nil {
				t.Fatal(err)
			}
			if evidence.Status != "pass" || evidence.EligibleCases != 90 ||
				len(evidence.UnregisteredCases) != 2 {
				t.Fatalf("unexpected compact/expand selection: status=%s eligible=%d unregistered=%d",
					evidence.Status, evidence.EligibleCases, len(evidence.UnregisteredCases))
			}
			for _, row := range evidence.Cases {
				original, found := eligible[row.Source.Line]
				if !found || !row.MemoryPointerArgument || !reflect.DeepEqual(row.OriginalInstruction, original) ||
					row.IRTextGeneration.Status != "pass" || row.LLVMObjectCompilation.Status != "pass" ||
					row.RuntimeExecution.Status != "not_run" {
					t.Fatalf("wrong compact/expand evidence: %+v", row)
				}
				delete(eligible, row.Source.Line)
			}
			if len(eligible) != 0 {
				t.Fatalf("missing %d original compact/expand occurrences", len(eligible))
			}
		})
	}
}

func TestInitializedContextReprobeVectorMemoryVSIB(t *testing.T) {
	for _, row := range []struct {
		arch, line string
		eligible   bool
		activeVEX  bool
	}{
		{"amd64", "VGATHERDPS X2, (R13)(X7*2), X1", true, true},
		{"amd64", "VGATHERDPS 360(R15)(X30*2), K6, X20", true, false},
		{"amd64", "VPSCATTERDD X2, K5, (AX)(X21*2)", true, false},
		{"amd64", "VGATHERDPS X2, (BP)(X7*2), X1", true, true},
		{"amd64", "VGATHERDPD (BP)(X10*2), K3, X6", true, false},
		{"amd64", "VPSCATTERDD Y22, K7, (BP)(Y4*2)", true, false},
		{"amd64", "VGATHERDPS (SP)(Z4*2), K2, Z20", false, false},
		{"amd64", "VGATHERDPS X3, 8(X4*1), X6", true, true},
		{"amd64", "VPGATHERQQ Y0, 0(Y1*1), Y2", true, true},
		{"amd64", "VPGATHERDD 16(Z4*2), K1, Z6", true, false},
		{"amd64", "VPSCATTERQQ X6, K1, 8(X4*8)", true, false},
		{"386", "VPGATHERDD X2, (BP)(X7*2), X1", true, true},
		{"386", "VPGATHERDD X3, 8(X4*1), X6", true, true},
	} {
		t.Run(row.arch+"/"+row.line, func(t *testing.T) {
			ins := compactProbeInstructions(t, row.line)[0]
			err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, row.arch, ins)
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("expected uninitialized VSIB inputs to require context: %v", err)
			}
			form := plan9asm.DescribeInstruction(plan9asm.ArchAMD64, row.arch, ins).Form
			forms := map[string]*formStat{form: {}}
			captureContextSource(forms, plan9asm.ArchAMD64, row.arch, ins,
				initializedContextSource{File: "vsib.s", Function: "case", Line: 1}, err)
			evidence, err := runInitializedContextReprobe(forms, "vector-memory", row.arch, "")
			if err != nil {
				t.Fatal(err)
			}
			if !row.eligible {
				if evidence.Status != "not_run" || evidence.EligibleCases != 0 || len(evidence.UnregisteredCases) != 1 {
					t.Fatalf("unbound stack acquired evidence: %+v", evidence)
				}
				return
			}
			if evidence.Status != "pass" || evidence.EligibleCases != 1 {
				t.Fatalf("missing VSIB object evidence: %s eligible=%d", evidence.Status, evidence.EligibleCases)
			}
			test := evidence.Cases[0]
			var indexOnly plan9asm.Reg
			var frameSize int64
			for _, arg := range ins.Args {
				if arg.Kind == plan9asm.OpMem && arg.Mem.Base == "" {
					indexOnly = arg.Mem.Index
				}
				if row.arch == "amd64" && arg.Kind == plan9asm.OpMem && arg.Mem.Base == "BP" {
					frameSize = 8
				}
			}
			activeVEX, loadedIndex := false, false
			for _, init := range test.Initialization {
				if init.Op == "VPCMPEQD" {
					activeVEX = true
				}
				if init.Op == "VMOVUPS" && len(init.Args) == 2 &&
					init.Args[0].Kind == plan9asm.OpMem && init.Args[0].Mem.Base == "AX" &&
					init.Args[1].Kind == plan9asm.OpReg && init.Args[1].Reg == indexOnly {
					loadedIndex = true
				}
			}
			if !test.MemoryPointerArgument || test.FrameSize != frameSize || activeVEX != row.activeVEX ||
				loadedIndex != (indexOnly != "") ||
				!reflect.DeepEqual(test.OriginalInstruction, ins) ||
				test.LLVMObjectCompilation.Status != "pass" || test.RuntimeExecution.Status != "not_run" {
				t.Fatalf("incorrect VSIB input or evidence: %+v", test)
			}
		})
	}
}

func TestInitializedContextReprobeScalarMemory(t *testing.T) {
	for _, mode := range []struct{ arch, size string }{{"amd64", "Q"}, {"386", "L"}} {
		t.Run(mode.arch, func(t *testing.T) {
			rows := []string{
				"ADD%[1]s (BX),CX",
				"ADC%[1]s DX, (BX)",
				"CMP%[1]s (BX),CX",
				"SAR%[1]s CX, (BX)",
				"CMOV%[1]sEQ (BX),CX",
				"MUL%[1]s (BX)",
				"IDIV%[1]s 4(BX)(DX*2)",
			}
			instructions := make([]string, 0, len(rows)+3)
			for _, row := range rows {
				instructions = append(instructions, fmt.Sprintf(row, mode.size))
			}
			instructions = append(instructions, "SETCC 2(BX)(AX*1)")
			// Scalar float conversions with memory sources have no SIMD
			// operand. The GP result may overwrite the base or index after
			// the source read; its old bits are not a numerical input.
			for _, precision := range []string{"SS", "SD"} {
				for _, operation := range []string{"CVT", "CVTT"} {
					stem := operation + precision + "2"
					names := []string{"V" + stem + "SI", "V" + stem + "SIQ",
						"V" + stem + "USIL", "V" + stem + "USIQ", stem + "SL"}
					if mode.arch == "amd64" {
						names = append(names, stem+"SQ")
					}
					for _, name := range names {
						instructions = append(instructions, name+" 5(BX),BX", name+" 7(BX)(CX*2),CX")
					}
				}
			}
			wantEligible := 56
			if mode.arch == "386" {
				wantEligible = 48
			}
			instructions = append(instructions, "ADC"+mode.size+" BX, (BX)", "PUSH"+mode.size+" (BX)")
			forms := make(map[string]*formStat)
			for i, line := range instructions {
				ins := compactProbeInstructions(t, line)[0]
				form := plan9asm.DescribeInstruction(plan9asm.ArchAMD64, mode.arch, ins).Form
				if forms[form] == nil {
					forms[form] = &formStat{}
				}
				err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, mode.arch, ins)
				if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
					t.Fatalf("%s did not require context: %v", line, err)
				}
				captureContextSource(forms, plan9asm.ArchAMD64, mode.arch, ins,
					initializedContextSource{File: "scalar.s", Function: "case", Line: i + 1}, err)
			}
			evidence, err := runInitializedContextReprobe(forms, "scalar-memory", mode.arch, "")
			if err != nil {
				t.Fatal(err)
			}
			if evidence.Status != "pass" || evidence.EligibleCases != wantEligible || len(evidence.UnregisteredCases) != 2 {
				t.Fatalf("unexpected scalar-memory partition: %s, eligible=%d, unregistered=%d",
					evidence.Status, evidence.EligibleCases, len(evidence.UnregisteredCases))
			}
			for i, row := range evidence.Cases {
				if !row.MemoryPointerArgument || row.OriginalInstruction.Raw != instructions[i] ||
					row.IRTextGeneration.Status != "pass" || row.LLVMObjectCompilation.Status != "pass" ||
					row.RuntimeExecution.Status != "not_run" {
					t.Fatalf("incorrect scalar-memory evidence: %+v", row)
				}
			}
		})
	}
}

func TestInitializedContextReprobeOfficial386Forms(t *testing.T) {
	const arch = "386"
	_, forms, parseErrors, _, err := scanGoAssemblerTestdataWithContexts(runtime.GOROOT(), plan9asm.ArchAMD64, arch, true)
	if err != nil || len(parseErrors) != 0 {
		t.Fatalf("official 386 assembler corpus: %v, parse errors: %v", err, parseErrors)
	}
	for _, test := range []struct {
		profile string
		file    string
		want    []string
	}{
		{"vector-register", "386.s", []string{"CMPPD X0, X1, 4"}},
		{"scalar-register", "386.s", []string{"SETCC AX", "DIVB AX", "IMULL AX"}},
		{"scalar-numeric-memory", "386enc.s", []string{"ADDL 2147483648(AX), AX", "ADDL -2147483648(AX), AX"}},
		{"mmx", "386enc.s", []string{
			"MOVQ (AX), M0", "MOVQ M0, 8(SP)", "MOVQ 8(SP), M0",
			"MOVQ M0, (AX)", "MOVQ M0, (BX)",
		}},
	} {
		t.Run(test.profile, func(t *testing.T) {
			evidence, err := runInitializedContextReprobe(forms, test.profile, arch, "")
			if err != nil {
				t.Fatal(err)
			}
			if evidence.Status != "pass" || len(evidence.ObjectBatches) == 0 {
				t.Fatalf("official 386 forms lack LLVM object evidence: %s", evidence.Status)
			}
			compiled := make(map[string]bool)
			for _, row := range evidence.Cases {
				if row.OriginalStatus != "context-required" || row.Source.File == "" ||
					row.LLVMObjectCompilation.Status != "pass" || row.RuntimeExecution.Status != "not_run" {
					t.Fatalf("wrong evidence for official source occurrence: %+v", row)
				}
				if row.Source.File == test.file {
					compiled[strings.Join(strings.Fields(row.OriginalInstruction.Raw), " ")] = true
				}
			}
			for _, instruction := range test.want {
				if !compiled[instruction] {
					t.Errorf("missing initialized LLVM object for original %q", instruction)
				}
			}
		})
	}
}

func TestInitializedContextReprobeMMXNativeRegions(t *testing.T) {
	const arch = "amd64"
	rows := []struct {
		instruction string
		pointer     bool
	}{
		{"PSLLW $4,M3", false},
		{"PSLLW M3,M2", false},
		{"PSHUFW $27,M2,M1", false},
		{"PMOVMSKB M3,DI", false},
		{"MOVQ M1,M2", false},
		{"MOVDQ2Q X3,M2", false},
		{"MOVQ (CX)(AX*4),M1", true},
		{"MOVNTQ M1,(AX)", true},
		{"MASKMOVQ M1,M2", true},
	}
	forms := make(map[string]*formStat)
	for i, row := range rows {
		ins := compactProbeInstructions(t, row.instruction)[0]
		probeErr := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, arch, ins)
		if !errors.Is(probeErr, plan9asm.ErrProbeNeedsContext) {
			t.Fatalf("isolated %s: %v", row.instruction, probeErr)
		}
		form := plan9asm.DescribeInstruction(plan9asm.ArchAMD64, arch, ins).Form
		if forms[form] == nil {
			forms[form] = &formStat{}
		}
		captureContextSource(forms, plan9asm.ArchAMD64, arch, ins,
			initializedContextSource{File: "mmx.s", Function: "probe", Line: i + 1}, probeErr)
	}
	evidence, err := runInitializedContextReprobe(forms, "mmx", arch, "")
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Status != "pass" || len(evidence.Cases) != len(rows) || len(evidence.ObjectBatches) != 1 {
		t.Fatalf("incorrect MMX evidence: status %s, cases %d, batches %d",
			evidence.Status, len(evidence.Cases), len(evidence.ObjectBatches))
	}
	for i, expected := range rows {
		c := evidence.Cases[i]
		if c.OriginalInstruction.Raw != expected.instruction || c.MemoryPointerArgument != expected.pointer ||
			c.FrameSize != 0 || len(c.Cleanup) != 1 || c.Cleanup[0].Op != "EMMS" ||
			c.IRTextGeneration.Status != "pass" || c.LLVMObjectCompilation.Status != "pass" ||
			c.RuntimeExecution.Status != "not_run" {
			t.Errorf("incorrect evidence for %s: %+v", expected.instruction, c)
		}
	}
	for _, instruction := range []string{
		"MOVQ M1,8(SP)", "MOVQ table(SB),M1", "MOVQ (AX)(AX*2),M1", "PSLLW X1,X2",
	} {
		ins := compactProbeInstructions(t, instruction)[0]
		if _, known := plan9asm.BuildInitializedMMXProbe(arch, ins); known {
			t.Errorf("%s acquired an unrelated or unproved native memory role", instruction)
		}
	}
}

func TestInitializedContextReprobeScalarNumericMemory(t *testing.T) {
	for _, mode := range []struct {
		arch   string
		widths string
	}{{"386", "BWL"}, {"amd64", "BWLQ"}} {
		t.Run(mode.arch, func(t *testing.T) {
			forms := make(map[string]*formStat)
			line := 0
			add := func(raw string) {
				ins := compactProbeInstructions(t, raw)[0]
				form := plan9asm.DescribeInstruction(plan9asm.ArchAMD64, mode.arch, ins).Form
				if forms[form] == nil {
					forms[form] = &formStat{}
				}
				line++
				captureContextSource(forms, plan9asm.ArchAMD64, mode.arch, ins,
					initializedContextSource{File: "arithmetic.s", Function: "probe", Line: line}, plan9asm.ErrProbeNeedsContext)
			}
			for _, stem := range []string{"ADD", "SUB", "ADC", "SBB", "AND", "OR", "XOR"} {
				for _, width := range mode.widths {
					destination := "AX"
					if width == 'B' {
						destination = "AH"
					}
					for _, address := range []string{"3(AX)", "-5(AX)(SI*2)", "7(BX)(BX*4)"} {
						add(stem + string(width) + " " + address + "," + destination)
					}
				}
			}
			want := line
			for _, raw := range []string{"ADDL (BX),AX", "ADDL AX,(AX)", "PUSHL (AX)", "CMPB (AX),AL", "ADDL 4(SP),AX"} {
				add(raw)
			}
			evidence, err := runInitializedContextReprobe(forms, "scalar-numeric-memory", mode.arch, "")
			if err != nil || evidence.Status != "pass" || evidence.EligibleCases != want ||
				len(evidence.UnregisteredCases) != line-want {
				t.Fatalf("scalar numeric profile: %d/%d selected, status=%s, err=%v",
					evidence.EligibleCases, want, evidence.Status, err)
			}
			for _, row := range evidence.Cases {
				if !row.NumericAddressArgument || row.MemoryPointerArgument ||
					row.LLVMObjectCompilation.Status != "pass" || row.RuntimeExecution.Status != "not_run" {
					t.Fatalf("wrong scalar numeric evidence: %+v", row)
				}
			}
		})
	}
}

func TestInitializedContextReprobeScalarReadAccumulatorRoles(t *testing.T) {
	for _, mode := range []struct{ arch, widths string }{{"386", "WL"}, {"amd64", "WLQ"}} {
		t.Run(mode.arch, func(t *testing.T) {
			type source struct {
				operands, profile string
			}
			rows := []source{
				{"DX, CX", "scalar-register"},
				{"3(BX), DX", "scalar-memory"},
				{"-7(BX)(CX*2), DX", "scalar-memory"},
				{"3(DX), DX", "scalar-numeric-memory"},
				{"7(BX)(BX*2), DX", "scalar-numeric-memory"},
			}
			forms := make(map[string]*formStat)
			want := make(map[string]map[string]bool)
			line := 0
			for _, stem := range []string{"BSF", "BSR", "CRC32"} {
				widths := mode.widths
				if stem == "CRC32" {
					widths = "B" + widths
				}
				for _, width := range widths {
					for _, row := range rows {
						raw := stem + string(width) + " " + row.operands
						ins := compactProbeInstructions(t, raw)[0]
						err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, mode.arch, ins)
						if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
							t.Fatalf("%s: expected a missing input before initialization, got %v", raw, err)
						}
						key := plan9asm.DescribeInstruction(plan9asm.ArchAMD64, mode.arch, ins).Form
						if forms[key] == nil {
							forms[key] = &formStat{}
						}
						line++
						captureContextSource(forms, plan9asm.ArchAMD64, mode.arch, ins,
							initializedContextSource{File: "accumulator.s", Function: "probe", Line: line}, err)
						if want[row.profile] == nil {
							want[row.profile] = make(map[string]bool)
						}
						want[row.profile][raw] = true
					}
				}
			}
			for _, profile := range []string{"scalar-register", "scalar-memory", "scalar-numeric-memory"} {
				t.Run(profile, func(t *testing.T) {
					evidence, err := runInitializedContextReprobe(forms, profile, mode.arch, "")
					if err != nil || evidence.Status != "pass" || evidence.EligibleCases != len(want[profile]) ||
						len(evidence.UnregisteredCases) != line-len(want[profile]) {
						t.Fatalf("selected %d/%d rows, status=%s, err=%v",
							evidence.EligibleCases, len(want[profile]), evidence.Status, err)
					}
					for _, row := range evidence.Cases {
						if !want[profile][row.OriginalInstruction.Raw] ||
							row.MemoryPointerArgument != (profile == "scalar-memory") ||
							row.NumericAddressArgument != (profile == "scalar-numeric-memory") ||
							row.LLVMObjectCompilation.Status != "pass" || row.RuntimeExecution.Status != "not_run" {
							t.Fatalf("wrong source role or object receipt: %+v", row)
						}
					}
				})
			}
		})
	}
}

func TestInitializedContextReprobeScalarMoveFamily(t *testing.T) {
	for _, mode := range []struct {
		arch   string
		widths []string
	}{
		{"386", []string{"B", "W", "L"}},
		{"amd64", []string{"B", "W", "L", "Q"}},
	} {
		t.Run(mode.arch, func(t *testing.T) {
			var instructions []string
			for _, width := range mode.widths {
				for _, address := range []string{"3(BX)", "-5(BX)(SI*2)"} {
					for _, arguments := range []string{
						address + ",DX", address + ",BX", "DX," + address, "$113," + address,
					} {
						instructions = append(instructions, "MOV"+width+" "+arguments)
					}
				}
			}
			if mode.arch == "386" {
				instructions = append(instructions, "MOVL 2147483648(AX), AX")
			}
			forms := make(map[string]*formStat)
			for index, line := range instructions {
				ins := compactProbeInstructions(t, line)[0]
				err := plan9asm.ProbeInstruction(plan9asm.ArchAMD64, mode.arch, ins)
				if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
					t.Fatalf("%s did not require initialized inputs: %v", line, err)
				}
				form := plan9asm.DescribeInstruction(plan9asm.ArchAMD64, mode.arch, ins).Form
				if forms[form] == nil {
					forms[form] = &formStat{}
				}
				captureContextSource(forms, plan9asm.ArchAMD64, mode.arch, ins,
					initializedContextSource{File: "scalar-move.s", Function: "probe", Line: index + 1}, err)
			}
			evidence, err := runInitializedContextReprobe(forms, "scalar-memory", mode.arch, "")
			if err != nil || evidence.Status != "pass" || evidence.EligibleCases != len(instructions) ||
				len(evidence.UnregisteredCases) != 0 {
				t.Fatalf("scalar moves: %d/%d selected, status=%s, err=%v",
					evidence.EligibleCases, len(instructions), evidence.Status, err)
			}
			for index, row := range evidence.Cases {
				if !row.MemoryPointerArgument || row.OriginalInstruction.Raw != instructions[index] ||
					row.LLVMObjectCompilation.Status != "pass" || row.RuntimeExecution.Status != "not_run" {
					t.Fatalf("incorrect scalar move evidence: %+v", row)
				}
			}
		})
	}
}
