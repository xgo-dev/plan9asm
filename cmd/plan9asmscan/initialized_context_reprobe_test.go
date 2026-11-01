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
	for _, mode := range []string{"missing", "wrong-version", "no-object", "nonzero"} {
		t.Run(mode, func(t *testing.T) {
			root, pkg, _ := initializedReprobeTestFixture(t)
			llc := filepath.Join(t.TempDir(), "reprobe-llc-fixture")
			if filepath.Ext(os.Args[0]) == ".exe" {
				llc += ".exe"
			}
			if mode != "missing" {
				initializedReprobeTestLink(t, llc)
			}
			_, stderr, err := initializedReprobeTestRun(t, root, pkg, "amd64", llc, mode, true)
			if err == nil || !strings.Contains(strings.ToLower(string(stderr)), "llvm") || strings.Contains(string(stderr), "flag provided but not defined") {
				t.Fatalf("LLVM %s must fail closed, not report a profile pass: %v\n%s", mode, err, stderr)
			}
		})
	}
}
