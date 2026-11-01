package plan9asm

import (
	"strings"
	"testing"
)

// Reuse only the independent GP/FLAGS/MXCSR/canary driver. Replace every tested
// instruction with a disjoint part of the complete literal-NOP witness set.
// Noncanonical/null effective addresses must not fault or change native state.
func x86RawNOPRuntimeFixture(bits int) (declarations, assembly, driver, reference string) {
	declarations, assembly, driver, reference = x86OrderingHintRuntimeFixture(bits)
	var batches [4]strings.Builder
	for i, code := range x86RawNOPWitnesses(bits) {
		batches[i%len(batches)].WriteString(x86RawDisplacementDirectives(code))
	}
	for i, op := range []string{"LFENCE", "MFENCE", "SFENCE", "PAUSE"} {
		assembly = strings.ReplaceAll(assembly, "\n"+op+"\n", "\n"+batches[i].String())
	}
	return
}

// Portable LLVM execution is distinct from the required original-Go native
// roots. Rosetta rejects some valid register NOPs (for example 0F 1F C2), so
// it cannot certify this family's original machine execution.
func TestX86RawNOPLLVMRuntime(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	declarations, assembly, _, reference := x86RawNOPRuntimeFixture(64)
	ir := x86NarrowOracleIR(t, assembly, declarations, execution.triple)
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			output := execution.compileAndRunLLVM(t, "nop", ir, reference, level)
			if string(output) != "ordering observations 256\n" {
				t.Fatalf("LLVM NOP GP/FLAGS/MXCSR/canary oracle: %q", output)
			}
		})
	}
}

func TestX86RawNOPOriginal386StaticELFCompileOnly(t *testing.T) {
	declarations, assembly, driver, _ := x86RawNOPRuntimeFixture(32)
	original := x86OrderingHintBuildOriginal(t, t.TempDir(), "linux", "386", declarations, assembly, driver)
	sealed, err := x87IA32StaticExecutable(original)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual original Go IA32 NOP ELF bytes=%d SHA256=%x; compile only", sealed.size, sealed.hash)
}
