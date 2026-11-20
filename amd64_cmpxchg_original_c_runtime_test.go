package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

func x86CMPXCHGOriginalCNumerical(t *testing.T, execution x86FloatCompareExecution) {
	t.Helper()
	reference := x86CMPXCHGOriginalCSource()
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			output := x86CMPXCHGCompileOriginalC(t, execution, reference, level)
			if string(output) != "actual C opcode CMPXCHG numerical observations 576 failures 0\n" {
				t.Fatalf("actual original C opcode vs independent math: %s", output)
			}
			t.Log(string(output))
		})
	}
}

func x86CMPXCHGOriginalCSource() string {
	_, _, names := x86CMPXCHGNumericalFixture()
	var definitions strings.Builder
	for index, op := range []string{"cmpxchgb %bl,", "cmpxchgw %bx,", "cmpxchgl %ebx,", "cmpxchgq %rbx,", "cmpxchg8b ", "cmpxchg16b "} {
		for _, locked := range []bool{false, true} {
			name := fmt.Sprintf("numeric_%d_%t", index, locked)
			prefix := ""
			if locked {
				prefix = "lock; "
			}
			fmt.Fprintf(&definitions, `static void %s(uint64_t *out, unsigned char *p,
        uint64_t expected_low, uint64_t expected_high, uint64_t desired_low,
        uint64_t desired_high, uint64_t seed) {
    __asm__ volatile(
        "pushq %%[seed]; popfq; %s%s(%%%%rsi);"
`, name, prefix, strings.ReplaceAll(op, "%", "%%"))
			definitions.WriteString(`        "movq %%rax,0(%%rdi); movq %%rdx,8(%%rdi);"
        "movq %%rbx,16(%%rdi); movq %%rcx,24(%%rdi);"
        "pushfq; popq %%r9; movq %%r9,32(%%rdi);"
        "lahf; movzbl %%ah,%%ebx; movq %%rbx,40(%%rdi);"
        "stmxcsr 48(%%rdi);"
        : "+a"(expected_low), "+d"(expected_high), "+b"(desired_low), "+c"(desired_high)
        : "D"(out), "S"(p), [seed] "r"(seed)
        : "r9", "cc", "memory");
}
`)
		}
	}
	reference := strings.Replace(x86CMPXCHGCNumerical, "KERNEL_PROTOTYPES", definitions.String(), 1)
	reference = strings.Replace(reference, "KERNEL_NAMES", names, 1)
	reference = strings.ReplaceAll(reference, "LLVM failure", "actual C opcode failure")
	reference = strings.ReplaceAll(reference, "LLVM kernel", "actual C opcode kernel")
	reference = strings.ReplaceAll(reference, "LLVM CMPXCHG numerical", "actual C opcode CMPXCHG numerical")
	return reference
}

func x86CMPXCHGCompileOriginalC(t *testing.T, execution x86FloatCompareExecution, sourceText, level string) []byte {
	t.Helper()
	directory := t.TempDir()
	source := filepath.Join(directory, "original.c")
	executable := filepath.Join(directory, gotoolchain.HostExecutable("original"))
	if err := os.WriteFile(source, []byte(sourceText), 0600); err != nil {
		t.Fatal(err)
	}
	command := append([]string(nil), execution.compiler...)
	command = append(command, level, source, "-o", executable)
	x86FloatCompareCaptureCommand(t, exec.Command(command[0], command[1:]...))
	return execution.run(t, executable)
}
