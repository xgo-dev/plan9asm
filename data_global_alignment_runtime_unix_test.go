//go:build unix

package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixDataGlobalAlignmentOriginalGoAndLLVM(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	goos := "linux"
	if strings.Contains(execution.triple, "apple") {
		goos = "darwin"
	}
	original := dataGlobalAlignmentGoBuild(t, "amd64", goos, 32)
	output := execution.run(t, original)
	if strings.TrimSpace(string(output)) != "actual Go assembly alignment and bytes PASS" {
		t.Fatal("original Go program did not execute its alignment/byte checks", string(output))
	}
	var consumers, declarations, checks strings.Builder
	ordinal := 0
	for _, row := range dataGlobalAlignmentSizes {
		for _, role := range []string{"rw", "ro", "local"} {
			name := fmt.Sprintf("asm_align_%s_n%d", role, row.size)
			fmt.Fprintf(&consumers, "define ptr @address%d() {\n ret ptr @%s\n}\n", ordinal, name)
			fmt.Fprintf(&declarations, "extern uint8_t *address%d(void);\n", ordinal)
			fmt.Fprintf(&checks, `{
    uint8_t *address=address%d();
    if (!address || (uintptr_t)address%%%d) {
        fprintf(stderr,"%s address mod32=%%lu\n",(unsigned long)((uintptr_t)address%%32));
        return 1;
    }
    for(int i=0;i<%d;i++) if(address[i]!=(i?0:0xa5)) return 2;
}
`, ordinal, row.alignment, name, row.size)
			ordinal++
		}
	}
	main := "#include <stdint.h>\n#include <stdio.h>\n" + declarations.String() + "int main(void) {\n" + checks.String() + "return 0;\n}\n"
	for _, route := range []string{"text", "direct"} {
		ir := dataGlobalAlignmentModule(t, ArchAMD64, execution.triple, route) + consumers.String()
		for _, level := range []string{"-O0", "-O2"} {
			t.Run(route+"/"+level, func(t *testing.T) {
				execution.compileAndRunLLVM(t, "data-global-alignment", ir, main, level)
			})
		}
	}
	t.Logf("75 original Go globals and both LLVM emitters: actual pointer residues, first bytes and complete zero tails; transport=%s/%s (non-native execution is diagnostic)", runtime.GOOS, runtime.GOARCH)
}
