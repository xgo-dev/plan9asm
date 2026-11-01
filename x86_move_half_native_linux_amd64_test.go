package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86MoveHalfOriginalGoFlagsDFAliases(t *testing.T) {
	x87IA32RequireNativeHost(t)
	execution := x86FloatCompareExecutionTools(t)
	directory := t.TempDir()
	preflight, executable := filepath.Join(directory, "native-half-cpu.c"), filepath.Join(directory, "native-half-cpu")
	const cpu = `#include <stdint.h>
#include <stdio.h>
int main(void) {
  __builtin_cpu_init();
  int enabled=!!__builtin_cpu_supports("avx512f");
  printf("half native CPUID/XCR0 AVX512F=%d\n",enabled);
  if(!enabled) return 1;
  uint64_t data[8]={0};
  __asm__ volatile(".byte 0x62,0xf1,0xfe,0x48,0x6f,0x00" :: "a"(data) : "zmm0","memory");
  return 0;
}
`
	if err := os.WriteFile(preflight, []byte(cpu), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, preflight, executable)
	if output := execution.run(t, executable); string(output) != "half native CPUID/XCR0 AVX512F=1\n" {
		t.Fatal("missing actual AVX512F/XCR0 and native Go transport opcode preflight", string(output))
	}
	t.Log("half native CPUID/XCR0 AVX512F=1; original EVEX transport opcode executed")
	source, declarations, prototypes, metadata, goRows := x86MoveHalfValueProgram()
	x86LEAActualTargetGoObject(t, "amd64", execution.triple, source)
	ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", execution.triple, "Go")
	if err != nil {
		t.Fatal("complete original initialized native x86 half-move source rejected", err)
	}
	driver := fmt.Sprintf(x86MoveHalfWholeBytesC, prototypes, metadata)
	for _, pipeline := range []struct{ name, level, ir string }{
		{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir}, {"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			if output := execution.compileAndRunLLVM(t, "native-half-complete", pipeline.ir, driver, pipeline.level); len(output) != 0 {
				t.Fatal("incomplete full-byte/FLAGS/DF native oracle", string(output))
			}
			t.Log("half native full64/FLAGS/DF=1/canary outcomes=512; complete original STD/CLD source and all eight named half moves")
		})
	}
	x86RunOriginalGoNativeSource(t, execution, "amd64", "package oracle\n"+declarations, source, fmt.Sprintf(x86MoveHalfOriginalGo, goRows))
	t.Log("half actual original Go full64/FLAGS/DF=1/canary outcomes=512")
	x87IA32RequireNativeHost(t)
}
