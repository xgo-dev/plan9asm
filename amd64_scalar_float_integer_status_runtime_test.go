//go:build unix

package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Constants deliberately reach O2: testing only dynamic finite inputs cannot
// detect poison deleting observable stores or folding away MXCSR exceptions.
// Expected bits and status come from the original Go-assembled instructions.
func x86ScalarFloatIntegerConstantOracle() (assembly, declarations, original, driver string) {
	var asm, decl, goCalls, cDecl, cCalls strings.Builder
	index := 0
	for _, name := range x86ScalarFloatIntegerOracleNames() {
		if strings.HasPrefix(name, "V") {
			continue
		}
		values := []uint64{0x7fc12345, 0x7f800000, 0xff800000, 0x4f000000, 0x3fc00000, 1}
		if strings.Contains(name, "SD") {
			values = []uint64{0x7ff8123456789abc, 0x7ff0000000000000, 0xfff0000000000000, 0x43e0000000000000, 0x3ff8000000000000, 1}
		}
		for _, bits := range values {
			function := fmt.Sprintf("probe%d", index)
			fmt.Fprintf(&asm, "TEXT ·%s(SB),4,$8-12\nSTMXCSR saved-4(SP)\nMOVQ out+0(FP),DI\nMOVQ $%#x,AX\nMOVQ AX,X0\nLDMXCSR csr+8(FP)\n%s X0,AX\nMOVQ AX,(DI)\nSTMXCSR 8(DI)\nLDMXCSR saved-4(SP)\nRET\n", function, bits, name)
			fmt.Fprintf(&decl, "func %s(out *[4]uint64, csr uint32)\n", function)
			fmt.Fprintf(&goCalls, "check(%d,%s)\n", index, function)
			fmt.Fprintf(&cDecl, "extern void %s(uint64_t*,uint32_t);\n", function)
			fmt.Fprintf(&cCalls, "check(%d,%s);\n", index, function)
			index++
		}
	}
	original = `package main
import "fmt"
func check(index int, fn func(*[4]uint64,uint32)) {
    for mode:=0; mode<4; mode++ {
        out:=[4]uint64{0x1111111111111111,0x2222222222222222,0x3333333333333333,0x4444444444444444}
        fn(&out,0x1f80|uint32(mode)<<13)
        fmt.Printf("%d %d %016x %016x %016x %016x\n",index,mode,out[0],out[1],out[2],out[3])
    }
}
` + decl.String() + "func main(){\n" + goCalls.String() + "}\n"
	driver = `#include <stdint.h>
#include <stdio.h>
static void check(int index,void (*fn)(uint64_t*,uint32_t)) {
    for(unsigned mode=0; mode<4; mode++) {
        uint64_t out[]={UINT64_C(0x1111111111111111),UINT64_C(0x2222222222222222),UINT64_C(0x3333333333333333),UINT64_C(0x4444444444444444)};
        fn(out,0x1f80|(mode<<13));
        printf("%d %u %016llx %016llx %016llx %016llx\n",index,mode,(unsigned long long)out[0],(unsigned long long)out[1],(unsigned long long)out[2],(unsigned long long)out[3]);
    }
}
` + cDecl.String() + "int main(void){\n" + cCalls.String() + "return 0;}\n"
	return asm.String(), decl.String(), original, driver
}

func x86ScalarFloatIntegerOriginalOutput(t *testing.T, execution x86FloatCompareExecution, assembly, main string) []byte {
	t.Helper()
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod":  "module example.invalid/scalarfloatinteger\ngo 1.20\n",
		"main.go": main, "original_amd64.s": assembly,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(dir, "original")
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-p=2", "-o", binary, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOARCH=amd64", "GOOS="+runtime.GOOS, "CGO_ENABLED=0", "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual original Go float-to-integer oracle: %v\n%s", err, output)
	}
	return execution.run(t, binary)
}

func TestCrossLinuxRuntimeMatrixX86ScalarFloatIntegerOriginalConstantsAndMXCSR(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	assembly, declarations, main, driver := x86ScalarFloatIntegerConstantOracle()
	original := x86ScalarFloatIntegerOriginalOutput(t, execution, assembly, main)
	want := strings.Split(strings.TrimSpace(string(original)), "\n")
	if len(want) != 192 {
		t.Fatalf("original Go produced %d rows, want 48 functions x 4 MXCSR modes", len(want))
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, assembly, declarations, "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for _, optimized := range []bool{false, true} {
				input := ir
				if optimized {
					input = x86MulDivRoundOptimize(t, ir)
				}
				for _, backend := range []string{"-O0", "-O2"} {
					t.Run(fmt.Sprintf("IR_O2=%v/backend%s", optimized, backend), func(t *testing.T) {
						output := execution.compileAndRunLLVM(t, "scalar-conversion", input, driver, backend)
						got := strings.Split(strings.TrimSpace(string(output)), "\n")
						if len(got) != len(want) {
							t.Fatalf("LLVM row count=%d original=%d", len(got), len(want))
						}
						mismatches := 0
						for index := range want {
							if got[index] != want[index] {
								if mismatches == 0 {
									t.Logf("first mismatch: original %s; LLVM %s", want[index], got[index])
								}
								mismatches++
							}
						}
						if mismatches != 0 {
							t.Errorf("original Go value/MXCSR/canary mismatches=%d/%d", mismatches, len(want))
						}
					})
				}
			}
		})
	}
}
