package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func arm64FPControlStateFixture() (source, declarations, original, driver string) {
	var assembly, goDecl, goMain, cMain strings.Builder
	goDecl.WriteString("package compare\n")
	goMain.WriteString("package main\nimport \"fmt\"\n")
	cMain.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for mode := 0; mode < 4; mode++ {
		name := fmt.Sprintf("compareControlState%d", mode)
		fmt.Fprintf(&goDecl, "func %s(*[2]uint64,*[3]uint64)\n", name)
		fmt.Fprintf(&goMain, "func %s(*[2]uint64,*[3]uint64)\n", name)
		fmt.Fprintf(&cMain, "extern void %s(uint64_t*,uint64_t*);\n", name)
		fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-16\n", name)
		assembly.WriteString(`MOVD in+0(FP),R0
MOVD out+8(FP),R1
MRS FPCR,R10
MRS FPSR,R11
MOVD 0(R0),R2
MOVD 8(R0),R3
CMP R0,R0
`)
		if mode&1 == 0 {
			assembly.WriteString("MSR R2,FPCR\nMSR R3,FPSR\n")
		} else {
			assembly.WriteString("WORD $0xd51b4402\nWORD $0xd51b4423\n")
		}
		if mode&2 == 0 {
			assembly.WriteString("MRS FPCR,R4\nMRS FPSR,R5\n")
		} else {
			assembly.WriteString("WORD $0xd53b4404\nWORD $0xd53b4425\n")
		}
		assembly.WriteString(`CSET EQ,R6
MOVD R4,0(R1)
MOVD R5,8(R1)
MOVD R6,16(R1)
MSR R10,FPCR
MSR R11,FPSR
RET
`)
	}
	goMain.WriteString(`func main() {
    count := 0
    functions := []func(*[2]uint64,*[3]uint64){
        compareControlState0, compareControlState1,
        compareControlState2, compareControlState3,
    }
    for index, function := range functions {
        for control := uint64(0); control < 16; control++ {
            for _, status := range []uint64{0, 1, 0x1f, 0x80, 0x0800009f} {
                input := [2]uint64{(control&3)<<22 | (control>>2)<<24, status}
                var output [3]uint64
                function(&input, &output)
                want := [3]uint64{input[0], input[1], 1}
                if output != want {
                    panic(fmt.Sprintf("control mode=%d input=%x got=%x want=%x", index, input, output, want))
                }
                count++
            }
        }
    }
    fmt.Println("ARM64_COMPARE_ORIGINAL_PASS control roundtrip", count)
}
`)
	cMain.WriteString(`int main(void) {
    void (*functions[])(uint64_t*,uint64_t*) = {
        compareControlState0, compareControlState1,
        compareControlState2, compareControlState3,
    };
    const uint64_t statuses[] = {0, 1, 0x1f, 0x80, 0x0800009f};
    for (unsigned index = 0; index < 4; index++) {
        for (uint64_t control = 0; control < 16; control++) {
            for (unsigned sample = 0; sample < 5; sample++) {
                uint64_t input[2] = {(control&3)<<22 | (control>>2)<<24, statuses[sample]};
                uint64_t output[3] = {0, 0, 0};
                functions[index](input, output);
                if (output[0] != input[0] || output[1] != input[1] || output[2] != 1) {
                    fprintf(stderr, "control mode=%u control=%llx status=%llx got=%llx/%llx/%llx\n",
                        index, (unsigned long long)input[0], (unsigned long long)input[1],
                        (unsigned long long)output[0], (unsigned long long)output[1],
                        (unsigned long long)output[2]);
                    return 1;
                }
            }
        }
    }
    return 0;
}
`)
	return assembly.String(), goDecl.String(), goMain.String(), cMain.String()
}

func arm64FPControlStateRuntime(t *testing.T, triple, goos string, compiler, runner []string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	source, declarations, original, driver := arm64FPControlStateFixture()
	arm64ScalarCompareActualGo(t, source, original, goos, runner)
	irs := arm64FPControlIRs(t, source, declarations, triple)
	for api, ir := range irs {
		for _, variant := range []struct{ name, ir string }{
			{"none", ir}, {"O2", armFloatEffectOptimizedIR(t, ir)},
		} {
			for _, level := range []int{0, 2} {
				t.Run(fmt.Sprintf("api%d/IR_%s/backend_O%d", api, variant.name, level), func(t *testing.T) {
					compileAndRunRuntimeTestWithCompiler(t, llc, compiler,
						"fp_control_state", triple, variant.ir, driver, runner, level)
				})
			}
		}
	}
}

func TestARM64FPControlStateNativeRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("Darwin counterpart; the required Linux/QEMU owner executes the same original Go oracle")
	}
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	arm64FPControlStateRuntime(t, "aarch64-apple-darwin", "darwin", []string{clang}, nil)
}
