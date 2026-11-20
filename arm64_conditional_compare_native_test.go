package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

var arm64ConditionalCompareNames = []string{"FCCMPS", "FCCMPD", "FCCMPES", "FCCMPED"}

func arm64ConditionalCompareDeadFixture() (string, string) {
	var source, declarations strings.Builder
	declarations.WriteString("package compare\n")
	for index, operation := range arm64ConditionalCompareNames {
		for mode := 0; mode < 2; mode++ {
			name := fmt.Sprintf("compareConditional%d_%d", index, mode)
			fmt.Fprintf(&declarations, "func %s(*[5]uint64,*[4]uint64)\n", name)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVD in+0(FP),R0\nMOVD out+8(FP),R1\n", name)
			source.WriteString("MRS FPCR,R10\nMRS FPSR,R11\nMOVD 24(R0),R2\nMSR R2,FPCR\nMOVD 32(R0),R2\nMSR R2,FPSR\n")
			move := "FMOVS"
			if strings.HasSuffix(operation, "D") {
				move = "FMOVD"
			}
			fmt.Fprintf(&source, "%s (R0),F0\n%s 8(R0),F31\nMOVD 16(R0),R2\nCMP $0,R2\n%s NE,F31,F0,$10\n", move, move, operation)
			if mode == 1 {
				source.WriteString("CMP R0,R0\n")
			}
			source.WriteString("CSET MI,R2\nCSET EQ,R3\nCSET CS,R4\nCSET VS,R5\nLSL $3,R2,R2\nLSL $2,R3,R3\nLSL $1,R4,R4\nORR R3,R2,R2\nORR R4,R2,R2\nORR R5,R2,R2\n")
			source.WriteString("MRS FPSR,R3\nMRS FPCR,R4\nMOVD R2,(R1)\nMOVD R3,8(R1)\nMOVD R4,16(R1)\nMSR R10,FPCR\nMSR R11,FPSR\nRET\n")
		}
	}
	return source.String(), declarations.String()
}

func arm64ConditionalCompareDeadRuntime(t *testing.T, triple, goos string, compiler, runner []string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	source, declarations := arm64ConditionalCompareDeadFixture()
	var original, driver strings.Builder
	original.WriteString(strings.Replace(declarations, "package compare", "package main\nimport \"fmt\"", 1))
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for index := range arm64ConditionalCompareNames {
		for mode := 0; mode < 2; mode++ {
			fmt.Fprintf(&driver, "extern void compareConditional%d_%d(uint64_t*,uint64_t*);\n", index, mode)
		}
	}
	original.WriteString("func main() {\n")
	driver.WriteString("int main(void) {\n")
	count := 0
	for index, operation := range arm64ConditionalCompareNames {
		bits := 32
		if strings.HasSuffix(operation, "D") {
			bits = 64
		}
		values := arm64CompareValues(bits)
		for _, value := range []uint64{values[6], values[8], values[10], values[2]} {
			for _, initialFlags := range []uint64{0, 4 << 28} {
				for _, control := range []uint64{0, 1 << 24} {
					flags, status := arm64CompareExpected(bits, value, 0, control, strings.Contains(operation, "E"))
					if initialFlags == 0 {
						flags, status = 10, 0
					}
					status |= 0x10 // Existing cumulative status must not be cleared.
					for mode := 0; mode < 2; mode++ {
						wantFlags := flags
						if mode == 1 {
							wantFlags = 6
						}
						fmt.Fprintf(&original, "{ in:=[5]uint64{%#x,0,%#x,%#x,0x10}; out:=[4]uint64{0,0,0,0x1234}; compareConditional%d_%d(&in,&out); if out!=[4]uint64{%d,%d,%#x,0x1234} { panic(fmt.Sprintf(\"case %d got %%x\",out)) } }\n", value, initialFlags, control, index, mode, wantFlags, status, control, count)
						fmt.Fprintf(&driver, "{ uint64_t in[5]={%#xULL,0,%#xULL,%#xULL,0x10},out[4]={0,0,0,0x1234}; compareConditional%d_%d(in,out); if(out[0]!=%d || out[1]!=%d || out[2]!=%#xULL || out[3]!=0x1234){fprintf(stderr,\"case %d %s got %%llx %%llx %%llx\\n\",(unsigned long long)out[0],(unsigned long long)out[1],(unsigned long long)out[2]);return 1;} }\n", value, initialFlags, control, index, mode, wantFlags, status, control, count, operation)
						count++
					}
				}
			}
		}
	}
	fmt.Fprintf(&original, "fmt.Println(\"ARM64_COMPARE_ORIGINAL_PASS conditional %d rows\")\n}\n", count)
	driver.WriteString("return 0;\n}\n")
	arm64ScalarCompareActualGo(t, source, original.String(), goos, runner)
	for api, ir := range arm64CompareMatrixIRs(t, source, declarations, triple) {
		for _, variant := range []struct{ name, ir string }{{"none", ir}, {"O2", armFloatEffectOptimizedIR(t, ir)}} {
			for _, level := range []int{0, 2} {
				t.Run(fmt.Sprintf("api%d/IR_%s/backend_O%d", api, variant.name, level), func(t *testing.T) {
					compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "conditional_compare_dead", triple, variant.ir, driver.String(), runner, level)
				})
			}
		}
	}
}

func TestARM64ConditionalCompareDeadNativeRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("Darwin host counterpart; required Linux/QEMU owner executes the same original Go fixture")
	}
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	arm64ConditionalCompareDeadRuntime(t, "aarch64-apple-darwin", "darwin", []string{clang}, nil)
}
