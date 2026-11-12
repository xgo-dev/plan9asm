package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Independent asm7.go case-54 named family, not the production specification.
var arm64ScalarBinaryNames = []string{
	"FADDS", "FADDD", "FSUBS", "FSUBD", "FMULS", "FMULD",
	"FNMULS", "FNMULD", "FDIVS", "FDIVD",
}

func arm64ScalarBinaryDeadFixture() (string, string) {
	var source, declarations strings.Builder
	declarations.WriteString("package compare\n")
	for index, operation := range arm64ScalarBinaryNames {
		for _, operands := range []int{2, 3} {
			name := fmt.Sprintf("compareBinary%d_%d", index, operands)
			fmt.Fprintf(&declarations, "func %s(*[3]uint64,*[4]uint64)\n", name)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVD in+0(FP),R0\nMOVD out+8(FP),R1\n", name)
			source.WriteString("MRS FPCR,R10\nMRS FPSR,R11\nMOVD 8(R0),R2\nMSR R2,FPCR\nMOVD 16(R0),R2\nMSR R2,FPSR\n")
			move := "FMOVS"
			if strings.HasSuffix(operation, "D") {
				move = "FMOVD"
			}
			fmt.Fprintf(&source, "%s (R0),F0\n%s (R0),F31\nCMP R0,R0\n%s F31,F0", move, move, operation)
			if operands == 3 {
				source.WriteString(",F15")
			}
			// The numerical destination is deliberately dead, not reloaded.
			source.WriteString("\nCSET EQ,R4\nMRS FPSR,R2\nMRS FPCR,R3\nMOVD R2,(R1)\nMOVD R3,8(R1)\nMOVD R4,16(R1)\nMSR R10,FPCR\nMSR R11,FPSR\nRET\n")
		}
	}
	return source.String(), declarations.String()
}

func arm64ScalarBinaryDeadRuntime(t *testing.T, triple, goos string, compiler, runner []string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	source, declarations := arm64ScalarBinaryDeadFixture()
	var original, driver strings.Builder
	original.WriteString(strings.Replace(declarations, "package compare", "package main\nimport \"fmt\"", 1))
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for index := range arm64ScalarBinaryNames {
		for _, operands := range []int{2, 3} {
			fmt.Fprintf(&driver, "extern void compareBinary%d_%d(uint64_t*,uint64_t*);\n", index, operands)
		}
	}
	original.WriteString("func main() {\n")
	driver.WriteString("int main(void) {\n")
	count := 0
	for index, operation := range arm64ScalarBinaryNames {
		for _, operands := range []int{2, 3} {
			for _, signaling := range []bool{false, true} {
				value := uint64(0x7ff8000000000001)
				if strings.HasSuffix(operation, "S") {
					value = 0x7fc00001
				}
				if signaling {
					if strings.HasSuffix(operation, "S") {
						value = 0x7f800001
					} else {
						value = 0x7ff0000000000001
					}
				}
				status := 0x10
				if signaling {
					status |= 1
				}
				for _, control := range []uint64{0, 1 << 25} {
					fmt.Fprintf(&original, "{ in:=[3]uint64{%#x,%#x,0x10};out:=[4]uint64{0,0,0,0x1234};compareBinary%d_%d(&in,&out);if out!=[4]uint64{%d,%#x,1,0x1234}{panic(fmt.Sprintf(\"case %d %s got %%x\",out))} }\n", value, control, index, operands, status, control, count, operation)
					fmt.Fprintf(&driver, "{uint64_t in[3]={%#xULL,%#xULL,0x10},out[4]={0,0,0,0x1234};compareBinary%d_%d(in,out);if(out[0]!=%d || out[1]!=%#xULL || out[2]!=1 || out[3]!=0x1234){fprintf(stderr,\"case %d %s got %%llx %%llx %%llx %%llx\\n\",(unsigned long long)out[0],(unsigned long long)out[1],(unsigned long long)out[2],(unsigned long long)out[3]);return 1;}}\n", value, control, index, operands, status, control, count, operation)
					count++
				}
			}
		}
	}
	fmt.Fprintf(&original, "fmt.Println(\"ARM64_COMPARE_ORIGINAL_PASS binary dead %d rows\")\n}\n", count)
	driver.WriteString("return 0;\n}\n")
	arm64ScalarCompareActualGo(t, source, original.String(), goos, runner)
	for api, ir := range arm64BinaryMatrixIRs(t, source, declarations, triple) {
		for _, variant := range []struct{ name, ir string }{{"none", ir}, {"O2", armFloatEffectOptimizedIR(t, ir)}} {
			for _, level := range []int{0, 2} {
				t.Run(fmt.Sprintf("api%d/IR_%s/backend_O%d", api, variant.name, level), func(t *testing.T) {
					compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "scalar_binary_dead", triple, variant.ir, driver.String(), runner, level)
				})
			}
		}
	}
}

func TestARM64ScalarBinaryDeadNativeRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("Darwin host counterpart; required Linux/QEMU owner executes the same original Go fixture")
	}
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	arm64ScalarBinaryDeadRuntime(t, "aarch64-apple-darwin", "darwin", []string{clang}, nil)
}
