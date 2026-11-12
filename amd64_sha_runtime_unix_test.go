//go:build unix

package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixedLocalSHARuntimeKernels(t *testing.T) []fixedLocalVEXRuntimeKernel {
	t.Helper()
	var kernels []fixedLocalVEXRuntimeKernel
	count := 0
	for _, family := range x86SHAOracleInputs {
		selectors := []int{0}
		if family.name == "SHA1RNDS4" {
			selectors = []int{0, 1, 2, 3}
		}
		for _, selector := range selectors {
			var operations []string
			for _, source := range []string{"X0", "X1", "X2", "64(BP)", "(SI)"} {
				operations = append(operations, x86SHAOracleRow(family.name, source, "X2", selector))
			}
			for _, source := range []string{"X1", "X0"} {
				operations = append(operations, x86SHAOracleRow(family.name, source, "X0", selector))
			}
			kernels = append(kernels, fixedLocalVEXRuntimeKernel{
				shape: fmt.Sprintf("%s/%d", family.name, selector), operations: operations,
			})
			count += len(operations)
		}
	}
	if len(kernels) != 10 || count != 70 {
		t.Fatal("complete SHA original-execution inventory changed", len(kernels), count)
	}
	return kernels
}

func fixedLocalSHARuntimePreflight(t *testing.T, execution x86FloatCompareExecution) string {
	t.Helper()
	directory := t.TempDir()
	source, executable := filepath.Join(directory, "sha.c"), filepath.Join(directory, "sha")
	const program = `#include <stdio.h>
#include <string.h>
#include <cpuid.h>
__attribute__((target("sha,sse2"))) static int original_sha(void) {
    unsigned bits;
    __asm__ volatile("pxor %%xmm0,%%xmm0; sha1msg1 %%xmm0,%%xmm0; pmovmskb %%xmm0,%0"
                     : "=r"(bits) :: "xmm0");
    return bits==0;
}
int main(void) {
    __builtin_cpu_init();
    int sha=!!__builtin_cpu_supports("sha");
    unsigned a, b, c, d, signature;
    char vendor[13]={0};
    __cpuid(0,a,b,c,d);
    memcpy(vendor,&b,4);
    memcpy(vendor+4,&d,4);
    memcpy(vendor+8,&c,4);
    __cpuid(1,signature,b,c,d);
    printf("fixed-frame native SHA=%d vendor=%s signature=%08x\n",sha,vendor,signature);
    return sha && original_sha() ? 0 : 1;
}
`
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, executable)
	return executable
}

func TestGoAMD64FixedLocalSHARuntimeObjects(t *testing.T) {
	execution := fixedLocalPackedCompileOnlyTools(t)
	fixedLocalSHARuntimePreflight(t, execution)
	fixedLocalVectorRuntime(t, execution, false, fixedLocalSHARuntimeKernels(t))
}

func fixedLocalSHAFaultRuntime(t *testing.T, execution x86FloatCompareExecution, execute bool) {
	t.Helper()
	var source, declarations, prototypes, originals, rows strings.Builder
	declarations.WriteString("package shafault\n")
	count := 0
	for _, family := range x86SHAOracleInputs {
		for _, dead := range []bool{false, true} {
			name := fmt.Sprintf("F%d", count)
			count++
			operation := x86SHAOracleRow(family.name, "(DI)", "X2", 3)
			store, nativeStore := "", ""
			if !dead {
				store = "MOVQ out+8(FP),SI\nMOVOU X2,(SI)\n"
				nativeStore = "MOVOU X2,(SI)\n"
			}
			initialize := "PXOR X0,X0\nPXOR X2,X2\n"
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ p+0(FP),DI\n%s%s\n%sRET\n", name, initialize, operation, store)
			fmt.Fprintf(&declarations, "func %s(p *[16]byte,out *[16]byte)\n", name)
			original := "Original" + name
			for _, symbol := range []string{name, original} {
				fmt.Fprintf(&prototypes, "extern void %s(const uint8_t*,uint8_t*);\n", symbol)
			}
			actual := x86OrderingHintGoBytes(t, "amd64", "TEXT original(SB),4,$0-0\n"+initialize+operation+"\n"+nativeStore+"RET\n")
			var encoded []string
			for _, value := range actual {
				encoded = append(encoded, fmt.Sprintf("0x%02x", value))
			}
			symbol := original
			if strings.Contains(execution.triple, "apple") {
				symbol = "_" + symbol
			}
			fmt.Fprintf(&originals, "__asm__(%q);\n", ".text\n.globl "+symbol+"\n"+symbol+":\n.byte "+strings.Join(encoded, ",")+"\n")
			fmt.Fprintf(&rows, "{%s,%s,16,1},\n", name, original)
		}
	}
	if count != 14 {
		t.Fatal("complete SHA live/dead fault inventory changed", count)
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	ir := x86NarrowOracleIR(t, source.String(), declarations.String(), execution.triple)
	// Intel XED marks SHA m128 REQUIRES_ALIGNMENT, but original Go opcodes
	// execute unaligned on some native CPUs. Observe both unaligned addresses
	// independently per original opcode and require exact translated agreement.
	// All other full-width/guard-page/dead-read expectations remain fixed; this
	// does not relax the separate private-frame alignment proof or AES owner.
	// https://github.com/intelxed/xed/blob/main/datafiles/sha/sha-isa.xed.txt
	const alignment = `#define NATIVE_ALIGNMENT 0
#define ALIGNMENT_OBSERVED(k,a,f) printf("sha alignment kernel%u address%u fault%d\n",k,a,f)
`
	driver := alignment + fmt.Sprintf(x86AESFaultC, prototypes.String(), originals.String(), rows.String())
	driver = strings.ReplaceAll(driver, "aes live/dead", "sha live/dead")
	driver = strings.ReplaceAll(driver, "AES kernel", "SHA kernel")
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			input := ir
			if level == "-O2" {
				input = x86DwordProductIROptimize(t, ir)
			}
			if !execute {
				execution.compileLLVM(t, "sha-fault", input, driver, level)
				return
			}
			output := execution.compileAndRunLLVM(t, "sha-fault", input, driver, level)
			want := fmt.Sprintf("sha live/dead kernels %d exact fault outcomes %d tripwires 4 failures 0\n", count, count*18)
			if !strings.HasSuffix(string(output), want) || strings.Count(string(output), "sha alignment kernel") != count*2 {
				t.Fatal("original SHA live/dead m128 fault comparison", string(output))
			}
			t.Log(strings.TrimSpace(string(output)))
		})
	}
}

func TestGoAMD64SHAFaultRuntimeObjects(t *testing.T) {
	fixedLocalSHAFaultRuntime(t, fixedLocalPackedCompileOnlyTools(t), false)
}
