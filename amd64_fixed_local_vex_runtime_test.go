//go:build unix

package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type fixedLocalVEXRuntimeKernel struct {
	shape      string
	operations []string
}

// A kernel owns one real register/width/immediate shape. Equivalent signed
// and unsigned immediate table rows share it; register/private/native memory
// sources and destination aliases remain separate observable operations.
func fixedLocalVEXRuntimeKernels(t *testing.T) []fixedLocalVEXRuntimeKernel {
	t.Helper()
	witnesses := append(fixedLocalVEXWitnesses(t), fixedLocalVEXBinaryWitnesses(t)...)
	var kernels []fixedLocalVEXRuntimeKernel
	rows, shapes := make(map[string]string), make(map[string]int)
	seen := make(map[string]bool)
	for _, witness := range witnesses {
		parts := strings.SplitN(witness.source, " ", 2)
		var args []string
		if len(parts) == 2 {
			args = strings.Split(parts[1], ",")
		}
		for index, argument := range args {
			if strings.HasPrefix(argument, "$") {
				args[index] = "$3"
				if strings.HasPrefix(parts[0], "VPERM2") {
					args[index] = "$49"
				} else if parts[0] == "VPALIGNR" {
					args[index] = "$17"
				}
			}
		}
		operation := strings.TrimSpace(parts[0] + " " + strings.Join(args, ","))
		owner := strings.Split(witness.owner, "/")
		row := owner[0] + "/" + owner[1]
		shape, exists := rows[row]
		if !exists {
			// The official witness builder emits the register choice first.
			if strings.Contains(operation, "(") {
				t.Fatal("runtime row lost its independent register witness", witness.owner)
			}
			shape, rows[row] = operation, operation
		}
		index, exists := shapes[shape]
		if !exists {
			index, shapes[shape] = len(kernels), len(kernels)
			kernels = append(kernels, fixedLocalVEXRuntimeKernel{shape: shape})
		}
		add := func(source string) {
			key := shape + "\n" + source
			if !seen[key] {
				seen[key] = true
				kernels[index].operations = append(kernels[index].operations, source)
			}
		}
		add(operation)
		if len(args) < 2 || (!strings.HasPrefix(args[len(args)-1], "X") && !strings.HasPrefix(args[len(args)-1], "Y")) {
			continue
		}
		for _, argument := range args[:len(args)-1] {
			if !strings.HasPrefix(argument, "X") && !strings.HasPrefix(argument, "Y") {
				continue
			}
			alias := append([]string(nil), args...)
			alias[len(alias)-1] = args[len(args)-1][:1] + argument[1:]
			add(parts[0] + " " + strings.Join(alias, ","))
		}
	}
	return kernels
}

// Each operation observes Y0..Y3 in full, including the upper 128 bits of an
// X destination, and all three scratch vectors (left canary/source/right).
// Input memory and the outer output canaries are printed by both drivers.
func fixedLocalVEXRuntimeProgram(kernels []fixedLocalVEXRuntimeKernel, triple string) (string, string, string, string) {
	var assembly, declarations, goRows, cRows, cDeclarations strings.Builder
	prefix := ""
	if strings.Contains(triple, "apple") {
		prefix = "_"
	}
	for index, kernel := range kernels {
		name := fmt.Sprintf("Value%d", index)
		fmt.Fprintf(&declarations, "func %s(out *uint64, input *[16]uint64)\n", name)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$256-16\nMOVQ out+0(FP),DI\nMOVQ input+8(FP),SI\n", name)
		assembly.WriteString("MOVQ SP,BP\nADDQ $64,BP\nANDQ $-64,BP\n")
		for observation, operation := range kernel.operations {
			for register := 0; register < 4; register++ {
				fmt.Fprintf(&assembly, "VMOVDQU %d(SI),Y%d\n", register*32, register)
			}
			assembly.WriteString("VMOVDQU Y3,32(BP)\nVMOVDQU Y0,64(BP)\nVMOVDQU Y2,96(BP)\n")
			assembly.WriteString(operation + "\n")
			for register := 0; register < 4; register++ {
				fmt.Fprintf(&assembly, "VMOVDQU Y%d,%d(DI)\n", register, observation*224+register*32)
			}
			for vector := 0; vector < 3; vector++ {
				fmt.Fprintf(&assembly, "VMOVDQU %d(BP),Y4\nVMOVDQU Y4,%d(DI)\n",
					32+vector*32, observation*224+128+vector*32)
			}
		}
		assembly.WriteString("VZEROUPPER\nRET\n")
		fmt.Fprintf(&goRows, "{%s,%d},\n", name, len(kernel.operations)*28)
		fmt.Fprintf(&cRows, "{value%d,%d},\n", index, len(kernel.operations)*28)
		label := runtimeCAsmLabel(prefix + "example.invalid/framefixture." + name)
		fmt.Fprintf(&cDeclarations, "extern void value%d(uint64_t*,uint64_t*) __asm__(%s);\n", index, label)
	}
	const values = `0,1,7,15,16,31,32,63,64,65,0x7f7f7f7f7f7f7f7f,
0x8080808080808080,0x7fff7fff7fff7fff,0x8000800080008000,
0xffffffffffffffff,0x0123456789abcdef`
	original := `package main
import ("fmt"; "unsafe")
` + declarations.String() + `
func main() {
    rows := []struct { call func(*uint64,*[16]uint64); words int }{
` + goRows.String() + `
    }
    values := []uint64{` + values + `}
    for row, entry := range rows {
        for sample := range values {
            var storage [24]uint64
            input := (*[16]uint64)(unsafe.Pointer((uintptr(unsafe.Pointer(&storage[0]))+63)&^uintptr(63)))
            for index := range input {
                input[index] = values[(sample+index)%len(values)]
            }
            output := make([]uint64,entry.words+8)
            for index := range output {
                output[index] = 0xc3c3c3c3c3c3c300+uint64(index)
            }
            entry.call(&output[4],input)
            fmt.Printf("%d %d",row,sample)
            for _, value := range output {
                fmt.Printf(" %016x",value)
            }
            for _, value := range input {
                fmt.Printf(" %016x",value)
            }
            fmt.Println()
        }
    }
}
`
	driver := `#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
` + runtimeCAsmLabelPreamble + cDeclarations.String() + `
int main(void) {
    const struct { void (*call)(uint64_t*,uint64_t*); size_t words; } rows[] = {
` + cRows.String() + `
    };
    const uint64_t values[] = {` + values + `};
    const size_t samples = sizeof(values)/sizeof(values[0]);
    for (size_t row = 0; row < sizeof(rows)/sizeof(rows[0]); row++) {
        for (size_t sample = 0; sample < samples; sample++) {
            _Alignas(64) uint64_t input[16];
            for (size_t index = 0; index < 16; index++) {
                input[index] = values[(sample+index)%samples];
            }
            const size_t words = rows[row].words+8;
            uint64_t *output = malloc(words*sizeof(*output));
            if (!output) return 2;
            for (size_t index = 0; index < words; index++) {
                output[index] = UINT64_C(0xc3c3c3c3c3c3c300)+index;
            }
            rows[row].call(output+4,input);
            printf("%zu %zu",row,sample);
            for (size_t index = 0; index < words; index++) {
                printf(" %016llx",(unsigned long long)output[index]);
            }
            for (size_t index = 0; index < 16; index++) {
                printf(" %016llx",(unsigned long long)input[index]);
            }
            puts("");
            free(output);
        }
    }
    return 0;
}
`
	return assembly.String(), declarations.String(), original, driver
}

func fixedLocalVEXRuntime(t *testing.T, execution x86FloatCompareExecution, execute bool) {
	t.Helper()
	fixedLocalVectorRuntime(t, execution, execute, fixedLocalVEXRuntimeKernels(t))
}

func fixedLocalVectorRuntime(t *testing.T, execution x86FloatCompareExecution, execute bool, kernels []fixedLocalVEXRuntimeKernel) {
	t.Helper()
	goAMD64FramePrepareOwnedToolCache(t)
	for start := 0; start < len(kernels); start += 32 {
		end := start + 32
		if end > len(kernels) {
			end = len(kernels)
		}
		t.Run(fmt.Sprintf("batch%d", start/32), func(t *testing.T) {
			assembly, declarations, original, driver := fixedLocalVEXRuntimeProgram(kernels[start:end], execution.triple)
			var want []string
			if execute {
				output := x86ScalarFloatIntegerOriginalOutput(t, execution, assembly, original)
				want = strings.Split(strings.TrimSpace(string(output)), "\n")
				if len(want) != (end-start)*16 {
					t.Fatalf("original Go emitted %d observations, want %d", len(want), (end-start)*16)
				}
			} else {
				x86COMICompileOriginalGo(t, map[string]string{
					"go.mod": "module vexframe\ngo 1.20\n", "main.go": original, "original_amd64.s": assembly,
				}, false)
			}
			pkg, request, _, options := fixedLocalTransportFixture(t, assembly, declarations,
				runtime.GOOS+"/amd64", execution.triple)
			fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"},
				func(t *testing.T, ir string, err error) {
					if err != nil {
						t.Fatal(err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						t.Run(level, func(t *testing.T) {
							input := ir
							if level == "-O2" {
								input = x86MulDivRoundOptimize(t, ir)
							}
							if !execute {
								execution.compileLLVM(t, "private-vex", input, driver, level)
								return
							}
							output := execution.compileAndRunLLVM(t, "private-vex", input, driver, level)
							got := strings.Split(strings.TrimSpace(string(output)), "\n")
							if len(got) != len(want) {
								t.Fatalf("LLVM emitted %d observations, original Go %d", len(got), len(want))
							}
							for index := range want {
								if got[index] != want[index] {
									t.Fatalf("kernel=%s sample=%d original=%s LLVM=%s", kernels[start+index/16].shape,
										index%16, want[index], got[index])
								}
							}
						})
					}
				})
		})
	}
	t.Logf("%d vector shape kernels, 16 input patterns; original Go and three LLVM APIs execute=%v", len(kernels), execute)
}

// Immediate-domain tests cover all selectors separately. These kernels compare
// original execution for four distinct selector patterns, both widths, memory and
// alias forms, and preserved/zeroed upper bytes. Memory canaries remain visible.
func fixedLocalShuffleRuntimeKernels() []fixedLocalVEXRuntimeKernel {
	var kernels []fixedLocalVEXRuntimeKernel
	names := []string{"PSHUFB", "PSHUFD", "PSHUFL", "PSHUFHW", "PSHUFLW", "VPSHUFD", "VPSHUFHW", "VPSHUFLW"}
	for _, name := range names {
		banks := []string{"X"}
		if strings.HasPrefix(name, "V") {
			banks = append(banks, "Y")
		}
		selectors := []string{"0", "27", "78", "255"}
		if name == "PSHUFB" {
			selectors = []string{""}
		}
		for _, bank := range banks {
			for _, selector := range selectors {
				prefix := name + " "
				if selector != "" {
					prefix += "$" + selector + ","
				}
				operations := []string{
					prefix + bank + "0," + bank + "2",
					prefix + bank + "0," + bank + "0",
					prefix + "64(BP)," + bank + "2",
					prefix + "0(SI)," + bank + "2",
				}
				if strings.HasPrefix(name, "V") {
					operations = append(operations, prefix+"65(BP),"+bank+"2", prefix+"1(SI),"+bank+"2")
				}
				kernels = append(kernels, fixedLocalVEXRuntimeKernel{shape: operations[0], operations: operations})
			}
		}
	}
	return kernels
}

func TestGoAMD64FixedLocalShuffleRuntimeObjects(t *testing.T) {
	kernels := fixedLocalShuffleRuntimeKernels()
	if len(kernels) != 41 {
		t.Fatal("legacy and VEX shuffle runtime inventory changed", len(kernels))
	}
	fixedLocalVectorRuntime(t, fixedLocalPackedCompileOnlyTools(t), false, kernels)
}

func fixedLocalCLMULRuntimeKernels(t *testing.T) []fixedLocalVEXRuntimeKernel {
	t.Helper()
	var kernels []fixedLocalVEXRuntimeKernel
	operations := 0
	for _, kind := range []string{"legacy", "X", "Y"} {
		for _, selector := range []int{0, 1, 16, 17, 238, 255} {
			var rows []string
			if kind == "legacy" {
				for _, source := range []string{"X1", "X2", "64(BP)", "(SI)"} {
					rows = append(rows, fmt.Sprintf("PCLMULQDQ $%d,%s,X2", selector, source))
				}
			} else {
				for _, source := range []string{kind + "1", "64(BP)", "(SI)", "65(BP)", "1(SI)"} {
					rows = append(rows, fmt.Sprintf("VPCLMULQDQ $%d,%s,%s2,%s3", selector, source, kind, kind))
				}
				for _, destination := range []string{kind + "1", kind + "2"} {
					rows = append(rows, fmt.Sprintf("VPCLMULQDQ $%d,%s1,%s2,%s", selector, kind, kind, destination))
				}
				for _, destination := range []string{kind + "3", kind + "2"} {
					rows = append(rows, fmt.Sprintf("VPCLMULQDQ $%d,%s2,%s2,%s", selector, kind, kind, destination))
				}
			}
			kernels = append(kernels, fixedLocalVEXRuntimeKernel{shape: rows[0], operations: rows})
			operations += len(rows)
		}
	}
	if len(kernels) != 18 || operations != 132 {
		t.Fatal("CLMUL original-execution inventory changed", len(kernels), operations)
	}
	return kernels
}

// AVX2 does not imply VPCLMULQDQ's Y-width instruction. The native owner
// checks both features and executes actual legacy/X and VEX/Y instructions;
// compile-only hosts build this preflight without claiming CPU availability.
func fixedLocalCLMULRuntimePreflight(t *testing.T, execution x86FloatCompareExecution) string {
	t.Helper()
	directory := t.TempDir()
	source, executable := filepath.Join(directory, "clmul.c"), filepath.Join(directory, "clmul")
	const program = `#include <stdio.h>
__attribute__((target("avx2,pclmul,vpclmulqdq"))) static int original_clmul(void) {
    unsigned legacy, wide;
    __asm__ volatile("pxor %%xmm0,%%xmm0; "
                     "pclmulqdq $0,%%xmm0,%%xmm0; pmovmskb %%xmm0,%0; "
                     "vpxor %%ymm0,%%ymm0,%%ymm0; "
                     "vpclmulqdq $0,%%ymm0,%%ymm0,%%ymm0; "
                     "vpmovmskb %%ymm0,%1; vzeroupper"
                     : "=r"(legacy), "=r"(wide) :: "ymm0");
    return legacy==0 && wide==0;
}
int main(void) {
    __builtin_cpu_init();
    int pclmul=!!__builtin_cpu_supports("pclmul");
    int vpclmul=!!__builtin_cpu_supports("vpclmulqdq");
    printf("fixed-frame native PCLMUL=%d VPCLMULQDQ=%d\n",pclmul,vpclmul);
    return pclmul && vpclmul && original_clmul() ? 0 : 1;
}
`
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, executable)
	return executable
}

func TestGoAMD64FixedLocalCLMULRuntimeObjects(t *testing.T) {
	execution := fixedLocalPackedCompileOnlyTools(t)
	fixedLocalCLMULRuntimePreflight(t, execution)
	fixedLocalVectorRuntime(t, execution, false, fixedLocalCLMULRuntimeKernels(t))
}

func TestGoAMD64FixedLocalVEXRuntimeObjects(t *testing.T) {
	fixedLocalVEXRuntime(t, fixedLocalPackedCompileOnlyTools(t), false)
}

func TestGoAMD64FixedLocalVEXRuntimeInventory(t *testing.T) {
	kernels := fixedLocalVEXRuntimeKernels(t)
	var witnesses []fixedLocalVEXWitness
	for _, kernel := range kernels {
		if len(kernel.operations) == 0 {
			t.Fatal("runtime kernel has no observable operation", kernel.shape)
		}
		for _, source := range kernel.operations {
			witnesses = append(witnesses, fixedLocalVEXWitness{owner: kernel.shape, source: source})
		}
	}
	fixedLocalCheckVEXEncodings(t, witnesses)
	t.Logf("540 official source witnesses grouped into %d real shape kernels, %d original-Go VEX operations including destination aliases",
		len(kernels), len(witnesses))
}

func fixedLocalShiftRuntimeKernels(t *testing.T) []fixedLocalVEXRuntimeKernel {
	t.Helper()
	var kernels []fixedLocalVEXRuntimeKernel
	operations := 0
	for index, name := range fixedLocalLegacyShiftNames() {
		for _, count := range []int{0, 1, 15, 127} {
			operation := fmt.Sprintf("%s $%d,X2", name, count)
			kernels = append(kernels, fixedLocalVEXRuntimeKernel{shape: operation, operations: []string{operation}})
			operations++
		}
		if index >= 8 {
			continue // Whole-byte shifts have only an immediate count.
		}
		var rows []string
		for _, count := range []string{"X0", "X2", "64(BP)", "(SI)"} {
			rows = append(rows, name+" "+count+",X2")
		}
		kernels = append(kernels, fixedLocalVEXRuntimeKernel{shape: rows[0], operations: rows})
		operations += len(rows)
	}
	if len(kernels) != 56 || operations != 80 {
		t.Fatal("complete legacy shift runtime inventory changed", len(kernels), operations)
	}
	return kernels
}

func TestGoAMD64FixedLocalShiftRuntimeObjects(t *testing.T) {
	fixedLocalVectorRuntime(t, fixedLocalPackedCompileOnlyTools(t), false, fixedLocalShiftRuntimeKernels(t))
}

func fixedLocalScalarLaneRuntimeKernels(t *testing.T) []fixedLocalVEXRuntimeKernel {
	t.Helper()
	rows := fixedLocalScalarLaneCases()
	var kernels []fixedLocalVEXRuntimeKernel
	owners := make(map[string]int)
	for _, row := range rows {
		first, _, _ := strings.Cut(row, "\n")
		name, operands, _ := strings.Cut(first, " ")
		index, exists := owners[name]
		if !exists {
			index, owners[name] = len(kernels), len(kernels)
			kernels = append(kernels, fixedLocalVEXRuntimeKernel{shape: name})
		}
		operation := "MOVQ (SI),AX\n" + row
		if strings.Contains(name, "INSR") {
			args := strings.Split(operands, ",")
			extract := strings.Replace(name, "INSR", "EXTR", 1)
			operation += fmt.Sprintf("\n%s %s,%s,AX", extract, args[0], args[len(args)-1])
		}
		// The existing scratch observation includes this separate full-GP
		// result slot. It exposes the high zeros of byte/word/dword extracts.
		// Y0 immediately observes native stores; Y1/Y2 retain the insert's
		// lane and upper-alias effects. Private transfers use bytes 65..72,
		// so neither the GP slot nor its surrounding canaries overlap them.
		operation += "\nMOVQ AX,88(BP)\nVMOVDQU (SI),Y0"
		kernels[index].operations = append(kernels[index].operations, operation)
	}
	if len(rows) != 132 || len(kernels) != 16 {
		t.Fatal("complete scalar-lane original-execution inventory changed", len(rows), len(kernels))
	}
	return kernels
}

func TestGoAMD64FixedLocalScalarLaneRuntimeObjects(t *testing.T) {
	fixedLocalVectorRuntime(t, fixedLocalPackedCompileOnlyTools(t), false, fixedLocalScalarLaneRuntimeKernels(t))
}
