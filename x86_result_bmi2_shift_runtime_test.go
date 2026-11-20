package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Execute the unchanged 72-function numerical/FLAGS/unaligned-memory fixture
// on the actual host. This is separate from native original-opcode execution.
func TestX86BMI2ShiftOriginalFixturePortableExecution(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc/clang required")
	}
	source, _, declarations, checks := x86BMI2ShiftRuntimeFixture(t)
	var goDeclarations strings.Builder
	for index := 0; index < 72; index++ {
		fmt.Fprintf(&goDeclarations, "func bmi2shift%d(count uint64,source,out *byte)\n", index)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, goDeclarations.String(), "amd64", triple, api)
			if err != nil {
				t.Fatal("original complete BMI2 source lost its native-read continuation", err)
			}
			for index, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					compileAndRunRuntimeTestForTarget(t, llc, clang,
						fmt.Sprintf("bmi2-original-%s-ir%d-%s", api, index, level[1:]),
						triple, text, x86BMI2ShiftRuntimeDriver(declarations, checks), nil)
				}
			}
		})
	}
}

func TestX86RORXPortableBoundaryValues(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc/clang required")
	}
	var source, declarations, prototypes, rows strings.Builder
	count := 0
	for _, bits := range []int{32, 64} {
		op := "RORXL"
		if bits == 64 {
			op = "RORXQ"
		}
		for _, immediate := range []int{0, 1, 7, 31, 32, 63, 64, 127, 128, 255} {
			for _, raw := range []bool{false, true} {
				name := fmt.Sprintf("Rotate%d", count)
				line := fmt.Sprintf("%s $%d,AX,AX", op, immediate)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nMOVQ value+0(FP),AX\n", name)
				emitX86GoEncodedTestInstruction(t, &source, line, raw)
				source.WriteString("MOVQ AX,ret+8(FP)\nRET\n")
				fmt.Fprintf(&declarations, "func %s(value uint64) uint64\n", name)
				fmt.Fprintf(&prototypes, "extern uint64_t %s(uint64_t);\n", name)
				fmt.Fprintf(&rows, "{%s,%d,%d},\n", name, bits, immediate)
				count++
			}
		}
	}
	if count != 40 {
		t.Fatal("complete named/raw width and boundary-count denominator changed", count)
	}
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source.String())
	main := "#include <stdint.h>\n#include <stdio.h>\n" + prototypes.String() + `
static const struct { uint64_t (*run)(uint64_t); unsigned bits, count; } cases[] = {
` + rows.String() + `};
int main(void) {
    for (unsigned row=0; row<sizeof(cases)/sizeof(cases[0]); row++) {
        uint64_t mask=cases[row].bits==64 ? UINT64_MAX : UINT32_MAX;
        unsigned n=cases[row].count & (cases[row].bits-1);
        for (unsigned bit=0; bit<64; bit++) {
            for (unsigned inverted=0; inverted<2; inverted++) {
                uint64_t value=UINT64_C(1)<<bit;
                if (inverted) value=~value;
                uint64_t low=value&mask, want=low;
                if (n) want=((low>>n)|(low<<(cases[row].bits-n)))&mask;
                uint64_t got=cases[row].run(value);
                if (got!=want) {
                    fprintf(stderr,"RORX row=%u bit=%u inverted=%u got=%llx want=%llx\n",
                            row,bit,inverted,(unsigned long long)got,(unsigned long long)want);
                    return 1;
                }
            }
        }
    }
    return 0;
}
`
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
			if err != nil {
				t.Fatal(err)
			}
			for index, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []string{"-O0", "-O2"} {
					compileAndRunRuntimeTestForTarget(t, llc, clang,
						fmt.Sprintf("rorx-%s-ir%d-%s", api, index, level[1:]), triple, text, main, nil)
				}
			}
		})
	}
}
