package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type x86MaskMoveIntegerKernel struct {
	name                  string
	inputBits, outputBits int
}

// GP word size, K value width and the KMOV memory width are separate axes.
// The existing Q-only owner, its original sources and fixed byte anchors stay
// unchanged; this owner extends both GP directions across the complete family.
func x86MaskMoveGPWidthFixture(t *testing.T, arch string) (string, string, string, []x86MaskMoveIntegerKernel) {
	t.Helper()
	word, move := 8, "MOVQ"
	if arch == "386" {
		word, move = 4, "MOVL"
	}
	var source, declarations, prototypes, checks strings.Builder
	var kernels []x86MaskMoveIntegerKernel
	for _, row := range x86ResultMaskMoveWidthOracle {
		bits := row.bits
		if bits > 8*word {
			bits = 8 * word
		}
		for _, fromGP := range []bool{true, false} {
			inputBits, outputBits, result := 64, 8*word, 8
			direction, instruction := "ToGP", row.op+" K0,AX"
			body := "KMOVQ a+0(FP),K0\n" + instruction + "\n" + move + " AX,ret+8(FP)\nRET\n"
			if fromGP {
				inputBits, outputBits, result = 8*word, 64, word
				direction, instruction = "FromGP", row.op+" AX,K0"
				body = move + " a+0(FP),AX\n" + instruction + "\n" + fmt.Sprintf("KMOVQ K0,ret+%d(FP)\nRET\n", result)
			}
			for _, raw := range []bool{false, true} {
				prefix, lowered := "Named", body
				if raw {
					prefix = "Raw"
					lowered = strings.Replace(body, instruction+"\n", x86RawNumericalInstruction(t, arch, instruction), 1)
				}
				name := fmt.Sprintf("%s%s%d", prefix, direction, row.bits)
				fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s", name, result+outputBits/8, lowered)
				fmt.Fprintf(&declarations, "func %s(a uint%d) uint%d\n", name, inputBits, outputBits)
				fmt.Fprintf(&prototypes, "extern uint%d_t %s(uint%d_t);\n", outputBits, name, inputBits)
				fmt.Fprintf(&checks, "if(check(\"%s\",%s((uint%d_t)a),a,%d)) return 1;\n", name, name, inputBits, bits)
				kernels = append(kernels, x86MaskMoveIntegerKernel{name, inputBits, outputBits})
			}
		}
	}
	// Native K/K and Q-memory transport must retain all 64 bits in both modes.
	for _, raw := range []bool{false, true} {
		name, instruction := "NamedKeepQ64", "KMOVQ K0,K1\n"
		if raw {
			name, instruction = "RawKeepQ64", x86RawNumericalInstruction(t, arch, "KMOVQ K0,K1")
		}
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-16\nKMOVQ a+0(FP),K0\n%sKMOVQ K1,ret+8(FP)\nRET\n", name, instruction)
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
		fmt.Fprintf(&prototypes, "extern uint64_t %s(uint64_t);\n", name)
		fmt.Fprintf(&checks, "if(check(\"%s\",%s(a),a,64)) return 1;\n", name, name)
		kernels = append(kernels, x86MaskMoveIntegerKernel{name, 64, 64})
	}
	if len(kernels) != 18 {
		t.Fatal("incomplete four-width GP and independent Q64 control directory", len(kernels))
	}
	triple := "x86_64-unknown-linux-gnu"
	if arch == "386" {
		triple = "i386-unknown-linux-gnu"
	}
	x86LEAActualTargetGoObject(t, arch, triple, source.String())
	driver := "#include <stdint.h>\n#include <stdio.h>\n" + prototypes.String() + x86MaskMoveGPWidthValueC +
		"int main(void) { for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);++i) { uint64_t a=values[i];\n" + checks.String() + "} return 0; }\n"
	return source.String(), declarations.String(), driver, kernels
}

func TestX86MaskMoveGPAllWidthsPortableIntegerValues(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			source, declarations, driver, kernels := x86MaskMoveGPWidthFixture(t, arch)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, execution.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					context := llvm.NewContext()
					defer context.Dispose()
					module, err := parseIRModuleInContext(context, ir)
					if !module.IsNil() {
						defer module.Dispose()
					}
					if err != nil {
						t.Fatal(err)
					}
					for _, row := range kernels {
						function := module.NamedFunction(row.name)
						if function.IsNil() || function.FirstBasicBlock().IsNil() || function.ParamsCount() != 1 ||
							function.Param(0).Type().TypeKind() != llvm.IntegerTypeKind || function.Param(0).Type().IntTypeWidth() != row.inputBits ||
							function.GlobalValueType().ReturnType().TypeKind() != llvm.IntegerTypeKind || function.GlobalValueType().ReturnType().IntTypeWidth() != row.outputBits {
							t.Fatal("portable integer C ABI differs from actual LLVM signature", row.name)
						}
					}
					for _, pipeline := range []struct {
						name, level string
						optimize    bool
					}{
						{"default-O0", "-O0", false}, {"default-O2", "-O2", false}, {"opt-O2", "-O2", true},
					} {
						t.Run(pipeline.name, func(t *testing.T) {
							text := ir
							if pipeline.optimize {
								text = x86DwordProductIROptimize(t, text)
							}
							execution.compileAndRunLLVM(t, "kmov-gp-width-values", text, driver, pipeline.level)
						})
					}
				})
			}
		})
	}
	t.Log("source-mode integer semantics only; no pointer-width retargeting or original native KMOV/AVX512 execution")
}

const x86MaskMoveGPWidthValueC = `
static const uint64_t values[]={
    0,1,UINT64_C(0x7fffffff),UINT64_C(0x80000000),
    UINT64_C(0xffffffff),UINT64_C(0x100000000),
    UINT64_C(0xffffffff00000000),UINT64_C(0x0123456789abcdef),
    UINT64_MAX,UINT64_C(0x8000000000000000),
    UINT64_C(0x7fffffffffffffff),UINT64_C(0x100000001)
};
static int check(const char *name,uint64_t actual,uint64_t input,unsigned bits) {
    uint64_t mask=bits==64 ? UINT64_MAX : (UINT64_C(1)<<bits)-1;
    uint64_t expected=input&mask;
    if(actual!=expected) {
        fprintf(stderr,"%s input=%llx bits=%u actual=%llx expected=%llx\n",name,
                (unsigned long long)input,bits,(unsigned long long)actual,(unsigned long long)expected);
        return 1;
    }
    return 0;
}
`
