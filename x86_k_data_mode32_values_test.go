package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

var x86KDataMode32ValueKernels = []struct {
	name, input, output, body    string
	frame, inputBits, outputBits int
}{
	{"From32", "uint32", "uint64", "MOVL a+0(FP),AX\nKMOVQ AX,K0\nKMOVQ K0,ret+4(FP)\nRET\n", 12, 32, 64},
	{"To32", "uint64", "uint32", "KMOVQ a+0(FP),K0\nKMOVQ K0,AX\nMOVL AX,ret+8(FP)\nRET\n", 12, 64, 32},
	{"From64Low", "uint64", "uint64", "MOVL a+0(FP),AX\nKMOVQ AX,K0\nKMOVQ K0,ret+8(FP)\nRET\n", 16, 64, 64},
	{"ThroughGP", "uint64", "uint64", "KMOVQ a+0(FP),K0\nKMOVQ K0,AX\nKMOVQ AX,K1\nKMOVQ K1,ret+8(FP)\nRET\n", 16, 64, 64},
	{"Keep64", "uint64", "uint64", "KMOVQ a+0(FP),K0\nKMOVQ K0,K1\nKMOVQ K1,ret+8(FP)\nRET\n", 16, 64, 64},
}

func x86KDataMode32ValueSource(t *testing.T) (string, string) {
	t.Helper()
	// Preserve W1 and the original Go opcode, including for the legal32-bit
	// alias. Actual Go must verify these bytes before they replace named text.
	operations := []struct {
		instruction string
		code        []byte
	}{
		{"KMOVQ AX,K0", []byte{0xc4, 0xe1, 0xfb, 0x92, 0xc0}},
		{"KMOVQ K0,AX", []byte{0xc4, 0xe1, 0xfb, 0x93, 0xc0}},
		{"KMOVQ AX,K1", []byte{0xc4, 0xe1, 0xfb, 0x92, 0xc8}},
		{"KMOVQ K0,K1", []byte{0xc4, 0xe1, 0xf8, 0x90, 0xc8}},
	}
	var named, declarations strings.Builder
	count := 0
	for _, row := range x86KDataMode32ValueKernels {
		name := "Named" + row.name
		body := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s", name, row.frame, row.body)
		listing, err := x86ScalarLiteralGoListing(t, "386", body)
		if err != nil {
			t.Fatal(err)
		}
		for offset, instruction := range strings.Split(body, "\n") {
			for _, operation := range operations {
				if instruction == operation.instruction {
					fixture := x86OfficialPackedCase{symbol: name, line: 1 + offset,
						witness: goasmrules.X86PackedBinaryWitness{Instruction: instruction, Encoding: operation.code}}
					if err := x86OfficialPackedVerifyListing(listing, []x86OfficialPackedCase{fixture}); err != nil {
						t.Fatal(err)
					}
					count++
				}
			}
		}
		named.WriteString(body)
		for _, prefix := range []string{"Named", "Raw"} {
			fmt.Fprintf(&declarations, "func %s%s(a %s) %s\n", prefix, row.name, row.input, row.output)
		}
	}
	if count != 6 {
		t.Fatal("lost original GP/K operations", count)
	}
	raw := strings.ReplaceAll(named.String(), "Named", "Raw")
	for _, operation := range operations {
		if !strings.Contains(raw, operation.instruction+"\n") {
			t.Fatal("missing raw counterpart", operation.instruction)
		}
		raw = strings.ReplaceAll(raw, operation.instruction+"\n", x86RawDisplacementDirectives(operation.code))
	}
	source := named.String() + raw
	x86LEAActualTargetGoObject(t, "386", "i386-unknown-linux-gnu", source)
	return source, declarations.String()
}

func TestX86KDataMode32GPQPortableIntegerValues(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	source, declarations := x86KDataMode32ValueSource(t)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "386", execution.triple, api)
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
			for _, row := range x86KDataMode32ValueKernels {
				for _, prefix := range []string{"Named", "Raw"} {
					function := module.NamedFunction(prefix + row.name)
					if function.IsNil() || function.FirstBasicBlock().IsNil() || function.ParamsCount() != 1 ||
						function.Param(0).Type().TypeKind() != llvm.IntegerTypeKind || function.Param(0).Type().IntTypeWidth() != row.inputBits ||
						function.GlobalValueType().ReturnType().TypeKind() != llvm.IntegerTypeKind || function.GlobalValueType().ReturnType().IntTypeWidth() != row.outputBits {
						t.Fatal("portable C ABI differs from actual translated integer types", prefix, row.name)
					}
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
						text = x86DwordProductIROptimize(t, ir)
					}
					execution.compileAndRunLLVM(t, "kmov-mode32-portable", text, x86KDataMode32ValueDriver, pipeline.level)
				})
			}
		})
	}
	t.Log("source386 integer semantics executed via matching host C/LLVM widths; no native386/AVX512 execution or memory-fault claim")
}

const x86KDataMode32ValueDriver = `
#include <stdint.h>
#include <stdio.h>
#define DECLARE(prefix) \
    extern uint64_t prefix##From32(uint32_t); \
    extern uint32_t prefix##To32(uint64_t); \
    extern uint64_t prefix##From64Low(uint64_t); \
    extern uint64_t prefix##ThroughGP(uint64_t); \
    extern uint64_t prefix##Keep64(uint64_t)
DECLARE(Named);
DECLARE(Raw);
struct kernels {
    uint64_t (*from32)(uint32_t);
    uint32_t (*to32)(uint64_t);
    uint64_t (*from64)(uint64_t), (*through)(uint64_t), (*keep)(uint64_t);
};
static const struct kernels variants[] = {
    {NamedFrom32, NamedTo32, NamedFrom64Low, NamedThroughGP, NamedKeep64},
    {RawFrom32, RawTo32, RawFrom64Low, RawThroughGP, RawKeep64}
};
int main(void) {
    static const uint64_t values[] = {
        0, 1, UINT64_C(0x7fffffff), UINT64_C(0x80000000),
        UINT64_C(0xffffffff), UINT64_C(0x100000000),
        UINT64_C(0xffffffff00000000), UINT64_C(0x0123456789abcdef),
        UINT64_MAX, UINT64_C(0x8000000000000000),
        UINT64_C(0x7fffffffffffffff), UINT64_C(0x100000001)
    };
    for (unsigned variant = 0; variant < 2; ++variant) {
        struct kernels k = variants[variant];
        for (unsigned i = 0; i < sizeof(values)/sizeof(values[0]); ++i) {
            uint64_t a = values[i], low = (uint32_t)a;
            uint64_t from32 = k.from32((uint32_t)a);
            uint32_t to32 = k.to32(a);
            uint64_t from64 = k.from64(a), through = k.through(a), keep = k.keep(a);
            if (from32 != low || (uint64_t)to32 != low || from64 != low ||
                    through != low || keep != a) {
                fprintf(stderr, "variant=%u case=%u input=%llx from32=%llx "
                        "to32=%x from64=%llx through=%llx keep=%llx\n",
                        variant, i, (unsigned long long)a, (unsigned long long)from32,
                        to32, (unsigned long long)from64,
                        (unsigned long long)through, (unsigned long long)keep);
                return 1;
            }
        }
    }
    return 0;
}
`
