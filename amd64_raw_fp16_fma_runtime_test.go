package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Execute the portable IR on the host, without requiring an AVX512-FP16
// CPU. Separate object tests check the actual x86 features and every target.
func TestRawFP16FMAPortableRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source, declarations, cases strings.Builder
	sigs := make(map[string]FuncSig)
	ops := rawFP16FMAOps()
	for _, opcode := range x86FMA3Opcodes() {
		op := ops[opcode]
		scalar := strings.HasSuffix(string(op), "SH")
		lengths := []byte{1}
		if scalar {
			lengths = []byte{0}
		} else if opcode == 0x98 {
			lengths = []byte{0, 1, 2}
		}
		for _, length := range lengths {
			for _, zero := range []bool{false, true} {
				for _, broadcast := range []bool{false, true} {
					if broadcast && (scalar || opcode != 0x98) {
						continue
					}
					name := fmt.Sprintf("halfFMA_%x_%d_%t_%t", opcode, length, zero, broadcast)
					fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\n", name)
					source.WriteString("MOVQ input+0(FP), DI\nMOVQ memory+8(FP), AX\nMOVQ out+16(FP), SI\nMOVQ mask+24(FP), CX\n")
					source.WriteString("KMOVQ CX, K1\nVMOVDQU64 (DI), Z0\nVMOVDQU64 64(DI), Z1\n")
					code := encodeRawFP16FMA(opcode, length, 1, 0, 0, 1, true, broadcast, zero)
					code[len(code)-1] = 0
					for _, value := range code {
						fmt.Fprintf(&source, "BYTE $0x%02x\n", value)
					}
					source.WriteString("VMOVDQU64 Z0, (SI)\nRET\n")
					sigs[name] = FuncSig{
						Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void,
						Attrs: "nounwind", // Suppress x86-only inference for this portable oracle.
						Frame: FrameLayout{Params: []FrameSlot{
							{Offset: 0, Type: Ptr, Index: 0, Field: -1},
							{Offset: 8, Type: Ptr, Index: 1, Field: -1},
							{Offset: 16, Type: Ptr, Index: 2, Field: -1},
							{Offset: 24, Type: I64, Index: 3, Field: -1},
						}},
					}
					order := []int{132, 213, 231}[(opcode>>4)-9]
					mode := int(opcode&15) - 8
					if mode < 0 {
						mode += 6 // 6/7 are alternating subtract-even/subtract-odd.
					} else {
						mode /= 2
					}
					lanes := 8 << length
					if scalar {
						lanes = 1
					}
					flag := func(value bool) int {
						if value {
							return 1
						}
						return 0
					}
					fmt.Fprintf(&declarations, "extern void %s(const void *, const void *, void *, uint64_t);\n", name)
					fmt.Fprintf(&cases, "  {%s, %d, %d, %d, %d, %d, %d},\n", name, order, mode, lanes, flag(scalar), flag(zero), flag(broadcast))
				}
			}
		}
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: testTargetTriple(runtime.GOOS, runtime.GOARCH), Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	mainC := "#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n#include <string.h>\n" + declarations.String() + x86TestGuardPagesC + `
typedef void (*operation)(const void *, const void *, void *, uint64_t);
struct test_case { operation run; int order, mode, lanes, scalar, zero, broadcast; };
static struct test_case cases[] = {
` + cases.String() + `};

// These operands and their exact products/sums fit in binary64. Round only
// once to FP16, independently of the translator's half-precision FMA.
static double from_half(uint16_t bits) {
    _Float16 value;
    memcpy(&value, &bits, 2);
    return value;
}

static uint16_t to_half(double value) {
    _Float16 result = (_Float16)value;
    uint16_t bits;
    memcpy(&bits, &result, 2);
    return bits;
}

int main(void) {
    if (setup_guard()) return 1;
    uint16_t input[64], memory[32], output[32];
    for (int lane = 0; lane < 32; lane++) {
        input[lane] = 0x3c01;       // 1 + 2^-10
        input[32 + lane] = 0xbc00;  // -1
        memory[lane] = 0x3bfe;      // 1 - 2^-10
    }
    const uint64_t masks[] = {0, 1, 0xaaaaaaaa, 0xffffffff, UINT64_C(1) << 60};
    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        struct test_case test = cases[index];
        for (size_t mi = 0; mi < sizeof(masks) / sizeof(masks[0]); mi++) {
            uint64_t mask = masks[mi];
            const void *pointer = memory;
            if ((mask & ((UINT64_C(1) << test.lanes) - 1)) == 0) pointer = NULL;
            if (mask == 1) {
                memcpy(guard + page - 3, memory, 2);
                pointer = guard + page - 3;
            }
            memset(output, 0xcc, sizeof(output));
            test.run(input, pointer, output, mask);
            for (int lane = 0; lane < 32; lane++) {
                uint16_t expected = 0;
                if (lane < test.lanes && (mask & (UINT64_C(1) << lane))) {
                    double d = from_half(input[lane]);
                    double s = from_half(input[32 + lane]);
                    double m = from_half(memory[test.broadcast ? 0 : lane]);
                    double a = d, b = m, c = s;
                    if (test.order == 213) { a = s; b = d; c = m; }
                    if (test.order == 231) { a = s; b = m; c = d; }
                    if (test.mode == 2 || test.mode == 3) a = -a;
                    if (test.mode == 1 || test.mode == 3 ||
                        (test.mode == 4 && lane % 2 == 0) ||
                        (test.mode == 5 && lane % 2 != 0)) c = -c;
                    expected = to_half(a * b + c);
                } else if (lane < test.lanes && !test.zero) {
                    expected = input[lane];
                } else if (test.scalar && lane < 8 && lane != 0) {
                    expected = input[lane];
                }
                if (output[lane] != expected) {
                    fprintf(stderr, "case %zu order %d mode %d mask %llx lane %d: %04x != %04x\n",
                            index, test.order, test.mode, (unsigned long long)mask, lane, output[lane], expected);
                    return 2;
                }
            }
        }
    }
    return free_guard();
}
`
	compileAndRunRuntimeTest(t, llc, clang, "fp16_fma_portable", ir, mainC)
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable() {
		const triple = "x86_64-apple-macosx"
		x86IR, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
		if err != nil {
			t.Fatal(err)
		}
		compileAndRunRuntimeTestForTarget(t, llc, clang, "fp16_fma_portable_x86", triple, x86IR, mainC, []string{"/usr/bin/arch", "-x86_64"})
	}
}
