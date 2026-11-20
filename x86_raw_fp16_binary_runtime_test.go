package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Execute portable values separately from native opcode/MXCSR qualification.
// Independent raw-bit references retain MIN/MAX's second-source NaNs and zeros.
func TestX86RawFP16BinaryPortableValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	var source, declarations, cases strings.Builder
	sigs := make(map[string]FuncSig)
	for mode, opcode := range []byte{0x58, 0x5c, 0x59, 0x5e, 0x5d, 0x5f} {
		for _, scalar := range []bool{false, true} {
			for length := byte(0); length < 3; length++ {
				if scalar && length != 0 {
					continue
				}
				for _, broadcast := range []bool{false, true} {
					if scalar && broadcast {
						continue
					}
					for mask := 1; mask <= 2; mask++ {
						name := fmt.Sprintf("binary%d", len(sigs))
						fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\n", name)
						source.WriteString("MOVQ input+0(FP),DI\nMOVQ memory+8(FP),AX\nMOVQ out+16(FP),SI\nMOVQ mask+24(FP),CX\n")
						source.WriteString("KMOVQ CX,K1\nVMOVDQU64 (DI),Z0\nVMOVDQU64 64(DI),Z2\n")
						code := x86FP16BinaryResultEncoding(opcode, length, scalar, true, broadcast, mask)
						source.WriteString(x86RawDisplacementDirectives(code))
						source.WriteString("VMOVDQU64 Z0,(SI)\nRET\n")
						sigs[name] = FuncSig{
							Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Attrs: "nounwind",
							Frame: FrameLayout{Params: []FrameSlot{
								{Offset: 0, Type: Ptr, Index: 0, Field: -1},
								{Offset: 8, Type: Ptr, Index: 1, Field: -1},
								{Offset: 16, Type: Ptr, Index: 2, Field: -1},
								{Offset: 24, Type: I64, Index: 3, Field: -1},
							}},
						}
						lanes, scalarFlag, broadcastFlag := 8<<length, 0, 0
						if scalar {
							lanes, scalarFlag = 1, 1
						}
						if broadcast {
							broadcastFlag = 1
						}
						fmt.Fprintf(&declarations, "extern void %s(const void *, const void *, void *, uint64_t);\n", name)
						fmt.Fprintf(&cases, "{%s,%d,%d,%d,%d,%d},\n", name, mode, lanes, scalarFlag, broadcastFlag, mask-1)
					}
				}
			}
		}
	}
	if len(sigs) != 84 {
		t.Fatal("incomplete portable binary value inventory", len(sigs))
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir := x86FP16NumericalModelIR(t, file, sigs, testTargetTriple(runtime.GOOS, runtime.GOARCH))
	mainC := "#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n#include <string.h>\n" + declarations.String() + x86TestGuardPagesC + `
typedef void (*operation)(const void *, const void *, void *, uint64_t);
struct binary_case { operation run; int mode, lanes, scalar, broadcast, zero; };
static const struct binary_case cases[] = {
` + cases.String() + `};

static int half_nan(uint16_t bits) {
    return (bits & 0x7c00) == 0x7c00 && (bits & 0x03ff) != 0;
}

static double from_half(uint16_t bits) {
    _Float16 value;
    memcpy(&value, &bits, 2);
    return value;
}

static uint16_t reference(int mode, uint16_t left, uint16_t right) {
    if (mode >= 4 && (half_nan(left) || half_nan(right))) return right;
    double a = from_half(left), b = from_half(right);
    if (mode == 4) return a < b ? left : right;
    if (mode == 5) return a > b ? left : right;
    double value = mode == 0 ? a+b : mode == 1 ? a-b : mode == 2 ? a*b : a/b;
    _Float16 result = (_Float16)value;
    uint16_t bits;
    memcpy(&bits, &result, 2);
    return bits;
}

int main(void) {
    if (setup_guard()) return 1;
    const uint16_t left[]  = {0x3c00,0x4000,0xbc00,0x4400,1,0x8000,0,0x7bff};
    const uint16_t right[] = {0x4000,0x3c00,0x4000,0x3800,0x3c00,0,0x8000,0x3800};
    const uint64_t masks[] = {0,1,0xaaaaaaaa,0xffff0000,0x80000000,0xffffffff,UINT64_C(1)<<60};
    uint16_t input[64], memory[32], output[34];
    for (size_t ci = 0; ci < sizeof(cases)/sizeof(cases[0]); ci++) {
        struct binary_case test = cases[ci];
        for (int scenario = 0; scenario < 8; scenario++) {
            for (int lane = 0; lane < 32; lane++) {
                input[lane] = (uint16_t)(0x1000+lane);
                input[32+lane] = left[(scenario+lane)%8];
                memory[lane] = right[(scenario+lane)%8];
                if (test.mode >= 4 && scenario >= 4) {
                    if (scenario & 1) input[32+lane] = 0x7d11;
                    if (scenario & 2) memory[lane] = 0x7e35;
                }
            }
            for (size_t mi = 0; mi < sizeof(masks)/sizeof(masks[0]); mi++) {
                uint64_t mask = masks[mi];
                const void *pointer = memory;
                if ((mask & ((UINT64_C(1)<<test.lanes)-1)) == 0) pointer = NULL;
                if (mask == 1) {
                    memcpy(guard+page-3,memory,2);
                    pointer = guard+page-3;
                }
                memset(output,0xcc,sizeof(output));
                test.run(input,pointer,output+1,mask);
                if (output[0] != 0xcccc || output[33] != 0xcccc) return 3;
                for (int lane = 0; lane < 32; lane++) {
                    uint16_t want = 0;
                    int active = lane < test.lanes && ((mask>>lane)&1);
                    if (active) want = reference(test.mode,input[32+lane],memory[test.broadcast?0:lane]);
                    else if (lane < test.lanes && !test.zero) want = input[lane];
                    else if (test.scalar && lane > 0 && lane < 8) want = input[32+lane];
                    uint16_t got = output[lane+1];
                    if (test.mode < 4 && active && half_nan(want) && half_nan(got)) continue;
                    if (got != want) {
                        fprintf(stderr,"case %zu scenario %d mask %llx lane %d: %04x != %04x\n",
                            ci,scenario,(unsigned long long)mask,lane,got,want);
                        return 2;
                    }
                }
            }
        }
    }
    return free_guard();
}
`
	compileAndRunRuntimeTest(t, llc, clang, "fp16_binary_values", ir, mainC)
}
