package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Portable LLVM execution checks all bytes, aliases, masks and FLAGS/CSR.
// It is not a claim of executing original AVX512 instructions on this host.
func TestCrossLinuxRuntimeMatrixX86VectorArithmeticResultAliases(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	for _, width := range []int{16, 32, 64} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			var source, declarations, reference, checks strings.Builder
			reference.WriteString("#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n#include <xmmintrin.h>\n")
			reference.WriteString(x86LegacyIntegerArithmeticCMath)
			reference.WriteString(x86VectorArithmeticResultReference)
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			count := 0
			for index, op := range x86ResultVectorArithmeticNames {
				mode := 0
				if index%8 >= 4 {
					mode = 1
					if index%8 >= 6 {
						mode = 2
					}
				}
				for masking := 0; masking < 3; masking++ {
					name := fmt.Sprint("VectorArithmetic", count)
					count++
					row := op.name
					if masking == 2 {
						row += ".Z"
					}
					row += " " + bank + "0," + bank + "1"
					if masking != 0 {
						row += ",K1"
					}
					// Independent, source-one alias and source-two alias.
					destination := (masking + 2) % 3
					row += fmt.Sprintf(",%s%d", bank, destination)
					fmt.Fprintf(&declarations, "func %s(out *[66]byte,a,b *[64]byte,mask uint64)\n", name)
					fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-32\n", name)
					source.WriteString("MOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nMOVQ mask+24(FP),DX\n")
					source.WriteString("VMOVUPS (BX),Z0\nVMOVUPS (CX),Z1\nVMOVUPS (CX),Z2\nKMOVQ DX,K1\nCMPQ AX,AX\nSTC\n")
					fmt.Fprintf(&source, "%s\nVMOVUPS Z%d,(AX)\nSETCS 64(AX)\nSETNE 65(AX)\nRET\n", row, destination)
					fmt.Fprintf(&reference, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", name)
					fmt.Fprintf(&checks, "    if (checkVectorArithmetic(%s,%q,%d,%d,%d,%d,%d,%d)) return 1;\n", name, row, width, op.bits/8, mode, index/8, masking, destination)
				}
			}
			if count != 48 || count > 64 {
				t.Fatal("incomplete or oversized runtime batch", count)
			}
			reference.WriteString("int main(void) {\n" + checks.String() + "    return 0;\n}\n")
			goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
					if err != nil {
						t.Fatal(err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						t.Run(level, func(t *testing.T) {
							execution.compileAndRunLLVM(t, "vector-arithmetic", ir, reference.String(), level)
						})
					}
				})
			}
			t.Log("48 kernels × 80 inputs × four masks; every output/alias byte, input and flag canaries")
		})
	}
}

const x86VectorArithmeticResultReference = `
typedef void (*vectorArithmetic)(uint8_t*, const uint8_t*, const uint8_t*, uint64_t);

static int checkVectorArithmetic(vectorArithmetic fn, const char *name,
                                 int width, int bytes, int mode, int subtract,
                                 int masking, int destination) {
    const uint64_t masks[] = {0, UINT64_MAX, UINT64_C(0x5555555555555555), UINT64_C(1) << 63};
    for (int sample = 0; sample < 80; ++sample) {
        uint8_t a[64], b[64], originalA[64], originalB[64], out[68];
        for (int block = 0; block < 4; ++block) {
            fill(a + block * 16, bytes, sample + block, 0);
            fill(b + block * 16, bytes, sample + block, 1);
        }
        memcpy(originalA, a, sizeof(a));
        memcpy(originalB, b, sizeof(b));
        for (unsigned m = 0; m < sizeof(masks) / sizeof(masks[0]); ++m) {
            uint64_t mask = masks[m];
            uint32_t before = _mm_getcsr();
            memset(out, 0xa7, sizeof(out));
            fn(out + 1, a, b, mask);
            if (_mm_getcsr() != before || out[0] != 0xa7 || out[67] != 0xa7 ||
                out[65] != 1 || out[66] != 0 ||
                memcmp(a, originalA, sizeof(a)) || memcmp(b, originalB, sizeof(b))) {
                fprintf(stderr, "%s state/input/canary mismatch\n", name);
                return 1;
            }
            for (int i = 0; i < 64; ++i) {
                uint8_t want = 0;
                if (i < width) {
                    int index = i / bytes;
                    if (!masking || ((mask >> index) & 1)) {
                        uint64_t x = lane(a + index * bytes, bytes);
                        uint64_t y = lane(b + index * bytes, bytes);
                        want = (uint8_t)(math(x, y, bytes, mode, subtract) >> (8 * (i % bytes)));
                    } else if (masking == 1) {
                        want = destination == 0 ? a[i] : b[i];
                    }
                }
                if (out[i + 1] != want) {
                    fprintf(stderr, "%s sample=%d mask=%llx byte=%d got=%x want=%x\n",
                            name, sample, (unsigned long long)mask, i, out[i + 1], want);
                    return 1;
                }
            }
        }
    }
    return 0;
}
`
