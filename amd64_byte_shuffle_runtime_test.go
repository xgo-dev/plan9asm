package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// This observes portable LLVM semantics, not execution of original AVX512.
// Every output byte, including wider aliases and surrounding canaries, is
// compared with an independent scalar reference over all 256 control values.
func TestCrossLinuxRuntimeMatrixX86ByteShuffleSoftware(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var source, declarations, reference, checks strings.Builder
	reference.WriteString(x86ByteShuffleReference)
	count := 0
	for _, width := range []int{16, 32, 64} {
		bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
		for legacy := 0; legacy < 2; legacy++ {
			for memory := 0; memory < 2; memory++ {
				for mask := 0; mask < 3; mask++ {
					for dst := 0; dst < 3; dst++ {
						if legacy != 0 && (width != 16 || mask != 0 || dst != 1) {
							continue
						}
						name := fmt.Sprint("Shuffle", count)
						count++
						row, control := "VPSHUFB", bank+"0"
						if legacy != 0 {
							row = "PSHUFB"
						}
						if memory != 0 {
							control = "(DI)"
						}
						if mask == 2 {
							row += ".Z"
						}
						row += " " + control + "," + bank + "1"
						if mask != 0 {
							row += ",K1"
						}
						if legacy == 0 {
							row += fmt.Sprintf(",%s%d", bank, dst)
						}
						fmt.Fprintf(&declarations, "func %s(out,a,b *[64]byte,flags *uint64,csr *uint32,seed,mask uint64)\n", name)
						fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-56\nMOVQ out+0(FP),DX\nMOVQ a+8(FP),DI\nMOVQ b+16(FP),SI\nMOVQ flags+24(FP),CX\nMOVQ csr+32(FP),BX\n", name)
						source.WriteString("VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (SI),Z2\nMOVQ mask+48(FP),AX\nKMOVQ AX,K1\nPUSHQ seed+40(FP)\nPOPFQ\n")
						fmt.Fprintf(&source, "%s\nVMOVUPS Z%d,(DX)\nPUSHFQ\nPOPQ AX\nMOVQ AX,(CX)\nSTMXCSR (BX)\nRET\n", row, dst)
						fmt.Fprintf(&reference, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint64_t*,uint32_t*,uint64_t,uint64_t);\n", name)
						fmt.Fprintf(&checks, "    if (check(%s,%q,%d,%d,%d,%d)) return 1;\n", name, row, width, legacy, mask, dst)
					}
				}
			}
		}
	}
	if count != 56 || count > 64 {
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
					execution.compileAndRunLLVM(t, "byte-shuffle", ir, reference.String(), level)
				})
			}
		})
	}
}

const x86ByteShuffleReference = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>

typedef void (*kernel)(uint8_t *, const uint8_t *, const uint8_t *,
                       uint64_t *, uint32_t *, uint64_t, uint64_t);

static int check(kernel fn, const char *name, int width, int legacy,
                 int masking, int dst) {
    _Alignas(64) uint8_t a[64], b[64], out[192], oldA[64], oldB[64];
    const uint64_t masks[] = {0, UINT64_MAX, UINT64_C(0x5555555555555555), UINT64_C(1) << 63};
    for (int sample = 0; sample < 256; ++sample) {
        for (int i = 0; i < 64; ++i) {
            a[i] = (uint8_t)(sample + i * 53);
            b[i] = (uint8_t)(sample * 17 - i * 91);
        }
        memcpy(oldA, a, 64);
        memcpy(oldB, b, 64);
        for (int seedIndex = 0; seedIndex < 2; ++seedIndex) {
            uint64_t seed = seedIndex ? 0x8d5 : 0;
            for (unsigned mi = 0; mi < sizeof(masks)/sizeof(masks[0]); ++mi) {
                uint64_t mask = masks[mi];
                struct { uint64_t before, value, after; } flags = {11, 0, 13};
                struct { uint32_t before, value, after; } csr = {17, 0, 19};
                uint32_t initialCSR = _mm_getcsr();
                memset(out, 0xa7, sizeof(out));
                fn(out + 64, a, b, &flags.value, &csr.value, seed, mask);
                if ((flags.value & 0x8d5) != seed || flags.before != 11 || flags.after != 13 ||
                    csr.value != initialCSR || csr.before != 17 || csr.after != 19 ||
                    memcmp(a, oldA, 64) || memcmp(b, oldB, 64)) {
                    fprintf(stderr, "%s state/input/canary mismatch\n", name);
                    return 1;
                }
                for (int i = 0; i < 192; ++i) {
                    unsigned want = 0xa7;
                    int offset = i - 64;
                    if (offset >= 0 && offset < 64) {
                        const uint8_t *old = dst == 0 ? a : b;
                        want = legacy ? old[offset] : 0;
                        if (offset < width) {
                            if (!masking || ((mask >> offset) & 1)) {
                                want = a[offset] & 0x80 ? 0 : b[(offset / 16) * 16 + (a[offset] & 15)];
                            } else {
                                want = masking == 2 ? 0 : old[offset];
                            }
                        }
                    }
                    if (out[i] != want) {
                        fprintf(stderr, "%s sample=%d mask=%llx byte=%d got=%x want=%x\n",
                                name, sample, (unsigned long long)mask, i, out[i], want);
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}
`
