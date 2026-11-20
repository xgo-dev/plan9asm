package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

const x86LowMultiplyReference = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>

typedef void (*kernel)(uint8_t *, const uint8_t *, const uint8_t *,
                       uint64_t *, uint32_t *, uint64_t, uint64_t);

static uint64_t little(const uint8_t *p, int bytes) {
    uint64_t value = 0;
    for (int i = 0; i < bytes; ++i) {
        value |= (uint64_t)p[i] << (8 * i);
    }
    return value;
}

static int check(kernel fn, const char *name, int width, int bytes,
                 int legacy, int masking, int broadcast, int memory, int dst) {
    _Alignas(64) uint8_t a[64], b[64], out[192], oldA[64], oldB[64];
    const uint64_t masks[] = {0, UINT64_MAX, 0x5555, UINT64_C(1) << 63};
    for (int sample = 0; sample < 65; ++sample) {
        for (int i = 0; i < 64; ++i) {
            a[i] = (uint8_t)(sample * 127 + i * 53);
            b[i] = (uint8_t)(sample * 17 - i * 91);
        }
        memcpy(oldA, a, 64);
        memcpy(oldB, b, 64);
        for (int seedIndex = 0; seedIndex < 2; ++seedIndex) {
            uint64_t seed = seedIndex ? 0x8d5 : 0;
            for (unsigned mi = 0; mi < sizeof(masks)/sizeof(masks[0]); ++mi) {
                uint64_t mask = masks[mi];
                uint64_t relevant = mask & ((UINT64_C(1) << (width / bytes)) - 1);
                const uint8_t *input = memory && masking && !relevant ? NULL : a;
                struct { uint64_t before, value, after; } flags = {11, 0, 13};
                struct { uint32_t before, value, after; } csr = {17, 0, 19};
                uint32_t initialCSR = _mm_getcsr();
                memset(out, 0xa7, sizeof(out));
                fn(out + 64, input, b, &flags.value, &csr.value, seed, mask);
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
                            int lane = offset / bytes;
                            int active = !masking || ((mask >> lane) & 1);
                            if (active) {
                                uint64_t x = little(a + (broadcast ? 0 : lane * bytes), bytes);
                                uint64_t y = little(b + lane * bytes, bytes);
                                want = (uint8_t)((x * y) >> (8 * (offset % bytes)));
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

// This executes the portable LLVM result, not original AVX512 machine code.
// Independent full-byte observations catch stale upper aliases and merging;
// NULL with inactive/high-only masks catches eager E4 memory accesses.
func TestCrossLinuxRuntimeMatrixX86PackedLowMultiplySoftware(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	for _, destination := range []int{0, 1} {
		t.Run(fmt.Sprint("destination-", destination), func(t *testing.T) {
			var declarations, assembly, reference, checks strings.Builder
			declarations.WriteString("package oracle\n")
			reference.WriteString(x86LowMultiplyReference)
			count := 0
			for _, name := range []string{"PMULLD", "VPMULLD", "VPMULLQ"} {
				legacy, bits := 0, 32
				widths := []int{16, 32, 64}
				if name == "PMULLD" {
					legacy, widths = 1, []int{16}
				}
				if name == "VPMULLQ" {
					bits = 64
				}
				for _, width := range widths {
					bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
					for source := 0; source < 3; source++ {
						for masking := 0; masking < 3; masking++ {
							if legacy != 0 && (masking != 0 || source == 2 || destination == 0) {
								continue
							}
							fn := fmt.Sprint("Low", count)
							count++
							row, first, broadcast, memory := name, bank+"0", 0, 0
							if source != 0 {
								first, memory = "(DI)", 1
							}
							if source == 2 {
								row, broadcast = row+".BCST", 1
							}
							if masking == 2 {
								row += ".Z"
							}
							row += " " + first + "," + bank + "1"
							if masking != 0 {
								row += ",K1"
							}
							if legacy == 0 {
								row += fmt.Sprintf(",%s%d", bank, destination)
							}
							fmt.Fprintf(&declarations, "func %s(out,a,b *[64]byte,flags *uint64,csr *uint32,seed,mask uint64)\n", fn)
							fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-56\nMOVQ out+0(FP),DX\nMOVQ a+8(FP),DI\nMOVQ b+16(FP),SI\nMOVQ flags+24(FP),CX\nMOVQ csr+32(FP),BX\nVMOVUPS (SI),Z1\n", fn)
							if source == 0 || destination == 0 {
								// For memory forms Z0's merge source uses B; do not
								// read the possibly inactive source address early.
								base := "DI"
								if source != 0 {
									base = "SI"
								}
								fmt.Fprintf(&assembly, "VMOVUPS (%s),Z0\n", base)
							}
							assembly.WriteString("MOVQ mask+48(FP),AX\nKMOVQ AX,K1\nPUSHQ seed+40(FP)\nPOPFQ\n")
							fmt.Fprintf(&assembly, "%s\nVMOVUPS Z%d,(DX)\nPUSHFQ\nPOPQ AX\nMOVQ AX,(CX)\nSTMXCSR (BX)\nRET\n", row, destination)
							fmt.Fprintf(&reference, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint64_t*,uint32_t*,uint64_t,uint64_t);\n", fn)
							old := destination
							if memory != 0 {
								old = 1
							}
							fmt.Fprintf(&checks, "    if (check(%s,%q,%d,%d,%d,%d,%d,%d,%d)) return 1;\n", fn, row, width, bits/8, legacy, masking, broadcast, memory, old)
						}
					}
				}
			}
			if count > 96 {
				t.Fatal("runtime batch exceeds its resource bound", count)
			}
			reference.WriteString("int main(void) {\n" + checks.String() + "    return 0;\n}\n")
			goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
			pkg := mustGoPackage(t, "oracle", declarations.String())
			file, err := Parse(ArchAMD64, assembly.String())
			if err != nil {
				t.Fatal(err)
			}
			sigs := map[string]FuncSig{}
			for _, fn := range file.Funcs {
				name := strings.TrimPrefix(fn.Sym, "·")
				sigs[name] = x86WordMultiplySignature(t, pkg, name)
			}
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple,
				Sigs: sigs, ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }})
			if err != nil {
				t.Fatal(err)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					execution.compileAndRunLLVM(t, "low-multiply", ir, reference.String(), level)
				})
			}
			t.Logf("%d kernels, 65 inputs, two FLAGS seeds, four masks; full aliases, canaries and inactive NULL sources", count)
		})
	}
}
