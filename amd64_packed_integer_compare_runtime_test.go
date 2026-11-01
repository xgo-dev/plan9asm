package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Every input is initialized by this first-party fixture. Its declared pointer
// transport is not a caller-region or native-frame permission certificate.
func x86PackedIntegerCompareRuntimeFixture(rows []x86PackedIntegerCompareCase) (string, string, string) {
	var declarations, source, prototypes strings.Builder
	for index, row := range rows {
		name := fmt.Sprintf("compare%d", index)
		fmt.Fprintf(&declarations, "func %s(out,a,b *byte, mask uint64, csr uint32, flags uint64)\n", name)
		fmt.Fprintf(&prototypes, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint64_t,uint32_t,uint64_t);\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-48\nMOVQ out+0(FP),DI\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nMOVQ mask+24(FP),DX\nLDMXCSR csr+32(FP)\n", name)
		source.WriteString("VMOVUPS (BX),Z0\nVMOVUPS (CX),Z1\nVMOVUPS (CX),Z2\n")
		for mask := 0; mask < 8; mask++ {
			fmt.Fprintf(&source, "KMOVQ DX,K%d\n", mask)
		}
		// Seed the independently selected status before the physical MMX
		// region. No CFG or unrelated effect can split that region's state.
		source.WriteString("PUSHQ flags+40(FP)\nPOPFQ\n")
		if row.mmx {
			source.WriteString("MOVQ (BX),M0\nMOVQ (CX),M1\n")
		}
		fmt.Fprintf(&source, "%s %s\n", row.op, row.operands)
		if row.mmx {
			source.WriteString("MOVQ M1,400(DI)\nEMMS\n")
		} else {
			source.WriteString("MOVQ $0,400(DI)\n")
		}
		for bank := 0; bank < 3; bank++ {
			fmt.Fprintf(&source, "MOVOU X%d,%d(DI)\nVMOVUPS Y%d,%d(DI)\nVMOVUPS Z%d,%d(DI)\n", bank, bank*112, bank, bank*112+16, bank, bank*112+48)
		}
		for mask := 0; mask < 8; mask++ {
			fmt.Fprintf(&source, "KMOVQ K%d,%d(DI)\n", mask, 336+mask*8)
		}
		// Observe LAHF before masking the popped word: AND changes FLAGS.
		// The whole RFLAGS word includes undefined/unmodeled control bits;
		// only the six independently seeded status bits are numerical here.
		source.WriteString("LAHF\nMOVB AH,416(DI)\nPUSHFQ\nPOPQ DX\n" +
			"ANDQ $0x8d5,DX\nMOVQ DX,408(DI)\nSTMXCSR 417(DI)\nRET\n")
	}
	return declarations.String(), source.String(), prototypes.String()
}

const x86PackedIntegerCompareScalarOracle = `
static uint64_t compareLane(const uint8_t *p, int bytes) {
    uint64_t value = 0;
    for (int j = 0; j < bytes; ++j) {
        value |= (uint64_t)p[j] << (8*j);
    }
    return value;
}

static int compareValue(uint64_t first, uint64_t second, int bytes, int greater) {
    if (!greater) {
        return first == second;
    }
    uint64_t sign = UINT64_C(1) << (bytes*8-1);
    return (second ^ sign) > (first ^ sign);
}

__attribute__((noinline)) static int checkCompare(
    void (*fn)(uint8_t*,const uint8_t*,const uint8_t*,uint64_t,uint32_t,uint64_t),
    const char *name, int width, int bytes, int greater, int legacy, int mmx,
    int maskResult, int masked, int memory, int broadcast,
    int firstBank, int secondBank, int destination) {
    const uint64_t masks[] = {0,1,UINT64_C(0x55aa55aa55aa55aa),UINT64_MAX};
    for (int round = 0; round < 12; ++round) {
        for (int m = 0; m < 4; ++m) {
            _Alignas(64) uint8_t aStorage[96], bStorage[96], output[424];
            uint8_t *a = aStorage+16;
            uint8_t *b = bStorage+16;
            memset(aStorage,0xa7,sizeof(aStorage));
            memset(bStorage,0xb9,sizeof(bStorage));
            memset(output,0xc3,sizeof(output));
            for (int i = 0; i < 64; ++i) {
                a[i] = (uint8_t)(i*17+round*31);
                b[i] = (uint8_t)(i*23+round*53);
            }
            if (round < 4) {
                memset(a,round == 0 ? 0xff : round == 1 ? 0x80 : round == 2 ? 1 : 0,64);
                memset(b,round == 0 ? 1 : round == 1 ? 0x7f : round == 2 ? 0 : 0xff,64);
            }
            uint8_t originalA[96], originalB[96];
            memcpy(originalA,aStorage,96);
            memcpy(originalB,bStorage,96);
            uint64_t mask = masks[m];
            uint32_t saved, csr = 0x1f80 | ((round%4)<<13) | round, after;
            __asm__ volatile("stmxcsr %0" : "=m"(saved));
            __asm__ volatile("ldmxcsr %0" : : "m"(csr));
            uint64_t expectedFlags = (mask&3) == 0 ? 0 : (mask&3) == 1 ? 0x55 : 0x895;
            fn(output+1,a,b,mask,csr,2|expectedFlags);
            __asm__ volatile("stmxcsr %0" : "=m"(after));
            __asm__ volatile("ldmxcsr %0" : : "m"(saved));
            if (after != csr || compareLane(output+418,4) != csr ||
                compareLane(output+409,8) != expectedFlags || output[417] != (2|(expectedFlags&0xd5)) ||
                output[0] != 0xc3 || output[422] != 0xc3 || output[423] != 0xc3 ||
                memcmp(originalA,aStorage,96) || memcmp(originalB,bStorage,96)) {
                fprintf(stderr,"%s CSR/flags/full-input/output canary mismatch\n",name);
                return 1;
            }
            uint8_t expected[3][64];
            memcpy(expected[0],a,64);
            memcpy(expected[1],b,64);
            memcpy(expected[2],b,64);
            const uint8_t *first = memory || firstBank == 0 ? a : b;
            const uint8_t *second = secondBank == 0 ? a : b;
            uint64_t resultMask = 0;
            uint8_t result[64] = {0};
            for (int i = 0; i < width; i += bytes) {
                int selected = compareValue(compareLane(first+(broadcast ? 0 : i),bytes),
                                            compareLane(second+i,bytes),bytes,greater);
                if (selected && (!masked || ((mask>>(i/bytes))&1))) {
                    resultMask |= UINT64_C(1) << (i/bytes);
                }
                memset(result+i,selected ? 0xff : 0,bytes);
            }
            if (!maskResult && !mmx) {
                memcpy(expected[destination],result,width);
                if (!legacy) {
                    memset(expected[destination]+width,0,64-width);
                }
            }
            for (int bank = 0; bank < 3; ++bank) {
                for (int view = 0; view < 3; ++view) {
                    int offset = bank*112+(view == 0 ? 0 : view == 1 ? 16 : 48);
                    int length = view == 0 ? 16 : view == 1 ? 32 : 64;
                    if (memcmp(output+1+offset,expected[bank],length)) {
                        fprintf(stderr,"%s round%d mask%llx bank%d view%d mismatch\n",
                                name,round,(unsigned long long)mask,bank,view);
                        return 1;
                    }
                }
            }
            for (int k = 0; k < 8; ++k) {
                uint64_t want = maskResult && k == destination ? resultMask : mask;
                if (compareLane(output+337+k*8,8) != want) {
                    fprintf(stderr,"%s K%d mismatch\n",name,k);
                    return 1;
                }
            }
            for (int i = 0; i < 8; ++i) {
                if (output[401+i] != (mmx ? result[i] : 0)) {
                    fprintf(stderr,"%s MMX bit-result mismatch\n",name);
                    return 1;
                }
            }
        }
    }
    return 0;
}
`

func TestX86PackedIntegerCompareStatusObserverThreeTargetObjects(t *testing.T) {
	rows := []x86PackedIntegerCompareCase{{
		op: "PCMPEQB", operands: "X0,X1", width: 16, bits: 8, legacy: true,
	}}
	for index, op := range []string{"PCMPEQB", "PCMPEQW", "PCMPEQL", "PCMPGTB", "PCMPGTW", "PCMPGTL"} {
		for _, operands := range []string{"M0,M1", "M1,M1", "(BX),M1"} {
			rows = append(rows, x86PackedIntegerCompareCase{
				op: op, operands: operands, width: 8, bits: 8 << uint(index%3), legacy: true, mmx: true,
			})
		}
	}
	declarations, source, _ := x86PackedIntegerCompareRuntimeFixture(rows)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
				if err != nil || ir == "" {
					t.Fatal("defined-status observer lost complete source effects", api, err)
				}
				for _, text := range []string{ir, x86MulDivRoundOptimize(t, ir)} {
					x86PackedStringCompileObject(t, llc, triple, text, "-O0")
					x86PackedStringCompileObject(t, llc, triple, text, "-O2")
				}
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixX86PackedIntegerCompareCompleteScalarSemantics(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	rows := x86PackedIntegerCompareCases("amd64")
	declarations, source, prototypes := x86PackedIntegerCompareRuntimeFixture(rows)
	x86LEAActualTargetGoObject(t, "amd64", triple, source)
	ir, err := x86PackedIntegerCompareAPI(t, source, declarations, "amd64", triple, "Go")
	if err != nil {
		t.Fatal(err)
	}
	var checks strings.Builder
	for index, row := range rows {
		maskResult := !row.legacy && strings.Contains(row.operands, "K")
		fmt.Fprintf(&checks, "    if (checkCompare(compare%d,\"compare%d\",%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d)) return 1;\n",
			index, index, row.width, row.bits/8, x86FloatAddSubBoolInt(strings.Contains(row.op, "GT")),
			x86FloatAddSubBoolInt(row.legacy), x86FloatAddSubBoolInt(row.mmx), x86FloatAddSubBoolInt(maskResult),
			x86FloatAddSubBoolInt(row.mask), x86FloatAddSubBoolInt(row.memory), x86FloatAddSubBoolInt(row.broadcast),
			row.first, row.second, row.destination)
	}
	program := "#include <stdint.h>\n#include <string.h>\n#include <stdio.h>\n" +
		"#if !defined(_WIN32)\n#include <sys/resource.h>\n#endif\n" +
		prototypes + x86PackedIntegerCompareScalarOracle + "\nint main(void) {\n" +
		"#if !defined(_WIN32)\n    struct rlimit noCore = {0,0};\n    if (setrlimit(RLIMIT_CORE,&noCore)) return 3;\n#endif\n" +
		checks.String() + "    return 0;\n}\n"
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "packed-integer-compare", triple, text, program, prefix)
		})
	}
	t.Logf("%d forms ×48 independent signed/equal/mask/full-bank/full flags/CSR/input+output canaries at O0/O2; portable VEX/EVEX, not native AVX512", len(rows))
}
