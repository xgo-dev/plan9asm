package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// This host-portable oracle covers the shared lowering axes, not physical x86
// ISA/FLAGS or legacy memory alignment. The original native family owners keep
// those independent obligations. Expected values do not use production specs.
func TestX86PackedBinaryPipelinePortableSemantics(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang required")
	}
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	for index, row := range []struct {
		instruction                         string
		width, bytes, mode, mask, broadcast int
		legacy, memory                      bool
	}{
		{"PSUBL X0,X2", 16, 4, 0, 0, 0, true, false},
		{"PSUBSB X0,X2", 16, 1, 1, 0, 0, true, false},
		{"VPSUBW Y0,Y1,Y2", 32, 2, 0, 0, 0, false, false},
		{"VPSUBQ.BCST.Z (DI),Z1,K1,Z2", 64, 8, 0, 2, 1, false, true},
		{"VPSUBSW (DI),Z1,K1,Z2", 64, 2, 1, 1, 0, false, true},
		{"VPSUBUSB.Z (DI),X1,K1,X2", 16, 1, 2, 2, 0, false, true},
		{"PMULLD X0,X2", 16, 4, 3, 0, 0, true, false},
		{"VPMULLD Y0,Y1,Y2", 32, 4, 3, 0, 0, false, false},
		{"VPMULLD.BCST.Z (DI),X1,K1,X2", 16, 4, 3, 2, 1, false, true},
		{"VPMULLQ (DI),Z1,K1,Z2", 64, 8, 3, 1, 0, false, true},
		{"PADDL X0,X2", 16, 4, 4, 0, 0, true, false},
		{"VPADDQ Y0,Y1,Y2", 32, 8, 4, 0, 0, false, false},
		{"VPADDSW (DI),Z1,K1,Z2", 64, 2, 5, 1, 0, false, true},
		{"VPADDUSB.Z (DI),X1,K1,X2", 16, 1, 6, 2, 0, false, true},
		{"VPADDD.BCST.Z (DI),Z1,K1,Z2", 64, 4, 4, 2, 1, false, true},
	} {
		name := fmt.Sprint("binary", index)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\n"+
			"MOVQ out+0(FP),DX\nMOVQ a+8(FP),DI\nMOVQ b+16(FP),SI\n"+
			"MOVQ mask+24(FP),AX\nKMOVQ AX,K1\n"+
			"VMOVUPS (SI),Z1\nVMOVUPS (SI),Z2\n", name)
		if !row.memory {
			source.WriteString("VMOVUPS (DI),Z0\n")
		}
		fmt.Fprintf(&source, "%s\nVMOVUPS Z2,(DX)\nRET\n", row.instruction)
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: I64, Index: 3, Field: -1},
			}}}
		fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", name)
		fmt.Fprintf(&checks, "if (check(%s,%q,%d,%d,%d,%d,%d,%d,%d)) return 1;\n",
			name, row.instruction, row.width, row.bytes, row.mode, row.mask,
			row.broadcast, x86FloatAddSubBoolInt(row.legacy), x86FloatAddSubBoolInt(row.memory))
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	main := x86PackedBinaryPipelineReference + declarations.String() +
		"int main(void) {\n" + checks.String() + "return 0;\n}\n"
	host := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	targets := []string{host}
	if host != "x86_64-unknown-linux-gnu" {
		targets = append(targets, "x86_64-unknown-linux-gnu")
	}
	for _, triple := range targets {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			if x86ScalarFloatIntegerNativeTarget("amd64", triple) || x86ScalarFloatIntegerNativeTarget("386", triple) {
				// Verify every function and reject native effects before removing
				// exactly its feature attribute. This numerical oracle must not
				// require AVX512 merely because its source uses Z registers.
				profiles := make(map[string]string, len(file.Funcs))
				for _, function := range file.Funcs {
					profiles[function.Sym] = inferFuncTargetFeaturesForGOARCH(ArchAMD64, "amd64", function)
				}
				ir, err = x86PackedShiftPortableFeatureProjection(ir, profiles)
				if err != nil {
					t.Fatal(err)
				}
			}
			x86ResultInitializationObject(t, llc, triple, ir, "packed-binary-portable")
			if triple != host {
				return // Cross object evidence, not cross execution.
			}
			for _, level := range []int{0, 2} {
				t.Run(fmt.Sprint("O", level), func(t *testing.T) {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "packed-binary",
						triple, ir, main, nil, level)
				})
			}
		})
	}
}

const x86PackedBinaryPipelineReference = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint64_t lane(const uint8_t *p, int bytes) {
    uint64_t value = 0;
    for (int i = 0; i < bytes; ++i) {
        value |= (uint64_t)p[i] << (8*i);
    }
    return value;
}

static uint64_t calculate(uint64_t a, uint64_t b, int bytes, int mode) {
    if (mode == 3) {
        return a*b;
    }
    if (mode == 4) {
        return a+b;
    }
    if (mode == 0) {
        return b-a;
    }
    if (mode == 2) {
        return b < a ? 0 : b-a;
    }
    if (mode == 6) {
        uint64_t max = (UINT64_C(1) << (bytes*8))-1;
        return a+b > max ? max : a+b;
    }

    int64_t sign = INT64_C(1) << (bytes*8-1);
    int64_t x = (a & sign) ? (int64_t)a - 2*sign : (int64_t)a;
    int64_t y = (b & sign) ? (int64_t)b - 2*sign : (int64_t)b;
    int64_t value = mode == 5 ? y+x : y-x;
    if (value < -sign) {
        return -sign;
    }
    if (value >= sign) {
        return sign-1;
    }
    return value;
}

static int check(void (*fn)(uint8_t*,const uint8_t*,const uint8_t*,uint64_t),
                 const char *name, int width, int bytes, int mode, int masking,
                 int broadcast, int legacy, int memory) {
    const uint64_t masks[] = {0, UINT64_MAX, 0x5555, UINT64_C(1)<<63};
    for (int sample = 0; sample < 32; ++sample) {
        uint8_t a[64], b[64], out[66], oldA[64], oldB[64];
        for (int i = 0; i < 64; ++i) {
            a[i] = (uint8_t)(sample*127 + i*53);
            b[i] = (uint8_t)(sample*17 - i*91);
        }
        if (sample < 4) {
            const uint8_t edgeA[] = {0xff, 0x80, 0x7f, 0x80};
            const uint8_t edgeB[] = {1, 0x7f, 0x7f, 0x80};
            memset(a, edgeA[sample], 64);
            memset(b, edgeB[sample], 64);
        }
        memcpy(oldA, a, 64);
        memcpy(oldB, b, 64);

        for (unsigned m = 0; m < sizeof(masks)/sizeof(masks[0]); ++m) {
            uint64_t mask = masks[m], relevant = UINT64_MAX >> (64-width/bytes);
            const uint8_t *input = memory && masking && !(mask & relevant) ? NULL : a;
            memset(out, 0xa7, sizeof(out));
            fn(out+1, input, b, mask);

            for (int offset = 0; offset < 64; ++offset) {
                uint8_t want = legacy ? b[offset] : 0;
                if (offset < width) {
                    int active = !masking || ((mask >> (offset/bytes)) & 1);
                    if (active) {
                        uint64_t first = lane(a+(broadcast ? 0 : offset/bytes*bytes), bytes);
                        uint64_t second = lane(b+offset/bytes*bytes, bytes);
                        uint64_t result = calculate(first, second, bytes, mode);
                        want = (uint8_t)(result >> (8*(offset%bytes)));
                    } else {
                        want = masking == 2 ? 0 : b[offset];
                    }
                }
                if (out[offset+1] != want) {
                    fprintf(stderr, "%s sample=%d mask=%llx byte=%d got=%x want=%x\n",
                            name, sample, (unsigned long long)mask, offset, out[offset+1], want);
                    return 1;
                }
            }
            if (out[0] != 0xa7 || out[65] != 0xa7 || memcmp(a, oldA, 64) || memcmp(b, oldB, 64)) {
                return 1;
            }
        }
    }
    return 0;
}
`
