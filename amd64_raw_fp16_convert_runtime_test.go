package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestRawFP16ConversionPortableRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source, declarations, calls strings.Builder
	sigs := make(map[string]FuncSig)
	for _, narrow := range []bool{false, true} {
		for length := 0; length < 3; length++ {
			for _, broadcast := range []bool{false, true} {
				for _, zero := range []bool{false, true} {
					name := fmt.Sprintf("halfConversion_%t_%d_%t_%t", narrow, length, broadcast, zero)
					fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\n", name)
					source.WriteString("MOVQ input+0(FP), AX\nMOVQ out+8(FP), SI\nMOVQ old+16(FP), DI\nMOVQ mask+24(FP), CX\nKMOVQ CX, K1\nVMOVDQU64 (DI), Z0\n")
					code := rawFP16Conversion(narrow, length, 1, 0, 0, true, broadcast, zero)
					code[len(code)-1] = 0
					for _, b := range code {
						fmt.Fprintf(&source, "BYTE $0x%02x\n", b)
					}
					source.WriteString("VMOVDQU64 Z0, (SI)\nRET\n")
					sigs[name] = FuncSig{
						Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Attrs: "nounwind",
						Frame: FrameLayout{Params: []FrameSlot{
							{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
							{Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1},
						}},
					}
					fmt.Fprintf(&declarations, "extern void %s(const void *, void *, const void *, uint64_t);\n", name)
					input, output, bytes, total, inactive := "halves", "singles", 2, 16, "UINT32_C(0xa5a5a5a5)"
					if narrow {
						input, output, bytes, total, inactive = "singles", "halves", 4, 32, "0xa5a5"
					}
					if zero {
						inactive = "0"
					}
					index := "lane"
					if broadcast {
						index = "0"
					}
					fmt.Fprintf(&calls, `
    {
        const void *pointer = %s;
        if ((mask & ((UINT64_C(1) << %d) - 1)) == 0) pointer = NULL;
        if (mask == 1) {
            memcpy(guard + page - %d, %s, %d);
            pointer = guard + page - %d;
        }
        %s(pointer, &output, old, mask);
        for (int lane = 0; lane < %d; lane++) {
            uint32_t expected = lane < %d ? ((mask & (UINT64_C(1) << lane)) ? %s[%s] : %s) : 0;
            uint32_t actual = output.%s[lane];
            if (actual != expected) {
                fprintf(stderr, "%s mask %%llx lane %%d: %%08x != %%08x\n",
                        (unsigned long long)mask, lane, actual, expected);
                return 2;
            }
        }
    }
`, input, 4<<length, bytes+1, input, bytes, bytes+1, name, total, 4<<length, output, index, inactive, output, name)
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
int main(void) {
    if (setup_guard()) return 1;
    const uint16_t halves[16] = {
        0x3c00, 0x8000, 0, 0xbc00, 1, 0x03ff, 0x0400, 0x7bff,
        0x7c00, 0xfc00, 0x3555, 0xb555, 0x4000, 0xc000, 0x7e00, 0xfe00
    };
    const uint32_t singles[16] = {
        0x3f800000, 0x80000000, 0, 0xbf800000, 0x33800000, 0x387fc000, 0x38800000, 0x477fe000,
        0x7f800000, 0xff800000, 0x3eaaa000, 0xbeaaa000, 0x40000000, 0xc0000000, 0x7fc00000, 0xffc00000
    };
    unsigned char old[64];
    memset(old, 0xa5, sizeof(old));
    union { uint16_t halves[32]; uint32_t singles[16]; } output;
    const uint64_t masks[] = {0, 1, 0xffff, 0xaaaa, UINT64_C(1) << 60};
    for (int mi = 0; mi < 5; mi++) {
        uint64_t mask = masks[mi];
` + calls.String() + `
    }
    return free_guard();
}
`
	compileAndRunRuntimeTest(t, llc, clang, "fp16_conversion_portable", ir, mainC)
}

func TestRawFP16ConversionRoundingRuntime(t *testing.T) {
	runPackedHalfRoundingRuntime(t, false)
}

func TestPackedHalfConversionDirectedRoundingRuntime(t *testing.T) {
	runPackedHalfRoundingRuntime(t, true)
}

func runPackedHalfRoundingRuntime(t *testing.T, legacy bool) {
	t.Helper()
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source, declarations, calls strings.Builder
	sigs := make(map[string]FuncSig)
	for rounding := 0; rounding < 4; rounding++ {
		name := fmt.Sprintf("halfRound%d", rounding)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVQ input+0(FP), AX\nMOVQ out+8(FP), SI\nVMOVDQU64 (AX), Z1\n", name)
		if legacy {
			fmt.Fprintf(&source, "VCVTPS2PH $%d, Z1, Y0\n", rounding)
		} else {
			for _, b := range rawFP16Conversion(true, rounding, 0, 0, 1, false, true, false) {
				fmt.Fprintf(&source, "BYTE $0x%02x\n", b)
			}
		}
		source.WriteString("VMOVDQU64 Z0, (SI)\nRET\n")
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void, Attrs: "nounwind",
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}},
		}
		fmt.Fprintf(&declarations, "extern void %s(const void *, void *);\n", name)
		fmt.Fprintf(&calls, `
    %s(input, output);
    for (int lane = 0; lane < 32; lane++) {
        uint16_t want = lane < 16 ? expected[%d][lane %% 8] : 0;
        if (output[lane] != want) {
            fprintf(stderr, "%s lane %%d: %%04x != %%04x\n", lane, output[lane], want);
            return 1;
        }
    }
`, name, rounding, name)
	}
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: testTargetTriple(runtime.GOOS, runtime.GOARCH), Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	mainC := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + declarations.String() + `
static double half_value(unsigned bits) {
    unsigned exponent = bits >> 10;
    double value = bits & 1023;
    int power = -24;
    if (exponent) {
        value += 1024;
        power = (int)exponent - 25;
    }
    while (power < 0) { value *= 0.5; power++; }
    while (power > 0) { value *= 2; power--; }
    return value;
}

// Independent numeric oracle: bracket the float between adjacent positive
// half values by binary search, then choose a bound according to sign/mode.
static uint16_t reference(uint32_t bits, int mode) {
    unsigned sign = bits >> 31;
    bits &= 0x7fffffff;
    if (bits >= 0x7f800000) {
        unsigned payload = bits == 0x7f800000 ? 0 : ((bits >> 13) & 1023) | 512;
        return (uint16_t)((sign << 15) | 0x7c00 | payload);
    }
    float source;
    memcpy(&source, &bits, 4);
    double value = source;
    unsigned low = 0, high = 0x7bff;
    while (low < high) {
        unsigned mid = (low + high + 1) / 2;
        if (half_value(mid) <= value) low = mid;
        else high = mid - 1;
    }
    unsigned result = low;
    double bottom = half_value(low);
    if (value != bottom) {
        if (mode == 0) {
            double top = low == 0x7bff ? 65536.0 : half_value(low + 1);
            double midpoint = (bottom + top) * 0.5;
            if (value > midpoint || (value == midpoint && (low & 1))) result++;
        } else if ((mode == 1 && sign) || (mode == 2 && !sign)) {
            result++;
        }
    }
    return (uint16_t)((sign << 15) | result);
}

int main(void) {
    // Exact halfway values, signed overflow, and half-subnormal ties.
    const uint32_t values[8] = {0x3f801000, 0x3f803000, 0xbf801000, 0xbf803000,
                               0x47800000, 0xc7800000, 0x33000000, 0xb3000000};
    const uint16_t expected[4][8] = {
        {0x3c00, 0x3c02, 0xbc00, 0xbc02, 0x7c00, 0xfc00, 0, 0x8000},
        {0x3c00, 0x3c01, 0xbc01, 0xbc02, 0x7bff, 0xfc00, 0, 0x8001},
        {0x3c01, 0x3c02, 0xbc00, 0xbc01, 0x7c00, 0xfbff, 1, 0x8000},
        {0x3c00, 0x3c01, 0xbc00, 0xbc01, 0x7bff, 0xfbff, 0, 0x8000}
    };
    uint32_t input[16];
    uint16_t output[32];
    for (int lane = 0; lane < 16; lane++) input[lane] = values[lane % 8];
` + calls.String() + `
    void (*functions[])(const void *, void *) = {halfRound0, halfRound1, halfRound2, halfRound3};
    uint32_t random = 0x13579bdf;
    for (int batch = 0; batch < 4096; batch++) {
        for (int lane = 0; lane < 16; lane++) {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            input[lane] = random;
        }
        for (int mode = 0; mode < 4; mode++) {
            functions[mode](input, output);
            for (int lane = 0; lane < 16; lane++) {
                uint16_t want = reference(input[lane], mode);
                if (output[lane] != want) {
                    fprintf(stderr, "mode %d input %08x: %04x != %04x\n", mode, input[lane], output[lane], want);
                    return 2;
                }
            }
        }
    }
    return 0;
}
`
	compileAndRunRuntimeTest(t, llc, clang, "fp16_conversion_rounding", ir, mainC)
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable() {
		const triple = "x86_64-apple-macosx"
		x86IR, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
		if err != nil {
			t.Fatal(err)
		}
		compileAndRunRuntimeTestForTarget(t, llc, clang, "fp16_conversion_rounding_x86", triple, x86IR, mainC, []string{"/usr/bin/arch", "-x86_64"})
	}
}
