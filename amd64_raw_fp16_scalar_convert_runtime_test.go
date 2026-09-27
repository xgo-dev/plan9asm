package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestRawFP16ScalarConversionPortableRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source, declarations, calls strings.Builder
	sigs := make(map[string]FuncSig)
	for index, tc := range fp16ScalarConversionCases {
		for _, zero := range []bool{false, true} {
			name := fmt.Sprintf("scalarHalf_%d_%t", index, zero)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\n", name)
			source.WriteString("MOVQ input+0(FP), AX\nMOVQ vectors+8(FP), DI\nMOVQ out+16(FP), SI\nMOVQ mask+24(FP), CX\nKMOVQ CX, K1\nVMOVDQU64 (DI), Z0\nVMOVDQU64 64(DI), Z1\n")
			code := rawFP16ScalarConversion(index, 3, 1, 0, 0, 1, true, false, zero)
			code[len(code)-1] = 0
			for _, b := range code {
				fmt.Fprintf(&source, "BYTE $0x%02x\n", b)
			}
			source.WriteString("VMOVDQU64 Z0, (SI)\nRET\n")
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Attrs: "nounwind",
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1},
				}},
			}
			bits := map[int]uint64{16: 0x4000, 32: 0x40000000, 64: 0x4000000000000000}
			fmt.Fprintf(&declarations, "extern void %s(const void *, const void *, void *, uint64_t);\n", name)
			inactive := "memcpy(expected, vectors, output_bytes);"
			if zero {
				inactive = "memset(expected, 0, output_bytes);"
			}
			fmt.Fprintf(&calls, `
    {
        const int input_bytes = %d, output_bytes = %d;
        uint64_t input = UINT64_C(%d), result = UINT64_C(%d);
        const void *pointer = NULL;
        if (mask & 1) {
            memcpy(guard + page - input_bytes - 1, &input, input_bytes);
            pointer = guard + page - input_bytes - 1;
        }
        memset(expected, 0, sizeof(expected));
        if (mask & 1) memcpy(expected, &result, output_bytes);
        else { %s }
        memcpy(expected + output_bytes, vectors + 64 + output_bytes, 16 - output_bytes);
        %s(pointer, vectors, output, mask);
        if (memcmp(expected, output, 64)) {
            fprintf(stderr, "%s mask %%llx: incorrect low, preserved or upper lanes\n", (unsigned long long)mask);
            return 2;
        }
    }
`, tc.inputBits/8, tc.outBits/8, bits[tc.inputBits], bits[tc.outBits], inactive, name, name)
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
    unsigned char vectors[128], output[64], expected[64];
    for (int i = 0; i < 128; i++) vectors[i] = (unsigned char)(0x20 + i);
    const uint64_t masks[] = {0, 1, 2, UINT64_C(1) << 60, UINT64_MAX};
    for (int mi = 0; mi < 5; mi++) {
        uint64_t mask = masks[mi];
` + calls.String() + `
    }
    return free_guard();
}
`
	compileAndRunRuntimeTest(t, llc, clang, "fp16_scalar_conversion", ir, mainC)
}

func TestRawFP16ScalarConversionRoundingRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source, declarations, calls strings.Builder
	sigs := make(map[string]FuncSig)
	for _, index := range []int{1, 3} {
		for rounding := 0; rounding < 4; rounding++ {
			name := fmt.Sprintf("scalarRound_%d_%d", index, rounding)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVQ input+0(FP), AX\nMOVQ out+8(FP), SI\nVMOVDQU64 (AX), Z2\n", name)
			for _, b := range rawFP16ScalarConversion(index, rounding, 1, 2, 0, 0, false, true, false) {
				fmt.Fprintf(&source, "BYTE $0x%02x\n", b)
			}
			source.WriteString("VMOVDQU64 Z0, (SI)\nRET\n")
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void, Attrs: "nounwind",
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			}
			fmt.Fprintf(&declarations, "extern void %s(const void *, void *);\n", name)
			input := "single"
			if index == 3 {
				input = "wide"
			}
			fmt.Fprintf(&calls, `
        %s(%s, output);
        if (output[0] != expected[%d][sample]) {
            fprintf(stderr, "%s sample %%d: %%04x != %%04x\n", sample, output[0], expected[%d][sample]);
            return 1;
        }
`, name, input, rounding, name, rounding)
			if index == 3 {
				fmt.Fprintf(&calls, `
        // These exactly representable doubles straddle a half tie but round
        // to that same tie in float; a double->float->half chain is wrong.
        if (sample == 0) {
            wide[0] = 1.0 + 0x1p-11 + 0x1p-40;
            %s(wide, output);
            const uint16_t above[] = {0x3c01, 0x3c00, 0x3c01, 0x3c00};
            if (output[0] != above[%d]) return 2;
            wide[0] = 1.0 + 0x1p-11 - 0x1p-40;
            %s(wide, output);
            const uint16_t below[] = {0x3c00, 0x3c00, 0x3c01, 0x3c00};
            if (output[0] != below[%d]) return 3;
            wide[0] = values[sample];
        }
`, name, rounding, name, rounding)
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
	mainC := "#include <stdint.h>\n#include <stdio.h>\n" + declarations.String() + `
int main(void) {
    const double values[] = {1 + 0x1p-11, 1 + 3 * 0x1p-11, -1 - 0x1p-11, -1 - 3 * 0x1p-11,
                             65536, -65536, 0x1p-25, -0x1p-25};
    const uint16_t expected[4][8] = {
        {0x3c00, 0x3c02, 0xbc00, 0xbc02, 0x7c00, 0xfc00, 0, 0x8000},
        {0x3c00, 0x3c01, 0xbc01, 0xbc02, 0x7bff, 0xfc00, 0, 0x8001},
        {0x3c01, 0x3c02, 0xbc00, 0xbc01, 0x7c00, 0xfbff, 1, 0x8000},
        {0x3c00, 0x3c01, 0xbc00, 0xbc01, 0x7bff, 0xfbff, 0, 0x8000}
    };
    uint16_t output[32];
    for (int sample = 0; sample < 8; sample++) {
        double wide[8] = {values[sample]};
        float single[16] = {(float)values[sample]};
` + calls.String() + `
    }
    return 0;
}
`
	compileAndRunRuntimeTest(t, llc, clang, "fp16_scalar_rounding", ir, mainC)
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable() {
		const triple = "x86_64-apple-macosx"
		x86IR, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
		if err != nil {
			t.Fatal(err)
		}
		compileAndRunRuntimeTestForTarget(t, llc, clang, "fp16_scalar_rounding_x86", triple, x86IR, mainC, []string{"/usr/bin/arch", "-x86_64"})
	}
}
