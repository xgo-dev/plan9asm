package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Intel AVX512-FP16 sections 5.74/5.75. Packed SQRT reserves vvvv;
// scalar SQRT instead uses it as the source of preserved upper X lanes.
func rawFP16PackedSqrt(length byte, source, destination, mask int, memory, control, zero bool) []byte {
	code := encodeRawFP16Binary(0x51, length, 0, source, destination, mask, false, control, zero)
	if memory {
		code[1] |= 0x60
		code[5] = byte(0x40 | (destination&7)<<3)
		code = append(code, 1)
	}
	return code
}

func TestRawFP16PackedSqrtRejectsNamedForms(t *testing.T) {
	const source = "TEXT namedHalfSqrt(SB),4,$0-0\nVSQRTPH X0, X1\nRET\n"
	requireX86GoAssemblerResult(t, "amd64", source, false)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"namedHalfSqrt": {Name: "namedHalfSqrt", Ret: Void}},
	}); err == nil {
		t.Fatal("accepted VSQRTPH absent from Go's named assembler table")
	}
}

func TestRawFP16SqrtPortableRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source, declarations, calls strings.Builder
	sigs := make(map[string]FuncSig)
	for _, scalar := range []bool{false, true} {
		for _, zero := range []bool{false, true} {
			name := fmt.Sprintf("halfSqrt_%t_%t", scalar, zero)
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\n", name)
			source.WriteString("MOVQ input+0(FP), DI\nMOVQ memory+8(FP), AX\nMOVQ out+16(FP), SI\nMOVQ mask+24(FP), CX\n")
			source.WriteString("KMOVQ CX, K1\nVMOVDQU64 (DI), Z0\nVMOVDQU64 64(DI), Z1\n")
			code := rawFP16PackedSqrt(0, 0, 0, 1, true, false, zero)
			if scalar {
				code = encodeRawFP16ScalarBinary(0x51, 0, 1, 0, 0, 1, true, false, zero)
			}
			code[len(code)-1] = 0
			for _, b := range code {
				fmt.Fprintf(&source, "BYTE $0x%02x\n", b)
			}
			source.WriteString("VMOVDQU64 Z0, (SI)\nRET\n")
			sigs[name] = FuncSig{
				Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void, Attrs: "nounwind",
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
					{Offset: 24, Type: I64, Index: 3, Field: -1},
				}},
			}
			lanes, fallback := 8, "input[lane]"
			if scalar {
				lanes = 1
			}
			if zero {
				fallback = "0"
			}
			upper := "0"
			if scalar {
				upper = "lane < 8 ? input[32 + lane] : 0"
			}
			fmt.Fprintf(&declarations, "extern void %s(const void *, const void *, void *, uint64_t);\n", name)
			fmt.Fprintf(&calls, `
        %s(input, pointer, output, mask);
        for (int lane = 0; lane < 32; lane++) {
            uint16_t expected = lane < %d ? ((mask & (UINT64_C(1) << lane)) ? roots[lane] : %s) : (%s);
            if (output[lane] != expected) {
                fprintf(stderr, "%s mask %%llx lane %%d: %%04x != %%04x\n",
                        (unsigned long long)mask, lane, output[lane], expected);
                return 2;
            }
        }
`, name, lanes, fallback, upper, name)
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
    // Independent bit-pattern oracle: sqrt(0, -0, 1, 4, 9, 16, 2^-24, +inf).
    const uint16_t memory[] = {0, 0x8000, 0x3c00, 0x4400, 0x4880, 0x4c00, 1, 0x7c00};
    const uint16_t roots[] = {0, 0x8000, 0x3c00, 0x4000, 0x4200, 0x4400, 0x0c00, 0x7c00};
    const uint64_t masks[] = {0, 1, 0xff, UINT64_C(1) << 60};
    uint16_t input[64], output[32];
    for (int lane = 0; lane < 64; lane++) input[lane] = (uint16_t)(0x1000 + lane);
    for (int mi = 0; mi < 4; mi++) {
        uint64_t mask = masks[mi];
        const void *pointer = memory;
        if ((mask & 0xff) == 0) pointer = NULL;
        if (mask == 1) {
            memcpy(guard + page - 3, memory, 2);
            pointer = guard + page - 3;
        }
` + calls.String() + `
    }
    return free_guard();
}
`
	compileAndRunRuntimeTest(t, llc, clang, "fp16_sqrt_portable", ir, mainC)
}

func TestDecodeRawFP16PackedSqrtFormats(t *testing.T) {
	for length := byte(0); length < 4; length++ {
		for _, memory := range []bool{false, true} {
			for _, control := range []bool{false, true} {
				if length == 3 && (!control || memory) {
					continue
				}
				for _, mask := range []int{0, 1, 7} {
					for _, zero := range []bool{false, true} {
						if zero && mask == 0 {
							continue
						}
						code := rawFP16PackedSqrt(length, 20, 21, mask, memory, control, zero)
						got, size, ok, err := decodedX86SameWidthConversionInstruction(code, 64)
						if err != nil || !ok || size != len(code) {
							t.Fatalf("%x: got %+v, size=%d, ok=%v, err=%v", code, got, size, ok, err)
						}
						want := Op("VSQRTPH")
						vl := length
						if control {
							if memory {
								want += ".BCST"
							} else {
								want += [...]Op{".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE"}[length]
								vl = 2
							}
						}
						if zero {
							want += ".Z"
						}
						prefix := [...]string{"X", "Y", "Z"}[vl]
						if got.Op != want || !got.x86Encoded || got.Args[len(got.Args)-1].String() != prefix+"21" {
							t.Fatalf("%x: got %+v, want raw %s with %s21", code, got, want, prefix)
						}
						wantSource := prefix + "20"
						if memory {
							width := 16 << vl
							if control {
								width = 2
							}
							wantSource = fmt.Sprintf("%d(AX)", width)
						}
						if got.Args[0].String() != wantSource {
							t.Fatalf("%x: source %s, want %s", code, got.Args[0], wantSource)
						}
					}
				}
			}
		}
	}
}

func TestDecodeRawFP16PackedSqrtInvalidForms(t *testing.T) {
	for _, tc := range []struct {
		index int
		bits  byte
	}{
		{2, 0x80}, // W1.
		{2, 0x04}, // Fixed bit cleared.
		{2, 0x08}, // Reserved vvvv.
		{3, 0x08}, // Reserved V'.
		{3, 0x80}, // Zeroing with K0.
		{3, 0x60}, // Reserved packed length.
	} {
		code := rawFP16PackedSqrt(0, 1, 2, 0, false, false, false)
		code[tc.index] ^= tc.bits
		if _, _, ok, err := decodedX86SameWidthConversionInstruction(code, 64); !ok || err == nil {
			t.Fatalf("accepted invalid %x: matched=%v, err=%v", code, ok, err)
		}
	}
}

func TestTranslateRawFP16PackedSqrtLLVM22Targets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	var source strings.Builder
	source.WriteString("TEXT rawHalfSqrt(SB),4,$0-0\n")
	for length := byte(0); length < 4; length++ {
		for _, memory := range []bool{false, true} {
			for _, control := range []bool{false, true} {
				if length == 3 && (!control || memory) {
					continue
				}
				code := rawFP16PackedSqrt(length, 1, 2, 1, memory, control, true)
				for _, b := range code {
					fmt.Fprintf(&source, "BYTE $0x%02x\n", b)
				}
			}
		}
	}
	source.WriteString("RET\n")
	for _, target := range []struct {
		arch, triple string
	}{
		{"amd64", "x86_64-apple-darwin"}, {"amd64", "x86_64-unknown-linux-gnu"},
		{"amd64", "x86_64-pc-windows-msvc"}, {"386", "i386-unknown-linux-gnu"},
		{"386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			requireX86GoAssemblerResult(t, target.arch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: target.arch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"rawHalfSqrt": {Name: "rawHalfSqrt", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"@llvm.sqrt.v8f16", "@llvm.sqrt.v16f16", "@llvm.sqrt.v32f16",
				"@llvm.experimental.constrained.sqrt.v32f16", "@llvm.masked.load.v8i16", "phi i16"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("missing %s", want)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "raw-half-sqrt.ll", "raw-half-sqrt.o", ir)
		})
	}
}
