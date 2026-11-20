package plan9asm

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

type arm64RDMACase struct {
	operation string
	bits      int
	lanes     int
	scalar    bool
	indexed   bool
	index     int
	line      string
}

func arm64RDMACases() []arm64RDMACase {
	var cases []arm64RDMACase
	for _, operation := range []string{"sqrdmlah", "sqrdmlsh"} {
		for _, bits := range []int{16, 32} {
			letter := "h"
			if bits == 32 {
				letter = "s"
			}
			for _, lanes := range []int{0, 64 / bits, 128 / bits} {
				for _, indexed := range []bool{false, true} {
					indexes := []int{-1}
					if indexed {
						indexes = indexes[:0]
						for index := 0; index < 128/bits; index++ {
							indexes = append(indexes, index)
						}
					}
					for _, index := range indexes {
						first := letter + "1"
						second := letter + "2"
						destination := letter + "0"
						if lanes != 0 {
							first = fmt.Sprintf("v1.%d%s", lanes, letter)
							second = fmt.Sprintf("v2.%d%s", lanes, letter)
							destination = fmt.Sprintf("v0.%d%s", lanes, letter)
						}
						if indexed {
							second = fmt.Sprintf("v2.%s[%d]", letter, index)
						}
						cases = append(cases, arm64RDMACase{
							operation: operation, bits: bits, lanes: lanes,
							scalar: lanes == 0, indexed: indexed, index: index,
							line: fmt.Sprintf("%s %s, %s, %s", operation, destination, first, second),
						})
					}
				}
			}
		}
	}
	return cases
}

func TestARM64RawRDMACompleteForms(t *testing.T) {
	cases := arm64RDMACases()
	if len(cases) != 84 {
		t.Fatalf("got %d forms and indexed lanes, want 84", len(cases))
	}
	lines := make([]string, 0, len(cases))
	for _, tc := range cases {
		lines = append(lines, tc.line)
	}
	words := assembleARM64LLVMWords(t, lines, "+rdm")
	for i, tc := range cases {
		decoded, ok := decodeARM64RawRDMA(words[i])
		lanes := tc.lanes
		if tc.scalar {
			lanes = 1
		}
		if !ok || decoded.intrinsic != tc.operation || decoded.arrangement.elementBits != tc.bits ||
			decoded.arrangement.lanes != lanes || decoded.scalar != tc.scalar ||
			decoded.byElement != tc.indexed || decoded.element != tc.index ||
			decoded.destination != 0 || decoded.first != 1 || decoded.second != 2 {
			t.Errorf("%s (%#08x): decoded %+v, %v", tc.line, words[i], decoded, ok)
		}
	}
	for _, boundary := range []struct {
		line                       string
		destination, first, second int
		index                      int
	}{
		{"sqrdmlah v31.8h, v31.8h, v15.h[0]", 31, 31, 15, 0},
		{"sqrdmlsh v31.8h, v31.8h, v15.h[7]", 31, 31, 15, 7},
		{"sqrdmlah v31.4s, v31.4s, v31.s[0]", 31, 31, 31, 0},
		{"sqrdmlsh v31.4s, v31.4s, v31.s[3]", 31, 31, 31, 3},
		{"sqrdmlah h31, h31, v15.h[7]", 31, 31, 15, 7},
		{"sqrdmlsh s31, s31, v31.s[3]", 31, 31, 31, 3},
	} {
		word := assembleARM64LLVMWords(t, []string{boundary.line}, "+rdm")[0]
		decoded, ok := decodeARM64RawRDMA(word)
		if !ok || decoded.destination != boundary.destination || decoded.first != boundary.first ||
			decoded.second != boundary.second || decoded.element != boundary.index {
			t.Errorf("%s (%#08x): decoded %+v, %v", boundary.line, word, decoded, ok)
		}
		words = append(words, word)
	}
	words = append(words, 0x6e5f86d5) // independently discovered gmsm encoding
	if decoded, ok := decodeARM64RawRDMA(0x6e5f86d5); !ok ||
		decoded.destination != 21 || decoded.first != 22 || decoded.second != 31 ||
		decoded.arrangement.elementBits != 16 || decoded.arrangement.lanes != 8 {
		t.Fatalf("gmsm encoding decoded as %+v, %v", decoded, ok)
	}

	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for i, word := range words {
		name := fmt.Sprintf("rdmaform%d", i)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVD in+0(FP),R0\nMOVD out+8(FP),R1\n", name)
		for reg := 0; reg < 32; reg++ {
			fmt.Fprintf(&source, "VLD1 (R0),[V%d.B16]\n", reg)
		}
		fmt.Fprintf(&source, "WORD $%#08x\nVST1 [V%d.B16],(R1)\nRET\n", word, word&31)
		sigs[name] = FuncSig{
			Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}},
		}
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			for _, feature := range []string{"+rdm", "llvm.aarch64.neon.sqrdmlah", "llvm.aarch64.neon.sqrdmlsh"} {
				if !strings.Contains(ir, feature) {
					t.Fatalf("IR missing %q", feature)
				}
			}
			compileLLVMToObject(t, llc, triple, "rdma.ll", "rdma.o", ir)
		})
	}
}

func TestARM64RawRDMARejectsReservedSizesAndInventedNames(t *testing.T) {
	for _, spec := range arm64RawRDMASpecs {
		for _, size := range []uint32{0, 3} {
			word := spec.base&^(3<<22) | size<<22
			if decoded, ok := decodeARM64RawRDMA(word); ok {
				t.Errorf("accepted reserved encoding %#08x as %+v", word, decoded)
			}
		}
	}
	for _, line := range []string{
		"SQRDMLAH V0.H4, V1.H4, V2.H4",
		"SQRDMLSH V0.S4, V1.S4, V2.S4",
	} {
		requireARM64GoAssemblerResult(t, "TEXT rdmaInvalid(SB),4,$0-0\n"+line+"\nRET\n", false)
	}
}

func TestCrossLinuxRuntimeMatrixARM64RDMA(t *testing.T) {
	cross := runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && os.Getenv("PLAN9ASM_CROSS_EXEC") == "1"
	if runtime.GOARCH != "arm64" && !cross {
		t.Skip("ARM64 native execution or required Linux cross-runtime matrix")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compiler := []string{findLLVM22Tool("clang")}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runner []string
	if cross {
		compiler = []string{"aarch64-linux-gnu-gcc"}
		triple = "aarch64-unknown-linux-gnu"
		runner = []string{"qemu-aarch64", "-L", "/usr/aarch64-linux-gnu"}
	} else if compiler[0] == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	file, sigs, oracle := arm64RDMAOracleProgram(t)
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "rdma", triple, ir, oracle, runner)
}

func arm64RDMAOracleProgram(t *testing.T) (*File, map[string]FuncSig, string) {
	t.Helper()
	cases := arm64RDMACases()
	lines := make([]string, len(cases))
	for index, tc := range cases {
		lines[index] = tc.line
	}
	words := assembleARM64LLVMWords(t, lines, "+rdm")
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	for index, tc := range cases {
		name := fmt.Sprintf("rdmaoracle%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\n", name)
		fmt.Fprint(&source, "MOVD acc+0(FP),R0\nMOVD a+8(FP),R1\nMOVD b+16(FP),R2\nMOVD out+24(FP),R3\n")
		fmt.Fprintf(&source, "VLD1 (R0),[V0.B16]\nVLD1 (R1),[V1.B16]\nVLD1 (R2),[V2.B16]\nWORD $%#08x\nVST1 [V0.B16],(R3)\nRET\n", words[index])
		sigs[name] = FuncSig{
			Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: Ptr, Index: 3, Field: -1},
			}},
		}
		fmt.Fprintf(&declarations, "extern void %s(const void *, const void *, const void *, void *);\n", name)
		lanes := tc.lanes
		if tc.scalar {
			lanes = 1
		}
		fmt.Fprintf(&checks, "    if (check(%s, %d, %d, %d, %d)) return %d;\n",
			name, tc.bits, lanes, tc.index, map[bool]int{true: 1, false: 0}[tc.operation == "sqrdmlsh"], index+1)
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	oracle := arm64RDMAOracleC + declarations.String() + "int main(void) {\n" + checks.String() + "return 0;\n}\n"
	return file, sigs, oracle
}

// Independent translation of Arm DDI 0602's integer pseudocode. The i128
// accumulator avoids overflow before the final signed saturation.
const arm64RDMAOracleC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int64_t lane(const uint8_t *p, int bits, int index) {
    if (bits == 16) {
        int16_t value;
        memcpy(&value, p + index * 2, 2);
        return value;
    }
    int32_t value;
    memcpy(&value, p + index * 4, 4);
    return value;
}

static int check(void (*fn)(const void *,const void *,const void *,void *),
                 int bits, int lanes, int index, int subtract) {
    uint8_t acc[16], a[16], b[16], got[16], want[16];
    uint32_t seed = 0x98124ab3U;
    for (unsigned trial = 0; trial < 256; trial++) {
        for (int byte = 0; byte < 16; byte++) {
            seed = seed * 1664525U + 1013904223U;
            acc[byte] = seed >> 24;
            seed = seed * 1664525U + 1013904223U;
            a[byte] = seed >> 16;
            b[byte] = seed >> 8;
        }
        if (trial == 0 || trial == 1) {
            memset(acc, trial == 0 ? 0x7f : 0x80, 16);
            memset(a, 0, 16);
            memset(b, 0, 16);
            for (int lane = 0; lane < 128 / bits; lane++) {
                a[(lane + 1) * bits / 8 - 1] = 0x80;
                b[(lane + 1) * bits / 8 - 1] = 0x80;
            }
        }
        memset(want, 0, 16);
        for (int position = 0; position < lanes; position++) {
            int secondIndex = index < 0 ? position : index;
            __int128 total = (__int128)lane(acc,bits,position) * (((__int128)1) << bits);
            __int128 product = 2 * (__int128)lane(a,bits,position) * lane(b,bits,secondIndex);
            total += subtract ? -product : product;
            total = (total + (((__int128)1) << (bits - 1))) >> bits;
            __int128 maximum = (((__int128)1) << (bits - 1)) - 1;
            __int128 minimum = -maximum - 1;
            if (total > maximum) total = maximum;
            if (total < minimum) total = minimum;
            uint32_t result = (uint32_t)total;
            memcpy(want + position * bits / 8, &result, bits / 8);
        }
        memset(got, 0xa5, 16);
        fn(acc, a, b, got);
        if (memcmp(got, want, 16) != 0) {
            fprintf(stderr, "RDMA mismatch bits=%d lanes=%d index=%d subtract=%d trial=%u\n",
                    bits, lanes, index, subtract, trial);
            return 1;
        }
    }
    return 0;
}
`
