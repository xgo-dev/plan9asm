package plan9asm

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Assemble all lines together with an independent encoder. Expected lane
// numbers come from the source spelling, never from the decoder's bit formula.
func assembleARM64LLVMWords(t *testing.T, lines []string, features string) []uint32 {
	t.Helper()
	mc := findLLVM22Tool("llvm-mc")
	if mc == "" {
		t.Fatal("LLVM 22 llvm-mc not found")
	}
	cmd := exec.Command(mc, "-triple=aarch64", "-mattr="+features, "-show-encoding")
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("LLVM MC oracle: %v\n%s", err, output)
	}
	encodings := regexp.MustCompile(`encoding: \[([^\]]+)\]`).FindAllStringSubmatch(string(output), -1)
	if len(encodings) != len(lines) {
		t.Fatalf("LLVM MC returned %d encodings for %d instructions: %s", len(encodings), len(lines), output)
	}
	words := make([]uint32, len(encodings))
	for i, encoding := range encodings {
		fields := strings.Split(encoding[1], ",")
		if len(fields) != 4 {
			t.Fatalf("not an A64 instruction: %q", encoding[0])
		}
		var bytes [4]byte
		for j, field := range fields {
			value, err := strconv.ParseUint(strings.TrimSpace(field), 0, 8)
			if err != nil {
				t.Fatal(err)
			}
			bytes[j] = byte(value)
		}
		words[i] = binary.LittleEndian.Uint32(bytes[:])
	}
	return words
}

type arm64MultiplyHighIndexCase struct {
	line             string
	bits, lanes      int
	scalar, rounding bool
	register, index  int
	operation        int
}

func arm64MultiplyHighIndexCases() []arm64MultiplyHighIndexCase {
	var cases []arm64MultiplyHighIndexCase
	for operation, op := range []string{"sqdmulh", "sqrdmulh", "mul", "mla", "mls"} {
		for _, bits := range []int{16, 32} {
			element := "h"
			reg := 15
			if bits == 32 {
				element, reg = "s", 31
			}
			for _, vectorBits := range []int{0, 64, 128} {
				if vectorBits == 0 && operation >= 2 {
					continue
				}
				lanes := vectorBits / bits
				destination, first := element+"2", element+"0"
				if vectorBits == 0 {
					lanes = 1
				} else {
					destination = fmt.Sprintf("v2.%d%s", lanes, element)
					first = fmt.Sprintf("v0.%d%s", lanes, element)
				}
				for index := 0; index < 128/bits; index++ {
					cases = append(cases, arm64MultiplyHighIndexCase{
						line: fmt.Sprintf("%s %s, %s, v%d.%s[%d]", op, destination, first, reg, element, index),
						bits: bits, lanes: lanes, scalar: vectorBits == 0,
						rounding: op == "sqrdmulh", register: reg, index: index,
						operation: operation,
					})
				}
			}
		}
	}
	return cases
}

func TestARM64MultiplyHighIndexedLaneOrder(t *testing.T) {
	cases := arm64MultiplyHighIndexCases()
	var lines []string
	for _, tc := range cases {
		lines = append(lines, tc.line)
	}
	words := assembleARM64LLVMWords(t, lines, "+neon")
	for i, tc := range cases {
		form, ok := decodeARM64RawSQDMULH(words[i])
		if tc.rounding {
			form, ok = decodeARM64RawSQRDMULH(words[i])
		}
		if tc.operation >= 2 {
			decode := []func(uint32) (arm64RawMUL, bool){decodeARM64RawMUL, decodeARM64RawMLA, decodeARM64RawMLS}[tc.operation-2]
			multiply, found := decode(words[i])
			ok = found
			form = arm64RawSQDMULH{
				arrangement: multiply.arrangement, destination: multiply.destination,
				first: multiply.first, second: multiply.second, element: multiply.element,
				byElement: multiply.byElement,
			}
		}
		if !ok || !form.byElement || form.element != tc.index || form.second != tc.register || form.first != 0 || form.destination != 2 ||
			form.scalar != tc.scalar || form.arrangement.elementBits != tc.bits || form.arrangement.lanes != tc.lanes {
			t.Errorf("%s (%#08x): decoded %+v, %v", tc.line, words[i], form, ok)
		}
	}
}

func TestARM64ConformanceMultiplyHighIndexedLanes(t *testing.T) {
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
	file, sigs, mainC := arm64MultiplyIndexProgram(t)
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "multiply_index", triple, ir, mainC, runner)
}

func TestARM64MultiplyIndexedObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	file, sigs, _ := arm64MultiplyIndexProgram(t)
	for _, triple := range []string{"aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "multiply.ll", "multiply.o", ir)
		})
	}
}

func arm64MultiplyIndexProgram(t *testing.T) (*File, map[string]FuncSig, string) {
	t.Helper()
	cases := arm64MultiplyHighIndexCases()
	if len(cases) != 144 {
		t.Fatalf("generated %d indexed forms, want 144", len(cases))
	}
	var lines []string
	for _, tc := range cases {
		lines = append(lines, tc.line)
	}
	words := assembleARM64LLVMWords(t, lines, "+neon")
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	for i, tc := range cases {
		name := fmt.Sprintf("multiplyindex%d", i)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVD a+0(FP),R0\nMOVD b+8(FP),R1\nMOVD out+16(FP),R2\n", name)
		fmt.Fprintf(&source, "VLD1 (R0),[V0.B16]\nVLD1 (R0),[V2.B16]\nVLD1 (R1),[V%d.B16]\nWORD $%#08x\nVST1 [V2.B16],(R2)\nRET\n", tc.register, words[i])
		sigs[name] = FuncSig{
			Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}},
		}
		fmt.Fprintf(&declarations, "extern void %s(const void *,const void *,void *);\n", name)
		fmt.Fprintf(&checks, "    if (check(%s,%d,%d,%d,%d)) return %d;\n", name, tc.bits, tc.lanes, tc.index, tc.operation, i+1)
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	mainC := arm64MultiplyHighIndexOracleC + declarations.String() + "int main(void) {\n" + checks.String() + "return 0;\n}\n"
	return file, sigs, mainC
}

const arm64MultiplyHighIndexOracleC = `
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

static int check(void (*fn)(const void *,const void *,void *), int bits, int lanes, int index, int operation) {
    uint8_t a[16], b[16], got[16], want[16];
    uint32_t seed = 123;
    for (unsigned trial = 0; trial < 256; trial++) {
        for (unsigned byte = 0; byte < 16; byte++) {
            seed = seed * 1664525U + 1013904223U;
            a[byte] = seed >> 24;
            b[byte] = seed >> 16;
        }
        // Include the saturating min*min case at every indexed position.
        if (trial == 0) {
            memset(a, 0, 16);
            memset(b, 0, 16);
            for (int i = 0; i < 128 / bits; i++) {
                a[(i + 1) * bits / 8 - 1] = 128;
                b[(i + 1) * bits / 8 - 1] = 128;
            }
        }
        memset(want, 0, 16);
        for (int i = 0; i < lanes; i++) {
            int64_t product = lane(a,bits,i) * lane(b,bits,index);
            int64_t value = product;
            if (operation < 2) {
                if (operation == 1) product += INT64_C(1) << (bits - 2);
                value = product >> (bits - 1);
                int64_t maximum = (INT64_C(1) << (bits - 1)) - 1;
                if (value > maximum) value = maximum;
            } else if (operation == 3) {
                value = lane(a,bits,i) + product;
            } else if (operation == 4) {
                value = lane(a,bits,i) - product;
            }
            uint32_t result = (uint32_t)value;
            memcpy(want + i * bits / 8, &result, bits / 8);
        }
        memset(got, 0xa5, 16);
        fn(a,b,got);
        if (memcmp(got, want, 16)) {
            fprintf(stderr,"multiply index mismatch bits=%d lanes=%d index=%d operation=%d trial=%u\n",
                    bits,lanes,index,operation,trial);
            return 1;
        }
    }
    return 0;
}
`
