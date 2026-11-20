package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// FEAT_SM4 is not universally available on ARM64 hosts. Execute it on the
// required Linux/QEMU CPU=max matrix, not an optional host-feature probe.
func TestCrossLinuxRuntimeMatrixARM64SM4(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("SM4 execution belongs to the required Linux cross-runtime matrix")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("cross-runtime driver requires linux/amd64")
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, tool := range []string{"aarch64-linux-gnu-gcc", "qemu-aarch64"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("required cross-runtime tool %s: %v", tool, err)
		}
	}

	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	index := 0
	for _, op := range []string{"sm4e", "sm4ekey"} {
		// Independent registers, each possible destination/source alias, source
		// aliasing and all-equal. Rotate through the complete V0..V31 range.
		aliases := [][3]int{{0, 1, 2}, {0, 0, 1}, {0, 1, 0}, {0, 1, 1}, {0, 0, 0}}
		if op == "sm4e" {
			aliases = [][3]int{{0, 0, 1}, {0, 0, 0}}
		}
		for offset := 0; offset < 32; offset++ {
			for _, alias := range aliases {
				d, n, m := (offset+alias[0])%32, (offset+alias[1])%32, (offset+alias[2])%32
				name := fmt.Sprintf("sm4case%d", index)
				index++
				word := uint32(0xce60c800 | m<<16 | n<<5 | d)
				key := 1
				if op == "sm4e" {
					word = uint32(0xcec08400 | m<<5 | d)
					key = 0
				}
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVD in+0(FP),R0\nMOVD out+8(FP),R1\n", name)
				// Save all physical vectors to check both the result and untouched
				// source/neighbor registers, rather than observing just one lane.
				for r := 0; r < 32; r++ {
					fmt.Fprintf(&source, "VLD1.P 16(R0),[V%d.S4]\n", r)
				}
				source.WriteString("CMP $0,R0\n")
				fmt.Fprintf(&source, "WORD $%#08x\n", word)
				for r := 0; r < 32; r++ {
					fmt.Fprintf(&source, "VST1.P [V%d.S4],16(R1)\n", r)
				}
				// SM4 must preserve NZCV; R0 is a non-null advanced input pointer.
				source.WriteString("CSET NE,R2\nMOVD R2,(R1)\nRET\n")
				sigs[name] = FuncSig{
					Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
					Frame: FrameLayout{Params: []FrameSlot{
						{Offset: 0, Type: Ptr, Index: 0, Field: -1},
						{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					}},
				}
				fmt.Fprintf(&declarations, "extern void %s(const uint32_t *, uint32_t *);\n", name)
				fmt.Fprintf(&checks, "    if (check(%s, %d, %d, %d, %d)) return 1;\n", name, d, n, m, key)
			}
		}
	}
	if index != 224 {
		t.Fatalf("generated %d cases, want 224", index)
	}
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	const triple = "aarch64-unknown-linux-gnu"
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	mainC := arm64SM4OracleC + declarations.String() + "\nint main(void) {\n" + checks.String() + "    return 0;\n}\n"
	compileAndRunRuntimeTestWithCompiler(t, llc,
		[]string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sm4"}, "sm4_semantics", triple, ir, mainC,
		[]string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"})
}

const arm64SM4OracleC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint8_t sbox[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

static uint32_t rotate(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32 - n));
}

// Four rounds, with word/byte order explicitly matching Arm DDI 0602.
static void reference(uint32_t out[4], const uint32_t in[4], const uint32_t constants[4], int key) {
    uint32_t state[8];
    memcpy(state, in, 16);
    for (unsigned round = 0; round < 4; round++) {
        uint32_t x = state[round + 1] ^ state[round + 2] ^ state[round + 3] ^ constants[round];
        uint32_t y = 0;
        for (unsigned byte = 0; byte < 4; byte++) {
            y |= (uint32_t)sbox[(x >> (8 * byte)) & 255] << (8 * byte);
        }
        uint32_t linear = key ? y ^ rotate(y, 13) ^ rotate(y, 23)
                              : y ^ rotate(y, 2) ^ rotate(y, 10) ^ rotate(y, 18) ^ rotate(y, 24);
        state[round + 4] = state[round] ^ linear;
    }
    memcpy(out, state + 4, 16);
}

typedef uint32_t words __attribute__((vector_size(16)));

static void native(uint32_t out[4], const uint32_t in[4], const uint32_t constants[4], int key) {
    words a, b, result;
    memcpy(&a, in, 16);
    memcpy(&b, constants, 16);
    if (key) {
        __asm__("sm4ekey %0.4s, %1.4s, %2.4s" : "=w"(result) : "w"(a), "w"(b));
    } else {
        result = a;
        __asm__("sm4e %0.4s, %1.4s" : "+w"(result) : "w"(b));
    }
    memcpy(out, &result, 16);
}

static int check(void (*fn)(const uint32_t *, uint32_t *), int d, int n, int m, int key) {
    uint32_t input[128], expected[130], actual[130], hardware[4];
    uint32_t seed = 0x12345678;
    for (unsigned trial = 0; trial < 256; trial++) {
        for (unsigned i = 0; i < 128; i++) {
            seed = seed * 1664525U + 1013904223U;
            input[i] = trial == 0 ? 0 : trial == 1 ? UINT32_MAX : seed;
        }
        memcpy(expected, input, sizeof(input));
        expected[128] = 1;
        expected[129] = 0;
        reference(expected + 4 * d, input + 4 * n, input + 4 * m, key);
        native(hardware, input + 4 * n, input + 4 * m, key);
        if (memcmp(hardware, expected + 4 * d, 16)) {
            fprintf(stderr, "SM4 reference/native mismatch key=%d trial=%u\n", key, trial);
            return 1;
        }
        memset(actual, 0xa5, sizeof(actual));
        fn(input, actual);
        if (memcmp(actual, expected, sizeof(actual))) {
            fprintf(stderr, "SM4 translated mismatch key=%d d=%d n=%d m=%d trial=%u\n", key, d, n, m, trial);
            return 1;
        }
    }
    return 0;
}
`
