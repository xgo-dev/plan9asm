package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestX86MinMaxMemoryAndViewsRuntime(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var prefix []string
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable() {
		triple = "x86_64-apple-macosx"
		prefix = []string{"/usr/bin/arch", "-x86_64"}
	} else if runtime.GOARCH != "amd64" {
		t.Skip("execution requires amd64 or Rosetta; five-target objects remain required")
	}

	var source, declarations strings.Builder
	checks := map[string]*strings.Builder{"views": {}, "memory": {}}
	sigs := map[string]FuncSig{}
	index := 0
	for _, op := range x86MinMaxTestOps {
		bits := map[byte]int{'B': 8, 'W': 16, 'D': 32, 'Q': 64}[op[len(op)-1]]
		signed, minimum := 0, 0
		if op[5] == 'S' {
			signed = 1
		}
		if strings.HasPrefix(op, "VPMIN") {
			minimum = 1
		}

		for w, width := range []string{"X", "Y", "Z"} {
			// Register/memory unmasked, register/memory masked, masked broadcast.
			for mode := 0; mode < 5; mode++ {
				if mode == 4 && bits < 32 {
					continue
				}
				for _, zero := range []bool{false, true} {
					if zero && mode < 2 {
						continue
					}
					for _, raw := range []bool{false, true} {
						name := fmt.Sprintf("minmax%d", index)
						index++
						fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\n", name)
						source.WriteString("MOVQ a+0(FP),AX\nMOVQ b+8(FP),BX\nMOVQ out+16(FP),DI\n")
						source.WriteString("VMOVUPS (AX),Z0\n")

						input := "(BX)"
						registerInput := mode == 0 || mode == 2
						if registerInput {
							source.WriteString("VMOVUPS (BX),Z1\n")
							input = width + "1"
						} else if raw {
							source.WriteString("VMOVUPS (AX),Z1\n")
						}
						suffix, mask := "", ""
						if mode == 4 {
							suffix = ".BCST"
						}
						if zero {
							suffix += ".Z"
						}
						if mode >= 2 {
							source.WriteString("KMOVQ mask+24(FP),K1\n")
							mask = "K1,"
						}

						destination, oldB := 0, 0
						if raw {
							destination = 1
							if registerInput {
								oldB = 1
							}
						}
						line := fmt.Sprintf("%s%s %s,%s0,%s%s%d", op, suffix, input, width, mask, width, destination)
						emitX86GoEncodedTestInstruction(t, &source, line, raw)
						fmt.Fprintf(&source, "VMOVUPS Z%d,(DI)\n", destination)
						fmt.Fprintf(&source, "VMOVUPS Y%d,64(DI)\n", destination)
						fmt.Fprintf(&source, "VMOVUPS X%d,96(DI)\nRET\n", destination)

						sigs[name] = FuncSig{
							Name: name,
							Args: []LLVMType{Ptr, Ptr, Ptr, I64},
							Ret:  Void,
							Frame: FrameLayout{Params: []FrameSlot{
								{Offset: 0, Type: Ptr, Index: 0, Field: -1},
								{Offset: 8, Type: Ptr, Index: 1, Field: -1},
								{Offset: 16, Type: Ptr, Index: 2, Field: -1},
								{Offset: 24, Type: I64, Index: 3, Field: -1},
							}},
						}
						fmt.Fprintf(&declarations, "extern void %s(const void*, const void*, void*, uint64_t);\n", name)
						kind, zeroing := "views", 0
						if mode >= 2 {
							kind = "memory"
						}
						if zero {
							zeroing = 1
						}
						fmt.Fprintf(checks[kind], "    if (check(%s, %d, %d, %d, %d, %d, %d, %d)) {\n", name, 16<<w, bits/8, signed, minimum, mode, zeroing, oldB)
						fmt.Fprintf(checks[kind], "        fprintf(stderr, \"%s failed\\n\");\n        return 1;\n    }\n", name)
					}
				}
			}
		}
	}
	if index != 672 {
		t.Fatalf("generated %d functions, want 672", index)
	}

	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	mainC := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" +
		x86TestGuardPagesC + declarations.String() + x86MinMaxRuntimeOracleC
	for _, kind := range []string{"views", "memory"} {
		t.Run(kind, func(t *testing.T) {
			body := mainC + "\nint main(void) {\n    if (setup_guard()) return 2;\n" +
				checks[kind].String() + "    return free_guard();\n}\n"
			compileAndRunRuntimeTestForTarget(t, llc, clang, "minmax_"+kind, triple, ir, body, prefix)
		})
	}
}

const x86MinMaxRuntimeOracleC = `
static uint64_t lane(const uint8_t *p, int bytes) {
    uint64_t value = 0;
    memcpy(&value, p, bytes);
    return value;
}

static uint64_t low_mask(int bits) {
    return bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1;
}

static uint64_t minmax(uint64_t a, uint64_t b, int bits, int sign, int minimum) {
    uint64_t sign_bit = sign ? UINT64_C(1) << (bits - 1) : 0;
    int less = (a ^ sign_bit) < (b ^ sign_bit);
    return less == minimum ? a : b;
}

static int check(void (*fn)(const void*, const void*, void*, uint64_t),
                 int width, int bytes, int sign, int minimum, int mode,
                 int zero, int old_b) {
    int lanes = width / bytes;
    uint64_t sign_bit = UINT64_C(1) << (bytes * 8 - 1);
    uint64_t values[] = {0, 1, sign_bit - 1, sign_bit, sign_bit + 1, UINT64_MAX};

    for (int n = 0; n < 64; n++) {
        uint8_t ab[65], bb[65], out[112], want[112] = {0};
        uint8_t *a = ab + 1, *b = bb + 1;
        for (int i = 0; i < 64 / bytes; i++) {
            uint64_t av = values[(n + i) % 6];
            uint64_t bv = values[(n / 6 + i * 3) % 6];
            memcpy(a + i * bytes, &av, bytes);
            memcpy(b + i * bytes, &bv, bytes);
        }

        uint64_t mask = n == 0 ? 0 : n == 1 ? UINT64_C(1) << 63 :
                        n == 2 ? UINT64_MAX : UINT64_C(0x5a5a01239876cdef) >> (n % 32);
        uint64_t active = mask & low_mask(lanes);
        for (int i = 0; i < lanes; i++) {
            uint64_t av = lane(a + i * bytes, bytes);
            uint64_t bv = lane(b + (mode == 4 ? 0 : i * bytes), bytes);
            uint64_t result;
            if (mode < 2 || ((mask >> i) & 1)) {
                result = minmax(av, bv, bytes * 8, sign, minimum);
            } else {
                result = zero ? 0 : old_b ? lane(b + i * bytes, bytes) : av;
            }
            memcpy(want + i * bytes, &result, bytes);
        }
        memcpy(want + 64, want, 32);
        memcpy(want + 96, want, 16);

        fn(a, mode >= 3 && !active ? NULL : b, out, mask);
        if (memcmp(out, want, sizeof(out))) {
            fprintf(stderr, "width=%d bytes=%d sign=%d min=%d mode=%d zero=%d n=%d\n",
                    width, bytes, sign, minimum, mode, zero, n);
            return 1;
        }
    }

    if (mode >= 3) {
        for (int enabled = 1; enabled <= lanes; enabled++) {
            uint8_t a[64], out[112], want[112] = {0};
            memset(a, 255, sizeof(a));
            int readable = mode == 4 ? bytes : enabled * bytes;
            uint8_t *b = guard + page - readable;
            memset(b, 255, (size_t)readable);

            for (int i = 0; i < lanes; i++) {
                if (i < enabled || !zero) {
                    memset(want + i * bytes, 255, (size_t)bytes);
                }
            }
            memcpy(want + 64, want, 32);
            memcpy(want + 96, want, 16);

            fn(a, b, out, low_mask(enabled));
            if (memcmp(out, want, sizeof(out))) {
                return 1;
            }
        }
    }
    return 0;
}
`
