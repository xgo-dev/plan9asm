package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVEExtendedLoadRuntime(t *testing.T, llc string) {
	type runtimeCase struct {
		kind, size, count, offset int
		zeroIndex                 bool
		native                    []string
	}
	var cases []runtimeCase
	var allNative []string
	for kind := 0; kind < 5; kind++ {
		for size := 0; size < 5; size++ {
			if kind < 2 && size > 3 || (kind == 2 || kind == 3) && (size < 2 || size > 3) || kind == 4 && size != 4 {
				continue
			}
			counts := []int{1}
			if kind < 2 {
				counts = []int{2, 4}
			}
			for _, count := range counts {
				offsets := []int{0}
				if kind == 0 || kind == 2 {
					offsets = []int{-8, 0, 7}
				} else if kind == 1 || kind == 4 {
					offsets = []int{0, 1} // ordinary index and the architectural XZR alias
				}
				for _, offset := range offsets {
					zeroIndex := (kind == 1 || kind == 4) && offset == 1
					native := []string{
						"ptrue p0.b", "ld1b {z30.b}, p0/z, [x1]", "ld1b {z20.b}, p0/z, [x2]",
						"cmpne p7.b, p0/z, z20.b, #0", "ldr x4, [x1, #256]", "ldr x5, [x1, #264]", "mov x6, #0",
					}
					address := fmt.Sprintf("[x0, x4, lsl #%d]", size)
					if kind == 0 || kind == 2 {
						address = fmt.Sprintf("[x0, #%d, mul vl]", offset*count)
					} else if zeroIndex && kind == 1 {
						address = fmt.Sprintf("[x0, xzr, lsl #%d]", size)
					}
					if kind < 2 {
						native = append(native,
							fmt.Sprintf("whilelo pn15.%c, x6, x5, vlx%d", "bhsd"[size], count),
							fmt.Sprintf("ld1%c {z28.%c-z%d.%c}, pn15/z, %s", "bhwd"[size], "bhsd"[size], 27+count, "bhsd"[size], address))
					} else if kind == 4 {
						index := "x4"
						if zeroIndex {
							index = "xzr"
						}
						native = append(native, fmt.Sprintf("ld1q {z30.q}, p7/z, [z30.d, %s]", index))
					} else {
						native = append(native, fmt.Sprintf("ld1%c {z30.q}, p7/z, %s", "bhwd"[size], address))
					}
					for i := 0; i < count; i++ {
						register := 28 + i
						if kind >= 2 {
							register = 30
						}
						native = append(native, fmt.Sprintf("st1b {z%d.b}, p0, [x3, #%d, mul vl]", register, i))
					}
					cases = append(cases, runtimeCase{kind, size, count, offset, zeroIndex, native})
					allNative = append(allNative, native...)
				}
			}
		}
	}
	words := assembleARM64LLVMWords(t, allNative, "+sve2p1")
	var source, declarations, checks strings.Builder
	declarations.WriteString(arm64SVEExtendedLoadRuntimeReference)
	sigs := make(map[string]FuncSig)
	for _, test := range cases {
		name := fmt.Sprintf("extended_load_%d", len(sigs))
		fmt.Fprintf(&source, "TEXT %s(SB),$0-32\nMOVD base+0(FP),R0\nMOVD indices+8(FP),R1\nMOVD mask+16(FP),R2\nMOVD out+24(FP),R3\n", name)
		var native strings.Builder
		native.WriteString("mov x0, %[base]\\n\\tmov x1, %[indices]\\n\\tmov x2, %[mask]\\n\\tmov x3, %[out]\\n\\t")
		for i, word := range words[:len(test.native)] {
			if test.kind < 2 && i == 7 {
				fmt.Fprintf(&source, "PWHILELO VLX%d, R5, R6, PN15.%c\n", test.count, "BHSD"[test.size])
			} else {
				fmt.Fprintf(&source, "WORD $%#08x\n", word)
			}
			fmt.Fprintf(&native, ".inst %#08x\\n\\t", word)
		}
		words = words[len(test.native):]
		source.WriteString("RET\n")
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
			{Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: Ptr, Index: 3, Field: -1},
		}}}
		fmt.Fprintf(&declarations, `extern void %[1]s(const void *, const void *, const void *, void *);
static void %[1]s_native(const void *base, const void *indices, const void *mask, void *out) {
  __asm__ volatile("%[2]s" :: [base]"r"(base), [indices]"r"(indices), [mask]"r"(mask), [out]"r"(out)
    : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "p0", "p7", "p15", "z20", "z28", "z29", "z30", "z31", "cc", "memory");
}
`, name, native.String())
		zero := 0
		if test.zeroIndex {
			zero = 1
		}
		fmt.Fprintf(&checks, "  if (check_extended_load(vl, %d, %d, %d, %d, %d, %s, %s_native, %q)) return 1;\n",
			test.kind, 1<<test.size, test.count, test.offset, zero, name, name, name)
	}
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	const triple = "aarch64-unknown-linux-gnu"
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := arm64SVEVectorLengthMain(declarations.String(), checks.String())
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve"}, "raw_extended_load", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}

const arm64SVEExtendedLoadRuntimeReference = `
typedef void (*extended_load_fn)(const void *, const void *, const void *, void *);
__attribute__((noinline, noclone))
static int check_extended_load(unsigned vl, unsigned kind, unsigned access, unsigned count,
    int offset, int zero_index, extended_load_fn translated, extended_load_fn native_instruction, const char *name) {
  unsigned char memory[32768], indices[272], mask[256], got[1024], native[1024], scalar[1024];
  unsigned element = kind < 2 ? access : 16;
  for (unsigned phase = 0; phase < 8; phase++) {
    for (unsigned i = 0; i < sizeof(memory); i++) memory[i] = i * 71 + (i >> 8) + phase;
    memset(indices, 0, sizeof(indices));
    memset(mask, 0, sizeof(mask));
    memset(got, 0x5a, sizeof(got));
    memset(native, 0x5a, sizeof(native));
    memset(scalar, 0x5a, sizeof(scalar));
    memset(scalar, 0, vl * count);
    unsigned char *base = phase ? memory + 16384 + phase % 4 : 0;
    int64_t index = zero_index ? 0 : (int64_t)(phase % 3) * 11 - 7;
    uint64_t limit = phase == 0 ? 0 : phase == 1 ? vl * count / access : vl * (phase % count + 1) / access - 1;
    memcpy(indices + 256, &index, sizeof(index));
    memcpy(indices + 264, &limit, sizeof(limit));
    for (unsigned i = 0; i < vl * count; i += element) {
      unsigned lane = i / element;
      int active = kind < 2 ? lane < limit : phase < 2 ? phase : (lane + phase) % 3 != 0;
      uintptr_t address = (uintptr_t)base;
      if (kind == 0) address += (int64_t)offset * vl * count + i;
      else if (kind == 1) address += index * access + i;
      else if (kind == 2) address += (int64_t)offset * (vl / 16 * access) + lane * access;
      else if (kind == 3) address += index * access + lane * access;
      else {
        uintptr_t encoded = active ? (uintptr_t)(memory + 16384 + lane * 37 + phase % 4) : 0;
        memcpy(indices + i, &encoded, sizeof(encoded));
        address = encoded + index;
      }
      if (kind >= 2) memset(mask + i, active, element);
      if (active) memcpy(scalar + i, (void *)address, access);
    }
    native_instruction(base, indices, mask, native);
    translated(base, indices, mask, got);
    if (memcmp(got, native, sizeof(got)) || memcmp(got, scalar, sizeof(got))) {
      fprintf(stderr, "%s: vl=%u phase=%u native=%d scalar=%d\n", name, vl, phase,
        memcmp(got, native, sizeof(got)), memcmp(got, scalar, sizeof(got)));
      return 1;
    }
  }
  return 0;
}
`
