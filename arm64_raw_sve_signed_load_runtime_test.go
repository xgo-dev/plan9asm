package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVESignedLoadRuntime(t *testing.T, llc string) {
	testARM64RawSVELoadRuntime(t, llc, arm64RawSVESignedLoadCases(), true)
}

func testARM64RawSVEUnsignedLoadRuntime(t *testing.T, llc string) {
	testARM64RawSVELoadRuntime(t, llc, arm64RawSVEUnsignedLoadCases(), false)
}

func testARM64RawSVELoadRuntime(t *testing.T, llc string, forms []arm64RawSVELoadCase, signed bool) {
	type runtimeCase struct {
		form                arm64RawSVELoadCase
		destination, offset int
		native              []string
	}
	var cases []runtimeCase
	var allNative []string
	for _, form := range forms {
		offsets := []int{0}
		if form.kind == "immediate" {
			offsets = []int{-8, 0, 7}
		} else if form.kind == "base" {
			offsets = []int{0, 31}
		}
		for _, offset := range offsets {
			for _, destination := range []int{30, 31} {
				base, index := 0, 30
				if form.kind == "base" {
					base = 30
				} else if form.kind == "register" {
					index = 4
				}
				native := []string{
					"ptrue p0.b", "ld1b { z30.b }, p0/z, [x1]", "ld1b { z31.b }, p0/z, [x1]",
					"ld1b { z29.b }, p0/z, [x2]", "cmpne p7.b, p0/z, z29.b, #0", "ldr x4, [x1]",
					form.loadAssembly(signed, destination, 7, base, index, offset),
					fmt.Sprintf("st1b { z%d.b }, p0, [x3]", destination),
				}
				cases = append(cases, runtimeCase{form, destination, offset, native})
				allNative = append(allNative, native...)
			}
		}
	}
	// One assembler invocation covers all cases; do not spawn a compiler for
	// every operand combination. C data/oracle loops are shared below as well.
	words := assembleARM64LLVMWords(t, allNative, "+sve")
	var source, declarations, checks strings.Builder
	declarations.WriteString(arm64SVELoadRuntimeReference)
	sigs := make(map[string]FuncSig)
	for _, test := range cases {
		name := fmt.Sprintf("ordinary_load_%d", len(sigs))
		fmt.Fprintf(&source, "TEXT %s(SB),$0-32\nMOVD base+0(FP),R0\nMOVD indices+8(FP),R1\nMOVD mask+16(FP),R2\nMOVD out+24(FP),R3\n", name)
		for _, word := range words[:len(test.native)] {
			fmt.Fprintf(&source, "WORD $%#08x\n", word)
		}
		words = words[len(test.native):]
		source.WriteString("RET\n")
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
			{Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: Ptr, Index: 3, Field: -1},
		}}}
		assembly := "mov x0, %[base]\\n\\t" + strings.NewReplacer("[x1]", "[%[indices]]", "[x2]", "[%[mask]]", "[x3]", "[%[out]]").Replace(strings.Join(test.native, "\\n\\t"))
		fmt.Fprintf(&declarations, `extern void %[1]s(const void *, const void *, const void *, void *);
static void %[1]s_native(const void *base, const void *indices, const void *mask, void *out) {
  __asm__ volatile("%[2]s" :: [base]"r"(base), [indices]"r"(indices), [mask]"r"(mask), [out]"r"(out)
    : "x0", "x4", "p0", "p7", "z29", "z30", "z31", "memory");
}
`, name, assembly)
		kind := map[string]int{"immediate": 0, "register": 1, "offset": 2, "base": 3}[test.form.kind]
		extension := map[string]int{"": 0, "uxtw": 1, "sxtw": 2}[test.form.extension]
		scale := 1
		if test.form.scaled {
			scale <<= test.form.memorySize
		}
		signedInput := 0
		if signed {
			signedInput = 1
		}
		fmt.Fprintf(&checks, "  if (check_ordinary_load(vl, %d, %d, %d, %d, %d, %d, %d, %s, %s_native, %q)) return 1;\n",
			1<<test.form.memorySize, 1<<test.form.elementSize, kind, extension, scale, test.offset, signedInput, name, name, name)
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
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve"}, "raw_ordinary_load", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}

const arm64SVELoadRuntimeReference = `
#include <sys/mman.h>
typedef void (*ordinary_load_fn)(const void *, const void *, const void *, void *);

__attribute__((noinline, noclone))
static int check_ordinary_load(unsigned vl, unsigned access, unsigned element, unsigned kind,
    unsigned extension, unsigned scale, int offset, int signed_input, ordinary_load_fn translated,
    ordinary_load_fn native_instruction, const char *name) {
  const size_t allocation = 32768;
  unsigned char *memory = mmap((void *)0x20000000, allocation, PROT_NONE,
    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (memory == MAP_FAILED) { perror("mmap"); return 1; }
  if ((uintptr_t)memory + allocation > UINT32_MAX ||
      mprotect(memory + 8192, 16384, PROT_READ | PROT_WRITE)) {
    fprintf(stderr, "cannot create guarded 32-bit-addressable SVE fixture\n");
    munmap(memory, allocation);
    return 1;
  }
  for (unsigned i = 8192; i < 24576; i++) memory[i] = i * 71 + (i >> 8);
  for (unsigned phase = 0; phase < 12; phase++) {
    unsigned char indices[256] = {0}, mask[256], got[256], native[256], scalar[256];
    unsigned char *base = phase ? memory + 16384 + phase % 4 : 0;
    int64_t scalar_index = (int64_t)(phase % 3) * 11 - 7;
    memset(got, 0x5a, sizeof(got));
    memset(native, 0x5a, sizeof(native));
    memset(scalar, 0x5a, sizeof(scalar));
    memset(scalar, 0, vl);
    for (unsigned i = 0; i < sizeof(indices); i += element) {
      unsigned lane = i / element;
      int active = phase < 2 ? phase : (lane + phase) % 3 != 0;
      for (unsigned j = 0; j < element; j++) mask[i + j] = active;
      int64_t index = (int64_t)((lane * 17 + phase * 23) % 251) - 125;
      if (extension == 1) index += 125;
      uint64_t encoded = index;
      uintptr_t address = 0;
      if (kind == 0) {
        address = (uintptr_t)base + offset * (int)(vl / element * access) + lane * access;
      } else if (kind == 1) {
        address = (uintptr_t)base + scalar_index * access + lane * access;
      } else if (kind == 2) {
        address = (uintptr_t)base + index * scale;
        if (extension) encoded = 0x9876543200000000ULL | (uint32_t)index;
        if (!active) encoded = phase ? (uintptr_t)(memory + 28672 - base) / scale : 0;
      } else {
        encoded = (uintptr_t)(memory + 16384) + index * access + phase % 4;
        address = encoded + offset * access;
        if (!active) encoded = phase ? (uintptr_t)(memory + 28672) : 0;
      }
      memcpy(indices + i, &encoded, element);
      if (i < vl && active) {
        uint64_t value = 0;
        memcpy(&value, (void *)address, access);
        if (signed_input && (value >> (access * 8 - 1))) value |= ~(UINT64_MAX >> (64 - access * 8));
        memcpy(scalar + i, &value, element);
      }
    }
    if (kind == 1) memcpy(indices, &scalar_index, sizeof(scalar_index));
    native_instruction(base, indices, mask, native);
    translated(base, indices, mask, got);
    if (memcmp(got, native, sizeof(got)) || memcmp(got, scalar, sizeof(got))) {
      fprintf(stderr, "%s: vl=%u phase=%u native=%d scalar=%d\n", name, vl, phase,
        memcmp(got, native, sizeof(got)), memcmp(got, scalar, sizeof(got)));
      munmap(memory, allocation);
      return 1;
    }
  }
  return munmap(memory, allocation) != 0;
}
`
