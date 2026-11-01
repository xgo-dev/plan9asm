package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVEIntegerDotRuntime(t *testing.T, llc string) {
	var source, declarations, checks strings.Builder
	declarations.WriteString(`
static int64_t dot_element(const unsigned char *data, unsigned index, unsigned bytes, int is_signed) {
  uint16_t value = 0;
  memcpy(&value, data + index * bytes, bytes);
  if (is_signed) return bytes == 1 ? (int8_t)value : (int16_t)value;
  return value;
}
`)
	sigs := make(map[string]FuncSig)
	for _, form := range arm64RawSVEIntegerDotCases() {
		// QEMU 10.2 implements SVE2.1 but not the SVE2.3 B->H dot products.
		// The latter retain independent encoding and three-platform object tests.
		if form.destination == "h" {
			continue
		}
		lanes := 1
		if form.indexed {
			lanes = form.lanes
		}
		first := form.maximumVector
		for lane := 0; lane < lanes; lane++ {
			for _, destination := range []int{first, 30, 31} {
				name := fmt.Sprintf("integerdot_%d", len(sigs))
				native := []string{
					"ptrue p0.b",
					fmt.Sprintf("ld1b { z%d.b }, p0/z, [x0]", first),
					"ld1b { z30.b }, p0/z, [x1]",
					"ld1b { z31.b }, p0/z, [x2]",
					form.assembly(destination, 30, first, lane),
					fmt.Sprintf("st1b { z%d.b }, p0, [x3]", destination),
				}
				fmt.Fprintf(&source, "TEXT %s(SB),$0-32\nMOVD a+0(FP),R0\nMOVD b+8(FP),R1\nMOVD acc+16(FP),R2\nMOVD out+24(FP),R3\n", name)
				words := assembleARM64LLVMWords(t, native, "+sve2p1,+i8mm")
				for _, word := range words {
					fmt.Fprintf(&source, "WORD $%#08x\n", word)
				}
				source.WriteString("RET\n")
				sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
					{Offset: 24, Type: Ptr, Index: 3, Field: -1},
				}}}
				fmt.Fprintf(&declarations, "extern void %s(const void *, const void *, const void *, void *);\n", name)
				// The cross assembler can predate SVE2.1. Encode just the tested
				// instruction with the independently checked LLVM MC word.
				native[4] = fmt.Sprintf(".inst %#08x", words[4])
				assembly := strings.NewReplacer("[x0]", "[%[a]]", "[x1]", "[%[b]]", "[x2]", "[%[acc]]", "[x3]", "[%[out]]").Replace(strings.Join(native, "\\n\\t"))
				sourceBytes, destinationBytes := 1, 4
				if form.source == "h" {
					sourceBytes = 2
				}
				if form.destination == "d" {
					destinationBytes = 8
				}
				firstSigned, secondSigned, indexed := 0, 0, 0
				if form.op == "sdot" || form.op == "usdot" {
					firstSigned = 1
				}
				if form.op == "sdot" || form.op == "sudot" {
					secondSigned = 1
				}
				if form.indexed {
					indexed = 1
				}
				accumulator := "acc"
				if destination == first {
					accumulator = "a"
				} else if destination == 30 {
					accumulator = "b"
				}
				fmt.Fprintf(&checks, `    {
      static const unsigned char edge[] = {0, 1, 127, 128, 255, 254, 85, 170};
      unsigned char a[256], b[256], acc[256], got[256], want[256], oracle[256];
      const unsigned source_bytes = %d, destination_bytes = %d;
      for (unsigned phase = 0; phase < 12; phase++) {
        for (unsigned i = 0; i < sizeof(a); i++) {
          a[i] = phase < 8 ? edge[(phase + i) %% 8] : i * 37 + phase * 13;
          b[i] = phase < 8 ? edge[(phase * 3 + i / 2) %% 8] : i * 17 + phase * 71;
          acc[i] = phase < 8 ? edge[phase] : i * 29 + phase;
        }
        memset(got, 0x5a, sizeof(got));
        memset(want, 0x5a, sizeof(want));
        memset(oracle, 0x5a, sizeof(oracle));
        for (unsigned i = 0; i < vl / destination_bytes; i++) {
          uint64_t value = 0;
          memcpy(&value, %s + i * destination_bytes, destination_bytes);
          unsigned group = destination_bytes / source_bytes;
          for (unsigned j = 0; j < group; j++) {
            unsigned first_index = %d ? (i * destination_bytes / 16) * (16 / source_bytes) + %d * group + j : i * group + j;
            int64_t first = dot_element(a, first_index, source_bytes, %d);
            int64_t second = dot_element(b, i * group + j, source_bytes, %d);
            value += (uint64_t)(first * second);
          }
          memcpy(oracle + i * destination_bytes, &value, destination_bytes);
        }
        __asm__ volatile("%s" :: [a]"r"(a), [b]"r"(b), [acc]"r"(acc), [out]"r"(want)
          : "p0", "z7", "z15", "z30", "z31", "memory");
        %s(a, b, acc, got);
        if (memcmp(got, want, sizeof(got)) != 0 || memcmp(got, oracle, sizeof(got)) != 0) {
          fprintf(stderr, "%s: vl=%%u phase=%%u\n", vl, phase);
          for (unsigned i = 0; i < sizeof(got); i++) {
            if (got[i] != want[i] || got[i] != oracle[i]) {
              fprintf(stderr, "byte %%u: got %%02x, native %%02x, scalar %%02x\n", i, got[i], want[i], oracle[i]);
              break;
            }
          }
          return %d;
        }
      }
    }
`, sourceBytes, destinationBytes, accumulator, indexed, lane, firstSigned, secondSigned,
					assembly, name, form.assembly(destination, 30, first, lane), len(sigs))
			}
		}
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
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.6-a+sve2+i8mm"}, "raw_integerdot", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}
