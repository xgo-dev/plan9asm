package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVEIntegerReductionRuntime(t *testing.T, llc string) {
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, op := range []string{"andv", "eorv", "orv", "addqv", "andqv", "eorqv", "orqv"} {
		for size := 0; size < 4; size++ {
			for _, destination := range []int{30, 31} {
				name := fmt.Sprintf("integer_reduce_%d", len(sigs))
				native := []string{
					"ptrue p0.b", "ld1b { z20.b }, p0/z, [x1]", "cmpne p7.b, p0/z, z20.b, #0",
					"ld1b { z30.b }, p0/z, [x0]", "ld1b { z31.b }, p0/z, [x0]",
					arm64RawSVEIntegerReductionAssembly(op, size, destination, 31, 7),
					fmt.Sprintf("st1b { z%d.b }, p0, [x2]", destination),
				}
				words := assembleARM64LLVMWords(t, native, "+sve2p1")
				fmt.Fprintf(&source, "TEXT %s(SB),$0-24\nMOVD a+0(FP),R0\nMOVD mask+8(FP),R1\nMOVD out+16(FP),R2\n", name)
				for _, word := range words {
					fmt.Fprintf(&source, "WORD $%#08x\n", word)
				}
				source.WriteString("RET\n")
				sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}}}
				fmt.Fprintf(&declarations, "extern void %s(const void *, const void *, void *);\n", name)
				// LLVM's independent assembler supplies SVE2.1 encodings, so the
				// native oracle also works with older cross-binutils assemblers.
				native[5] = fmt.Sprintf(".inst %#08x", words[5])
				assembly := strings.NewReplacer("[x0]", "[%[a]]", "[x1]", "[%[mask]]", "[x2]", "[%[out]]").Replace(strings.Join(native, "\\n\\t"))
				outputBytes, stride := 1<<size, 1<<size
				if strings.HasSuffix(op, "qv") {
					outputBytes, stride = 16, 16
				}
				identity, operator := "0", "|"
				switch {
				case strings.HasPrefix(op, "and"):
					identity, operator = "UINT64_MAX", "&"
				case strings.HasPrefix(op, "eor"):
					operator = "^"
				case strings.HasPrefix(op, "add"):
					operator = "+"
				}
				fmt.Fprintf(&checks, `    {
      unsigned char a[256], mask[256], got[256], native[256], scalar[256];
      const unsigned element = %d;
      for (unsigned phase = 0; phase < 12; phase++) {
        for (unsigned i = 0; i < sizeof(a); i++) {
          a[i] = phase == 2 ? 0xff : i * 71 + phase * 83;
          mask[i] = phase < 2 ? phase : (i / element + phase * 3) %% 7 != 0;
        }
        memset(got, 0x5a, sizeof(got));
        memset(native, 0x5a, sizeof(native));
        memset(scalar, 0x5a, sizeof(scalar));
        memset(scalar, 0, vl);
        for (unsigned j = 0; j < %d; j += element) {
          uint64_t value = %s;
          for (unsigned i = j; i < vl; i += %d) {
            if (mask[i]) {
              uint64_t input = 0;
              memcpy(&input, a + i, element);
              value = value %s input;
            }
          }
          memcpy(scalar + j, &value, element);
        }
        __asm__ volatile("%s" :: [a]"r"(a), [mask]"r"(mask), [out]"r"(native)
          : "p0", "p7", "z20", "z30", "z31", "memory");
        %s(a, mask, got);
        if (memcmp(got, native, sizeof(got)) || memcmp(got, scalar, sizeof(got))) {
          fprintf(stderr, "%s: vl=%%u phase=%%u\n", vl, phase);
          return %d;
        }
      }
    }
`, 1<<size, outputBytes, identity, stride, operator, assembly, name, name, len(sigs))
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
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve2"}, "raw_integer_reduce", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}
