package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVEMultiplyAccumulateRuntime(t *testing.T, llc string) {
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, op := range []string{"mla", "mls", "mad", "msb"} {
		for size := 0; size < 4; size++ {
			lanes := []int{-1}
			if size > 0 && (op == "mla" || op == "mls") {
				for lane := 0; lane < 16>>size; lane++ {
					lanes = append(lanes, lane)
				}
			}
			multiplier := 7
			if size == 3 {
				multiplier = 15
			}
			for _, lane := range lanes {
				for _, destination := range []int{31, 30, multiplier} {
					name := fmt.Sprintf("multiply_accumulate_%d", len(sigs))
					native := []string{
						"ptrue p0.b", "ld1b { z20.b }, p0/z, [x3]", "cmpne p7.b, p0/z, z20.b, #0",
						"ld1b { z30.b }, p0/z, [x0]", fmt.Sprintf("ld1b { z%d.b }, p0/z, [x1]", multiplier),
						fmt.Sprintf("ld1b { z%d.b }, p0/z, [x2]", destination),
						arm64RawSVEMultiplyAccumulateAssembly(op, size, destination, 30, multiplier, 7, lane),
						fmt.Sprintf("st1b { z%d.b }, p0, [x4]", destination),
					}
					fmt.Fprintf(&source, "TEXT %s(SB),$0-40\nMOVD a+0(FP),R0\nMOVD b+8(FP),R1\nMOVD c+16(FP),R2\nMOVD mask+24(FP),R3\nMOVD out+32(FP),R4\n", name)
					for _, word := range assembleARM64LLVMWords(t, native, "+sve2") {
						fmt.Fprintf(&source, "WORD $%#08x\n", word)
					}
					source.WriteString("RET\n")
					sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
						{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
						{Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: Ptr, Index: 3, Field: -1},
						{Offset: 32, Type: Ptr, Index: 4, Field: -1},
					}}}
					fmt.Fprintf(&declarations, "extern void %s(const void *, const void *, const void *, const void *, void *);\n", name)
					assembly := strings.NewReplacer("[x0]", "[%[a]]", "[x1]", "[%[b]]", "[x2]", "[%[c]]", "[x3]", "[%[mask]]", "[x4]", "[%[out]]").Replace(strings.Join(native, "\\n\\t"))
					first, second, operator := "a", "b", "+"
					if destination == 30 {
						first = "c"
					}
					if destination == multiplier {
						second = "c"
					}
					if op == "mls" {
						operator = "-"
					}
					expression := "accumulator " + operator + " x * y"
					if op == "mad" {
						expression = "y + accumulator * x"
					} else if op == "msb" {
						expression = "y - accumulator * x"
					}
					fmt.Fprintf(&checks, `    {
      unsigned char a[256], b[256], c[256], mask[256], got[256], native[256], scalar[256];
      const unsigned element = %d;
      const int lane = %d;
      for (unsigned phase = 0; phase < 12; phase++) {
        for (unsigned i = 0; i < sizeof(a); i++) {
          a[i] = phase == 2 ? 0xff : i * 71 + phase * 83;
          b[i] = phase == 2 ? 0xff : i * 17 + phase * 51;
          c[i] = phase == 2 ? 0xff : i * 59 + phase * 29;
          mask[i] = phase < 2 ? phase : (i / element + phase * 3) %% 7 != 0;
        }
        memset(got, 0x5a, sizeof(got));
        memset(native, 0x5a, sizeof(native));
        memset(scalar, 0x5a, sizeof(scalar));
        for (unsigned i = 0; i < vl; i += element) {
          uint64_t x = 0, y = 0, accumulator = 0;
          unsigned multiplier_offset = lane < 0 ? i : (i & ~15u) + lane * element;
          memcpy(&x, %s + i, element);
          memcpy(&y, %s + multiplier_offset, element);
          memcpy(&accumulator, c + i, element);
          if (lane >= 0 || mask[i]) accumulator = %s;
          memcpy(scalar + i, &accumulator, element);
        }
        __asm__ volatile("%s" :: [a]"r"(a), [b]"r"(b), [c]"r"(c), [mask]"r"(mask), [out]"r"(native)
          : "p0", "p7", "z7", "z15", "z20", "z30", "z31", "memory");
        %s(a, b, c, mask, got);
        if (memcmp(got, native, sizeof(got)) || memcmp(got, scalar, sizeof(got))) {
          fprintf(stderr, "%s: vl=%%u phase=%%u\n", vl, phase);
          return %d;
        }
      }
    }
`, 1<<size, lane, first, second, expression, assembly, name, name, len(sigs))
				}
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
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve2"}, "raw_multiply_accumulate", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}
