package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVEFloatCompareRuntime(t *testing.T, llc string) {
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	for _, width := range []struct {
		suffix, load, ctype, samples string
		bytes                        int
	}{
		{"h", "h", "uint16_t", "0, 0x8000, 0x3c00, 0xbc00, 0x7c00, 0xfc00, 0x7e01, 0x7c01, 1, 0x8001", 2},
		{"s", "w", "uint32_t", "0, 0x80000000, 0x3f800000, 0xbf800000, 0x7f800000, 0xff800000, 0x7fc00001, 0x7f800001, 1, 0x80000001", 4},
		{"d", "d", "uint64_t", "0, 0x8000000000000000ULL, 0x3ff0000000000000ULL, 0xbff0000000000000ULL, 0x7ff0000000000000ULL, 0xfff0000000000000ULL, 0x7ff8000000000001ULL, 0x7ff0000000000001ULL, 1, 0x8000000000000001ULL", 8},
	} {
		for _, zero := range []bool{false, true} {
			ops := []string{"facge", "facgt", "fcmeq", "fcmge", "fcmgt", "fcmne", "fcmuo"}
			if zero {
				ops = []string{"fcmeq", "fcmge", "fcmgt", "fcmle", "fcmlt", "fcmne"}
			}
			for _, op := range ops {
				for _, pattern := range []string{"all", "vl3"} {
					name := fmt.Sprintf("compare_%s_%s_%t_%s", op, width.suffix, zero, pattern)
					second := "z31." + width.suffix
					if zero {
						second = "#0.0"
					}
					native := []string{
						"ptrue p0.b",
						fmt.Sprintf("ptrue p7.%s, %s", width.suffix, pattern),
						fmt.Sprintf("ld1%s { z30.%s }, p0/z, [x0]", width.load, width.suffix),
						fmt.Sprintf("ld1%s { z31.%s }, p0/z, [x1]", width.load, width.suffix),
						fmt.Sprintf("%s p15.%s, p7/z, z30.%s, %s", op, width.suffix, width.suffix, second),
						"mov z0.b, #-1",
						"mov z1.b, #0",
						fmt.Sprintf("sel z0.%s, p15, z0.%s, z1.%s", width.suffix, width.suffix, width.suffix),
						"st1b { z0.b }, p0, [x2]",
					}
					fmt.Fprintf(&source, "TEXT %s(SB),$0-24\nMOVD a+0(FP),R0\nMOVD b+8(FP),R1\nMOVD out+16(FP),R2\n", name)
					for _, word := range assembleARM64LLVMWords(t, native, "+sve") {
						fmt.Fprintf(&source, "WORD $%#08x\n", word)
					}
					source.WriteString("RET\n")
					sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
						{Offset: 0, Type: Ptr, Index: 0, Field: -1},
						{Offset: 8, Type: Ptr, Index: 1, Field: -1},
						{Offset: 16, Type: Ptr, Index: 2, Field: -1},
					}}}
					fmt.Fprintf(&declarations, "extern void %s(const void *, const void *, void *);\n", name)
					assembly := strings.NewReplacer("[x0]", "[%[a]]", "[x1]", "[%[b]]", "[x2]", "[%[out]]").Replace(strings.Join(native, "\\n\\t"))
					fmt.Fprintf(&checks, `    {
      const %s samples[] = {%s};
      for (unsigned shift = 0; shift < 10; shift++) {
        %s a[128], b[128];
        for (unsigned i = 0; i < vl / %d; i++) {
          a[i] = samples[(i + shift) %% 10];
          b[i] = samples[(9 - i %% 10 + shift) %% 10];
        }
        unsigned char got[256] = {0}, want[256] = {0};
        __asm__ volatile("%s" :: [a]"r"(a), [b]"r"(b), [out]"r"(want)
          : "p0", "p7", "p15", "z0", "z1", "z30", "z31", "memory");
        %s(a, b, got);
        if (memcmp(got, want, vl) != 0) {
          fprintf(stderr, "%s: vl=%%u shift=%%u\n", vl, shift);
          return %d;
        }
      }
    }
`, width.ctype, width.samples, width.ctype, width.bytes, assembly, name, name, len(sigs))
				}
			}
		}
	}
	main := arm64SVEVectorLengthMain(declarations.String(), checks.String())
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	const triple = "aarch64-unknown-linux-gnu"
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.2-a+sve"}, "raw_float_compare", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}
