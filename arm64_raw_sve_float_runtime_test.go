package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func testARM64RawSVEFloatRuntime(t *testing.T, llc string) {
	var source, declarations, checks strings.Builder
	sigs := make(map[string]FuncSig)
	ops := []string{"fadd", "fsub", "fmul", "faddv", "fadda", "frecpe", "frsqrte"}
	for _, op := range []string{"fabs", "fneg", "frecpx", "frinta", "frinti", "frintm", "frintn", "frintp", "frintx", "frintz", "fsqrt"} {
		ops = append(ops, op, op+"_zero")
	}
	for _, op := range []string{"fmax", "fmin", "fmaxnm", "fminnm"} {
		ops = append(ops, op, op+"_zeroimm", op+"_oneimm", op+"p", op+"v")
	}
	for _, width := range []struct {
		suffix, scalar, ctype string
		bytes                 int
	}{
		{"h", "h", "_Float16", 2}, {"s", "s", "float", 4}, {"d", "d", "double", 8},
	} {
		for _, op := range ops {
			minmax := strings.HasPrefix(op, "fmax") || strings.HasPrefix(op, "fmin")
			name := op + "_" + width.suffix
			loadStore := map[int]string{2: "h", 4: "w", 8: "d"}[width.bytes]
			native := []string{
				"ptrue p7.b",
				fmt.Sprintf("ptrue p0.%s, vl3", width.suffix),
				fmt.Sprintf("ld1%s { z0.%s }, p7/z, [x0]", loadStore, width.suffix),
				fmt.Sprintf("ld1%s { z1.%s }, p7/z, [x1]", loadStore, width.suffix),
				fmt.Sprintf("ld1%s { z5.%s }, p7/z, [x0]", loadStore, width.suffix),
			}
			count := "vl"
			if op == "faddv" || op == "fadda" {
				native[2] = fmt.Sprintf("ld1%s { z0.%s }, p7/z, [x1]", loadStore, width.suffix)
				instruction := fmt.Sprintf("faddv %s0, p0, z5.%s", width.scalar, width.suffix)
				if op == "fadda" {
					instruction = fmt.Sprintf("fadda %s0, p0, %s0, z5.%s", width.scalar, width.scalar, width.suffix)
				}
				native = append(native, instruction, "st1b { z0.b }, p7, [x2]")
			} else if minmax {
				instruction := ""
				if strings.HasSuffix(op, "v") {
					instruction = fmt.Sprintf("%s %s0, p0, z5.%s", op, width.scalar, width.suffix)
				} else {
					operation, second := op, "z1."+width.suffix
					if strings.HasSuffix(op, "imm") {
						operation = strings.SplitN(op, "_", 2)[0]
						second = "#0.0"
						if strings.HasSuffix(op, "_oneimm") {
							second = "#1.0"
						}
					}
					instruction = fmt.Sprintf("%s z0.%s, p0/m, z0.%s, %s", operation, width.suffix, width.suffix, second)
				}
				native = append(native, instruction, "st1b { z0.b }, p7, [x2]")
			} else if op == "fadd" || op == "fsub" || op == "fmul" {
				native = append(native, fmt.Sprintf("%s z0.%s, p0/m, z0.%s, z1.%s", op, width.suffix, width.suffix, width.suffix),
					"st1b { z0.b }, p7, [x2]")
			} else if op == "frecpe" || op == "frsqrte" {
				native = append(native, fmt.Sprintf("%s z0.%s, z5.%s", op, width.suffix, width.suffix), "st1b { z0.b }, p7, [x2]")
			} else {
				operation := strings.TrimSuffix(op, "_zero")
				native = append(native, fmt.Sprintf("%s z0.%s, p0/m, z5.%s", operation, width.suffix, width.suffix), "st1b { z0.b }, p7, [x2]")
			}
			raw := append([]string(nil), native...)
			if strings.HasSuffix(op, "_zero") {
				// QEMU's SVE1 oracle expresses newer zeroing encodings as a
				// cleared destination followed by the native merging operation.
				at := len(native) - 2
				raw[at] = strings.Replace(raw[at], "p0/m", "p0/z", 1)
				native = append(native[:at:at], "mov z0.b, #0", native[at], native[at+1])
			}
			words := assembleARM64LLVMWords(t, raw, "+sve2p2")
			fmt.Fprintf(&source, "TEXT %s(SB),$0-24\nMOVD a+0(FP),R0\nMOVD b+8(FP),R1\nMOVD out+16(FP),R2\n", name)
			for _, word := range words {
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
			samples, sampleCount, phases := "65504, -65504, 0.125, -0.0, 0.00001, -1.0", 6, 1
			second := fmt.Sprintf("(%s)(i + 2)", width.ctype)
			if minmax {
				samples = "0.0, -0.0, __builtin_nan(\"\"), 1.0, -1.0, __builtin_inf(), -__builtin_inf(), 0.00001, 65504, -65504"
				sampleCount, phases = 10, 10
				second = fmt.Sprintf("(%s)samples[(i + phase + 3) %% 10]", width.ctype)
			}
			fmt.Fprintf(&checks, `    {
    for (unsigned phase = 0; phase < %d; phase++) {
      %s a[128], b[128];
      const double samples[] = {%s};
      for (unsigned i = 0; i < vl / %d; i++) {
        a[i] = (%s)samples[(i + phase) %% %d];
        b[i] = %s;
      }
      unsigned char got[256] = {0}, want[256] = {0};
      __asm__ volatile("%s" :: [a]"r"(a), [b]"r"(b), [out]"r"(want)
        : "p0", "p7", "z0", "z1", "z5", "memory");
      %s(a, b, got);
      if (memcmp(got, want, %s) != 0) {
        fprintf(stderr, "%s: vl=%%u phase=%%u\n", vl, phase);
        return %d;
      }
    }
    }
`, phases, width.ctype, samples, width.bytes, width.ctype, sampleCount, second, assembly, name, count, name, len(sigs))
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
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"aarch64-linux-gnu-gcc", "-march=armv8.5-a+sve2"}, "raw_float_sve", triple, ir, main,
		[]string{"qemu-aarch64", "-cpu", "max,sve-max-vq=16", "-L", "/usr/aarch64-linux-gnu"})
}
