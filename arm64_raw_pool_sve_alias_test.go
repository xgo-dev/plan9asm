package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawPoolScalableAddressAliases(t *testing.T) {
	for _, test := range []struct {
		name, body string
		offset     int
		want       bool
	}{
		{"addvl", "addvl x12,x9,#1\nldr x0,[x12]", 512, true},
		{"addpl", "addpl x12,x9,#1\nldr x0,[x12]", 512, true},
		{"negative-addvl", "addvl x12,x9,#-1\nldr x0,[x12]", 512, true},
		{"negative-addpl", "addpl x12,x9,#-1\nldr x0,[x12]", 512, true},
		{"in-place", "addvl x9,x9,#1\nldr x0,[x9]", 512, true},
		{"original-killed", "addpl x12,x9,#1\nmov x9,xzr\nldr x0,[x12]", 512, true},
		{"maximum-vl-overrun", "addvl x12,x9,#1\nldr x0,[x12]", 800, false},
		{"maximum-pl-overrun", "addpl x12,x9,#1\nldr x0,[x12]", 1000, false},
		{"maximum-vl-underrun", "addvl x12,x9,#-1\nldr x0,[x12]", 16, false},
		{"escaping-alias", "addvl x12,x9,#1\nstr x12,[x0]\nldr x0,[x12]", 512, false},
		{"stack-pointer-escape", "addvl sp,x9,#0\nldr x0,[sp]", 512, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			lines := append([]string{"adr x9,#0"}, strings.Split(test.body, "\n")...)
			lines = append(lines, "mov x9,xzr", "mov x12,xzr", "ret")
			lines[0] = fmt.Sprintf("adr x9,#%d", len(lines)*4+test.offset)
			var instructions []Instr
			for _, word := range assembleARM64LLVMWords(t, lines, "+sve") {
				instructions = append(instructions, Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
			}
			const poolWords = 256
			for i := 0; i < poolWords; i++ {
				instructions = append(instructions, Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: 0x17b4a14d}}})
			}
			points := make([]arm64RawLayoutPoint, len(instructions))
			for i := range points {
				points[i].offset = int64(i * 4)
			}
			data, _, _ := identifyARM64UnlabelledPool(Func{Instrs: instructions}, points, map[string]bool{}, 0)
			if got := len(data) == poolWords; got != test.want {
				t.Fatalf("pool proof=%v, want %v", got, test.want)
			}
		})
	}
}

func TestARM64RawPoolScalableAliasImmediateFamily(t *testing.T) {
	var assembly []string
	for _, op := range []string{"addvl", "addpl"} {
		for immediate := -32; immediate <= 31; immediate++ {
			assembly = append(assembly, fmt.Sprintf("%s x12,x9,#%d", op, immediate))
		}
	}
	words := assembleARM64LLVMWords(t, assembly, "+sve")
	for index, word := range words {
		form, ok := decodeARM64RawSVEAddress(word)
		if !ok {
			t.Fatalf("missing typed decoder for %s", assembly[index])
		}
		bounds := &arm64RawPoolBounds{size: 32768}
		got, ok := arm64RawPoolScalableAlias(form, arm64RawPoolRange{16384, 16384}, bounds)
		want := arm64RawPoolRange{32768, 0}
		for vectorBytes := int64(16); vectorBytes <= 256; vectorBytes += 16 {
			unit := vectorBytes
			if index >= 64 {
				unit /= 8
			}
			offset := 16384 + int64(index%64-32)*unit
			if offset < want.low {
				want.low = offset
			}
			if offset > want.high {
				want.high = offset
			}
		}
		if !ok || got != want {
			t.Fatalf("%s: got %+v/%v, want %+v", assembly[index], got, ok, want)
		}
	}
}

func arm64RawPoolSVEAliasesRuntime(t *testing.T, triple string) (string, string) {
	t.Helper()
	var machine []string
	var origins []int
	var cases strings.Builder
	for _, op := range []string{"addvl", "addpl"} {
		for _, immediate := range []int{-32, -1, 0, 1, 31} {
			for _, destination := range []int{9, 12} {
				origins = append(origins, len(machine))
				machine = append(machine, "adr x9,#0",
					fmt.Sprintf("%s x%d,x9,#%d", op, destination, immediate),
					fmt.Sprintf("ldr x1,[x%d]", destination),
					fmt.Sprintf("str x1,[x0,#%d]", (len(origins)-1)*8),
					"mov x9,xzr", "mov x12,xzr")
				divisor := 1
				if op == "addpl" {
					divisor = 8
				}
				fmt.Fprintf(&cases, "{%d, %d},", divisor, immediate)
			}
		}
	}
	machine = append(machine, "ret")
	for _, at := range origins {
		machine[at] = fmt.Sprintf("adr x9,#%d", (len(machine)-at)*4+8192)
	}
	var source strings.Builder
	source.WriteString("TEXT pool_sve(SB),$0-8\nMOVD out+0(FP),R0\n")
	for _, word := range assembleARM64LLVMWords(t, machine, "+sve") {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	for i := uint32(0); i < 4096; i++ {
		fmt.Fprintf(&source, "WORD $%#08x\n", i*0x9e3779b9^(i>>4))
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"pool_sve": {
			Name: "pool_sve", Args: []LLVMType{Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	checks := fmt.Sprintf(`
  const int cases[][2] = {%s};
  uint64_t out[22] = {0};
  out[0] = 0x1234;
  out[21] = 0x5678;
  pool_sve(out + 1);
  if (out[0] != 0x1234 || out[21] != 0x5678) return 1;
  for (unsigned i = 0; i < 20; i++) {
    int offset = 8192 + cases[i][1] * (int)(vl / cases[i][0]);
    uint64_t expected = 0;
    for (unsigned byte = 0; byte < 8; byte++) {
      unsigned at = (unsigned)offset + byte;
      uint32_t word = (at / 4) * UINT32_C(0x9e3779b9) ^ (at / 4 >> 4);
      expected |= (uint64_t)((word >> ((at %% 4) * 8)) & 255) << (byte * 8);
    }
    if (out[i + 1] != expected) {
      fprintf(stderr, "pool alias case=%%u VL=%%u\n", i, vl);
      return 2;
    }
  }
`, cases.String())
	return ir, arm64SVEVectorLengthMain("extern void pool_sve(uint64_t *);\n", checks)
}

func TestARM64RawPoolSVEAliasesLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, _ := arm64RawPoolSVEAliasesRuntime(t, triple)
			compileLLVMToObject(t, llc, triple, "pool_sve.ll", "pool_sve.o", ir)
		})
	}
}
