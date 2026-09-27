package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64RawPoolSVEValuesRuntime(t *testing.T, triple string) (string, string) {
	t.Helper()
	var machine []string
	var origins []int
	var checks strings.Builder
	add := func(body []string, expected string) {
		at := len(machine)
		index := len(origins)
		origins = append(origins, at)
		machine = append(machine, "adr x9,#0")
		machine = append(machine, body...)
		machine = append(machine, "ldr x1,[x9]", fmt.Sprintf("str x1,[x0,#%d]", index*8), "mov x9,xzr")
		fmt.Fprintf(&checks, "  offsets[%d] = %s;\n", index, expected)
	}
	for _, op := range []string{"cnt", "inc", "dec"} {
		for width, suffix := range "bhwd" {
			for _, pattern := range []int{0, 8, 9, 13, 14, 29, 30, 31} {
				body := []string{"addvl x9,x9,#-8", "mov x10,#0",
					fmt.Sprintf("%s%c x10,#%d,mul #16", op, suffix, pattern),
					"rdvl x11,#8", "add x9,x9,x11"}
				sign := "+"
				if op == "dec" {
					sign = "-"
				}
				body = append(body, "add x9,x9,x10")
				add(body, fmt.Sprintf("8192 %s 16 * pattern_count(vl >> %d, %d)", sign, width, pattern))
			}
		}
	}
	machine = append(machine, "ret")
	for _, at := range origins {
		machine[at] = fmt.Sprintf("adr x9,#%d", (len(machine)-at)*4+8192)
	}
	var source strings.Builder
	source.WriteString("TEXT pool_sve_values(SB),$0-8\nMOVD out+0(FP),R0\n")
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
		Sigs: map[string]FuncSig{"pool_sve_values": {
			Name: "pool_sve_values", Args: []LLVMType{Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const declarations = `
extern void pool_sve_values(uint64_t *);
static int pattern_count(unsigned n, unsigned pattern) {
  const unsigned fixed[] = {0,1,2,3,4,5,6,7,8,16,32,64,128,256};
  if (pattern == 0) {
    unsigned result = 1;
    while (result <= n / 2) result *= 2;
    return result;
  }
  if (pattern < sizeof(fixed) / sizeof(fixed[0]))
    return fixed[pattern] <= n ? fixed[pattern] : 0;
  if (pattern == 29) return n - n % 4;
  if (pattern == 30) return n - n % 3;
  if (pattern == 31) return n;
  return 0;
}
`
	main := fmt.Sprintf(`
  uint64_t out[%d] = {0};
  int offsets[%d] = {0};
  out[0] = 0x1234;
  out[%d] = 0x5678;
  pool_sve_values(out + 1);
  if (out[0] != 0x1234 || out[%d] != 0x5678) return 1;
%s
  for (unsigned i = 0; i < %d; i++) {
    uint64_t expected = 0;
    for (unsigned byte = 0; byte < 8; byte++) {
      unsigned at = offsets[i] + byte;
      uint32_t word = (at / 4) * UINT32_C(0x9e3779b9) ^ (at / 4 >> 4);
      expected |= (uint64_t)((word >> ((at %% 4) * 8)) & 255) << (byte * 8);
    }
    if (out[i + 1] != expected) {
      fprintf(stderr, "pool count case=%%u VL=%%u\n", i, vl);
      return 2;
    }
  }
`, len(origins)+2, len(origins), len(origins)+1, len(origins)+1, checks.String(), len(origins))
	const lengths = "16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256"
	return ir, arm64SVEVectorLengthsMain(declarations, main, lengths)
}

func TestARM64RawPoolSVEValuesLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, _ := arm64RawPoolSVEValuesRuntime(t, triple)
			compileLLVMToObject(t, llc, triple, "pool_sve_values.ll", "pool_sve_values.o", ir)
		})
	}
}
