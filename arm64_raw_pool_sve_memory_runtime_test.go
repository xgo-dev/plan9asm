package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64RawPoolSVEMemoryRuntime(t *testing.T, triple string) (string, string) {
	t.Helper()
	var machine []string
	var origins []int
	for _, register := range []string{"z31", "p15"} {
		for _, immediate := range []int{-1, 0, 1, 3} {
			origins = append(origins, len(machine))
			machine = append(machine, "adr x9,#0",
				fmt.Sprintf("ldr %s,[x9,#%d,mul vl]", register, immediate),
				fmt.Sprintf("str %s,[x0]", register),
				"add x0,x0,#256", "mov x9,xzr")
		}
	}
	machine = append(machine, "ret")
	for _, at := range origins {
		machine[at] = fmt.Sprintf("adr x9,#%d", (len(machine)-at)*4+2048)
	}
	var source strings.Builder
	source.WriteString("TEXT pool_sve_memory(SB),$0-8\nMOVD out+0(FP),R0\n")
	for _, word := range assembleARM64LLVMWords(t, machine, "+sve") {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	for i := uint32(0); i < 1024; i++ {
		fmt.Fprintf(&source, "WORD $%#08x\n", i*0x9e3779b9^(i>>4))
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"pool_sve_memory": {
			Name: "pool_sve_memory", Args: []LLVMType{Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const checks = `
  uint8_t out[8 * 256 + 2];
  memset(out, 0xaa, sizeof(out));
  pool_sve_memory(out + 1);
  if (out[0] != 0xaa || out[sizeof(out)-1] != 0xaa) return 1;
  const int immediates[] = {-1, 0, 1, 3};
  for (unsigned test = 0; test < 8; test++) {
    unsigned width = test < 4 ? vl : vl / 8;
    int offset = 2048 + immediates[test % 4] * (int)width;
    for (unsigned byte = 0; byte < 256; byte++) {
      unsigned expected = 0xaa;
      if (byte < width) {
        unsigned at = offset + byte;
        uint32_t word = (at / 4) * UINT32_C(0x9e3779b9) ^ (at / 4 >> 4);
        expected = (word >> ((at % 4) * 8)) & 255;
      }
      if (out[test * 256 + byte + 1] != expected) {
        fprintf(stderr, "scalable pool load case=%u VL=%u byte=%u\n", test, vl, byte);
        return 2;
      }
    }
  }
`
	const lengths = "16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256"
	main := arm64SVEVectorLengthsMain("extern void pool_sve_memory(uint8_t *);\n", checks, lengths)
	return ir, main
}

func TestARM64RawPoolSVEMemoryLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, _ := arm64RawPoolSVEMemoryRuntime(t, triple)
			compileLLVMToObject(t, llc, triple, "pool_sve_memory.ll", "pool_sve_memory.o", ir)
		})
	}
}
