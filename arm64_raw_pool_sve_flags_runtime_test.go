package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64RawPoolSVEFlagsRuntime(t *testing.T, triple string) (string, string) {
	t.Helper()
	forms := arm64PoolSVEFlagPreservingForms()
	machine := []string{
		"adr x9,#0", "ptrue p7.b", "ptrue p15.b",
		"dup z9.b,#2", "dup z30.b,#3", "dup z31.b,#4",
	}
	for index, form := range forms {
		machine = append(machine, "cmp x1,#15", form, "b.hi #12",
			"ldrb w2,[x9,x1]", fmt.Sprintf("str x2,[x0,#%d]", index*8))
	}
	// Keep the vector computation observable as well as the guarded reads.
	machine = append(machine, fmt.Sprintf("add x0,x0,#%d", len(forms)*8),
		"str z31,[x0]", "add x0,x0,#256", "str z9,[x0]",
		"add x0,x0,#256", "str p9,[x0]", "mov x9,xzr", "ret")
	machine[0] = fmt.Sprintf("adr x9,#%d", len(machine)*4)
	var source strings.Builder
	source.WriteString("TEXT pool_sve_flags(SB),$0-16\nMOVD out+0(FP),R0\nMOVD index+8(FP),R1\n")
	for _, word := range assembleARM64LLVMWords(t, machine, "+sve2p1") {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	for i := 0; i < 4; i++ {
		fmt.Fprintf(&source, "WORD $%#08x\n", uint32(0x17b4a140+i))
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"pool_sve_flags": {
			Name: "pool_sve_flags", Args: []LLVMType{Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	checks := fmt.Sprintf(`
  const uint32_t words[4] = {0x17b4a140, 0x17b4a141, 0x17b4a142, 0x17b4a143};
  const uint64_t indexes[] = {0, 1, 3, 7, 15, 16, 255, UINT64_C(1)<<32, UINT64_MAX};
  uint8_t bytes[16];
  memcpy(bytes, words, sizeof(bytes));
  for (unsigned input = 0; input < sizeof(indexes)/sizeof(indexes[0]); input++) {
    uint64_t out[%d + 68 + 2];
    memset(out, 0xaa, sizeof(out));
    pool_sve_flags(out + 1, indexes[input]);
    if (out[0] != UINT64_C(0xaaaaaaaaaaaaaaaa) ||
        out[sizeof(out)/sizeof(out[0])-1] != UINT64_C(0xaaaaaaaaaaaaaaaa)) return 1;
    uint64_t expected = indexes[input] <= 15 ? bytes[indexes[input]] : UINT64_C(0xaaaaaaaaaaaaaaaa);
    for (unsigned form = 0; form < %d; form++) {
      if (out[form+1] != expected) {
        fprintf(stderr, "SVE pool flags form=%%u VL=%%u input=%%u\n", form, vl, input);
        return 2;
      }
    }
  }
`, len(forms), len(forms))
	const lengths = "16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256"
	return ir, arm64SVEVectorLengthsMain("extern void pool_sve_flags(uint64_t *, uint64_t);\n", checks, lengths)
}

func TestARM64RawPoolSVEFlagsLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, _ := arm64RawPoolSVEFlagsRuntime(t, triple)
			compileLLVMToObject(t, llc, triple, "pool_sve_flags.ll", "pool_sve_flags.o", ir)
		})
	}
}
