package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64RawPoolSVEContiguousRuntime(t *testing.T, triple string) (string, string) {
	t.Helper()
	machine := []string{"adr x9,#0", "mov x10,#-3"}
	var cases strings.Builder
	count := 0
	for _, signed := range []bool{false, true} {
		for memory := 0; memory < 4; memory++ {
			for element := memory; element < 4; element++ {
				if signed && element == memory {
					continue
				}
				for _, kind := range []string{"register", "immediate"} {
					form := arm64RawSVELoadCase{memorySize: memory, elementSize: element, kind: kind}
					for _, active := range []int{0, 1} {
						machine = append(machine, "ptrue p7.b")
						if active == 0 {
							machine = append(machine, "eor p7.b,p7/z,p7.b,p7.b")
						}
						machine = append(machine, form.loadAssembly(signed, 31, 7, 9, 10, -2),
							"str z31,[x0]", "add x0,x0,#256")
						negative, immediate := 0, 0
						if signed {
							negative = 1
						}
						if kind == "immediate" {
							immediate = 1
						}
						fmt.Fprintf(&cases, "  {%d,%d,%d,%d,%d},\n", 1<<memory, 1<<element, negative, immediate, active)
						count++
					}
				}
			}
		}
	}
	machine = append(machine, "mov x9,xzr", "ret")
	machine[0] = fmt.Sprintf("adr x9,#%d", len(machine)*4+2048)
	var source strings.Builder
	source.WriteString("TEXT pool_sve_contiguous(SB),$0-8\nMOVD out+0(FP),R0\n")
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
		Sigs: map[string]FuncSig{"pool_sve_contiguous": {
			Name: "pool_sve_contiguous", Args: []LLVMType{Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	checks := fmt.Sprintf(`
  const struct { unsigned memory, element, negative, immediate, active; } cases[] = {
%s
  };
  uint8_t out[%d * 256 + 2];
  memset(out, 0xaa, sizeof(out));
  pool_sve_contiguous(out + 1);
  if (out[0] != 0xaa || out[sizeof(out)-1] != 0xaa) return 1;
  for (unsigned test = 0; test < sizeof(cases)/sizeof(cases[0]); test++) {
    unsigned memory = cases[test].memory, element = cases[test].element;
    unsigned offset = cases[test].immediate ? 2048 - 2*vl*memory/element : 2048 - 3*memory;
    for (unsigned byte = 0; byte < 256; byte++) {
      unsigned expected = 0xaa;
      if (byte < vl) {
        uint64_t value = 0;
        if (cases[test].active) {
          for (unsigned part = 0; part < memory; part++) {
            unsigned at = offset + (byte/element)*memory + part;
            uint32_t word = (at/4)*UINT32_C(0x9e3779b9) ^ (at/4 >> 4);
            value |= (uint64_t)((word >> ((at%%4)*8)) & 255) << (part*8);
          }
          if (cases[test].negative && (value & (UINT64_C(1) << (memory*8-1))))
            value |= UINT64_MAX << (memory*8);
        }
        expected = (value >> ((byte%%element)*8)) & 255;
      }
      if (out[test*256+byte+1] != expected) {
        fprintf(stderr, "SVE contiguous pool case=%%u VL=%%u byte=%%u\n", test, vl, byte);
        return 2;
      }
    }
  }
`, cases.String(), count)
	const lengths = "16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256"
	return ir, arm64SVEVectorLengthsMain("extern void pool_sve_contiguous(uint8_t *);\n", checks, lengths)
}

func TestARM64RawPoolSVEContiguousLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, _ := arm64RawPoolSVEContiguousRuntime(t, triple)
			compileLLVMToObject(t, llc, triple, "pool_sve_contiguous.ll", "pool_sve_contiguous.o", ir)
		})
	}
}
