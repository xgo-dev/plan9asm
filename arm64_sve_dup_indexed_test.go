package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Go's encodeImm2Tsz and LLVM's sve_int_perm_dup_i encode an index within
// 512 bits, independently of the vector length currently selected at runtime.
func TestARM64SVEDupIndexedCompleteGrammar(t *testing.T) {
	var lines []string
	var forms []arm64RawSVEDupElement
	var source strings.Builder
	source.WriteString("TEXT dup_indexed_forms(SB),$0-0\n")
	for size, width := range "bhsdq" {
		for lane := 0; lane < 64>>size; lane++ {
			lines = append(lines, fmt.Sprintf("dup z2.%c,z31.%c[%d]", width, width, lane))
			forms = append(forms, arm64RawSVEDupElement{elementBits: 8 << size, lane: lane, source: 31, destination: 2})
			fmt.Fprintf(&source, "ZDUP Z31.%c[%d],Z2.%c\n", "BHSDQ"[size], lane, "BHSDQ"[size])
		}
	}
	source.WriteString("RET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)
	for index, word := range assembleARM64LLVMWords(t, lines, "+sve") {
		if got, ok := decodeARM64RawSVEDupElement(word); !ok || got != forms[index] {
			t.Errorf("%s: decoded %+v/%v, want %+v", lines[index], got, ok, forms[index])
		}
	}
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"dup_indexed_forms": {Name: "dup_indexed_forms", Ret: Void}}}); err != nil {
		t.Fatal(err)
	}
}

func TestARM64SVEDupIndexedRejectsOutOfRangeLanes(t *testing.T) {
	for size, width := range "BHSDQ" {
		for _, lane := range []int{-1, 64 >> size} {
			instruction := fmt.Sprintf("ZDUP Z31.%c[%d],Z2.%c", width, lane, width)
			t.Run(instruction, func(t *testing.T) {
				source := "TEXT bad_dup(SB),$0-0\n" + instruction + "\nRET\n"
				requireARM64SVEGoAssemblerResult(t, source, false)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					return
				}
				_, err = Translate(file, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
					Sigs: map[string]FuncSig{"bad_dup": {Name: "bad_dup", Ret: Void}}})
				if err == nil {
					t.Fatalf("accepted out-of-range lane: %s", instruction)
				}
			})
		}
	}
}

func arm64SVEDupIndexedRuntime(t *testing.T, triple string) (string, string) {
	t.Helper()
	var machine []string
	var cases strings.Builder
	count := 0
	for size, width := range "bhsdq" {
		for lane := 0; lane < 64>>size; lane++ {
			for _, destination := range []int{2, 31} {
				machine = append(machine, "ldr z31,[x1]",
					fmt.Sprintf("dup z%d.%c,z31.%c[%d]", destination, width, width, lane),
					fmt.Sprintf("str z%d,[x0]", destination), "add x0,x0,#256")
				fmt.Fprintf(&cases, "  {%d,%d},\n", 1<<size, lane)
				count++
			}
		}
	}
	machine = append(machine, "ret")
	var source, native strings.Builder
	source.WriteString("TEXT dup_indexed(SB),$0-16\nMOVD out+0(FP),R0\nMOVD input+8(FP),R1\n")
	native.WriteString("__asm__(\".text\\n.p2align 2\\n.global native_dup\\nnative_dup:\\n\"\n")
	for _, word := range assembleARM64LLVMWords(t, machine, "+sve") {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
		fmt.Fprintf(&native, "\".inst %#08x\\n\"\n", word)
	}
	native.WriteString(");\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"dup_indexed": {
			Name: "dup_indexed", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	checks := fmt.Sprintf(`
  const struct { unsigned width, lane; } cases[] = {
%s
  };
  uint8_t input[256], translated[%d*256+2], native[%d*256+2];
  for (unsigned byte = 0; byte < sizeof(input); byte++) input[byte] = 1 + byte%%251;
  memset(translated, 0xaa, sizeof(translated));
  memset(native, 0xaa, sizeof(native));
  dup_indexed(translated+1, input);
  native_dup(native+1, input);
  if (memcmp(translated, native, sizeof(native))) return 1;
  if (translated[0] != 0xaa || translated[sizeof(translated)-1] != 0xaa) return 2;
  for (unsigned test = 0; test < sizeof(cases)/sizeof(cases[0]); test++) {
    unsigned width = cases[test].width, lane = cases[test].lane;
    for (unsigned byte = 0; byte < 256; byte++) {
      unsigned expected = 0xaa;
      if (byte < vl) expected = lane*width < vl ? input[lane*width+byte%%width] : 0;
      if (translated[test*256+byte+1] != expected) {
        fprintf(stderr, "SVE DUP width=%%u lane=%%u VL=%%u byte=%%u\n", width, lane, vl, byte);
        return 3;
      }
    }
  }
`, cases.String(), count, count)
	declarations := "extern void dup_indexed(uint8_t *, const uint8_t *);\nextern void native_dup(uint8_t *, const uint8_t *);\n" + native.String()
	const lengths = "16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256"
	return ir, arm64SVEVectorLengthsMain(declarations, checks, lengths)
}

func TestARM64SVEDupIndexedLLVM(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, _ := arm64SVEDupIndexedRuntime(t, triple)
			compileLLVMToObject(t, llc, triple, "dup_indexed.ll", "dup_indexed.o", ir)
		})
	}
}
