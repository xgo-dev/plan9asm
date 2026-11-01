package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Independent axes from Go 1.27 _yvpbroadcastb: B/W/D/Q, X/Y/Z,
// memory/X/GP source, unmasked/merge/zero. Observe every overlapping view,
// including upper bits, and suppress masked-off scalar memory faults.
func integerBroadcastViews(t *testing.T, triple string) (string, string) {
	t.Helper()
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	index := 0
	for _, spec := range []struct {
		op   string
		bits int
	}{
		{"VPBROADCASTB", 8}, {"VPBROADCASTW", 16}, {"VPBROADCASTD", 32}, {"VPBROADCASTQ", 64},
	} {
		for width, dst := range []string{"X0", "Y0", "Z0"} {
			for input := 0; input < 3; input++ {
				for mask := 0; mask < 3; mask++ {
					name := fmt.Sprintf("integer_broadcast_%d", index)
					index++
					fmt.Fprintf(&source, "TEXT %s(SB),4,$0-32\nMOVQ old+0(FP),BX\nMOVQ src+8(FP),AX\nMOVQ out+16(FP),DI\nMOVQ mask+24(FP),CX\nKMOVQ CX,K7\nVMOVUPS (BX),Z0\n", name)
					operand := "(AX)"
					if input == 1 {
						source.WriteString("VMOVUPS (AX),X1\n")
						operand = "X1"
					} else if input == 2 {
						source.WriteString("MOVQ (AX),R8\n")
						operand = "R8"
					}
					op, predicate := spec.op, ""
					if mask != 0 {
						predicate = "K7,"
					}
					if mask == 2 {
						op += ".Z"
					}
					fmt.Fprintf(&source, "%s %s,%s%s\nVMOVUPS Z0,(DI)\nVMOVUPS Y0,64(DI)\nVMOVUPS X0,96(DI)\nRET\n", op, operand, predicate, dst)
					sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void,
						Frame: FrameLayout{Params: []FrameSlot{
							{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
							{Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: I64, Index: 3, Field: -1},
						}},
					}
					fmt.Fprintf(&declarations, "extern void %s(const void *,const void *,void *,uint64_t);\n", name)
					fmt.Fprintf(&checks, "if (check(%s,%d,%d,%d,%d)) return 1;\n", name, 16<<width, spec.bits/8, mask, input)
				}
			}
		}
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	main := `
#include <stdint.h>
#include <stdio.h>
` + declarations.String() + `
static int check(void (*fn)(const void *,const void *,void *,uint64_t),int width,int lane,int form,int input) {
  const uint64_t masks[] = {0, 1, 2, UINT64_C(0xaaaaaaaaaaaaaaaa), UINT64_MAX, UINT64_C(1) << 63};
  for (unsigned m = 0; m < sizeof(masks)/sizeof(masks[0]); m++) {
    uint8_t old[64], src[16], output[112];
    for (int i = 0; i < 64; i++) old[i] = (uint8_t)(197-i*3);
    for (int i = 0; i < 16; i++) src[i] = (uint8_t)(17+i*7);
    uint64_t relevant = width/lane == 64 ? UINT64_MAX : (UINT64_C(1) << (width/lane)) - 1;
    int inactiveMemory = input == 0 && form != 0 && (masks[m] & relevant) == 0;
    fn(old, inactiveMemory ? 0 : src, output, masks[m]);
    for (int view = 0; view < 3; view++) {
      int offset = view == 0 ? 0 : view == 1 ? 64 : 96;
      for (int i = 0; i < (64 >> view); i++) {
        int enabled = form == 0 || ((masks[m] >> (i/lane)) & 1);
        uint8_t want = i >= width ? 0 : enabled ? src[i%lane] : form == 2 ? 0 : old[i];
        if (output[offset+i] != want) {
          fprintf(stderr,"broadcast width=%d lane=%d form=%d input=%d mask=%u view=%d byte=%d got=%u want=%u\n",width,lane,form,input,m,view,i,output[offset+i],want);
          return 1;
        }
      }
    }
  }
  return 0;
}
int main(void) {
` + checks.String() + "return 0;\n}\n"
	return ir, main
}

func TestIntegerBroadcastRegisterViews(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"x86_64-apple-macosx", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, main := integerBroadcastViews(t, triple)
			compileLLVMToObject(t, llc, triple, "integer_broadcast.ll", "integer_broadcast.o", ir)
			var runner []string
			execute := runtime.GOARCH == "amd64" && triple == testTargetTriple(runtime.GOOS, runtime.GOARCH)
			if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && triple == "x86_64-apple-macosx" && rosettaAvailable() {
				execute = true
				runner = []string{"/usr/bin/arch", "-x86_64"}
			}
			if execute {
				clang := findLLVM22Tool("clang")
				if clang == "" {
					t.Fatal("LLVM 22 clang not found")
				}
				compileAndRunRuntimeTestForTarget(t, llc, clang, "integer_broadcast", triple, ir, main, runner)
			}
		})
	}
}
