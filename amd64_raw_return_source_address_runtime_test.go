package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// The original native reference executes Go's actual LEA and raw C3 bytes,
// not an encoding manufactured by the translator. Register arguments here
// are an explicit numerical custom ABI, never a native-pointer permission.
func TestCrossLinuxRuntimeMatrixX86RawReturnSourceAddressNumerical(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	var assembly, oracle, checks strings.Builder
	oracle.WriteString(`#include <stdint.h>
#include <stdio.h>
#if defined(__APPLE__)
#define LABEL(name) "_" name
#else
#define LABEL(name) name
#endif
`)
	sigs := make(map[string]FuncSig)
	for _, width := range []string{"L", "Q"} {
		for _, scale := range []int{1, 2, 4, 8} {
			name := fmt.Sprintf("address%s%d", width, scale)
			source := fmt.Sprintf("TEXT %s(SB),4,$0-0\nMOV%s $-7(AX)(CX*%d),AX\nBYTE $0xc3\nRET\n", name, width, scale)
			assembly.WriteString(source)
			code := x86PackedShiftActualGoBytes(t, "amd64", source)
			instruction, err := x86asm.Decode(code, 64)
			if err != nil || instruction.Op != x86asm.LEA || instruction.Len >= len(code) || code[instruction.Len] != 0xc3 {
				t.Fatalf("actual Go address rewrite/raw return lost: %x / %v", code, err)
			}
			var bytes strings.Builder
			for _, value := range code[:instruction.Len+1] {
				if bytes.Len() != 0 {
					bytes.WriteByte(',')
				}
				fmt.Fprintf(&bytes, "0x%02x", value)
			}
			oracle.WriteString(x86OriginalSysVDeclaration("uint64_t", "original"+name, "uint64_t,uint64_t"))
			fmt.Fprintf(&oracle, `
extern uint64_t %[1]s(uint64_t,uint64_t);
__asm__(".text\n.globl " LABEL("original%[1]s") "\n"
        LABEL("original%[1]s") ":\n"
        "movq %%rdi,%%rax\nmovq %%rsi,%%rcx\n.byte %[2]s\n");
`, name, bytes.String())
			want := fmt.Sprintf("a+%d*b-7", scale)
			if width == "L" {
				want = "(uint64_t)(uint32_t)(" + want + ")"
			}
			fmt.Fprintf(&checks, `
    { uint64_t want=%[1]s;
      if (%[2]s(a,b)!=want || original%[2]s(a,b)!=want) {
        fprintf(stderr,"raw RET address %[2]s seed %%u\n",seed); return 1;
      }
    }
`, want, name)
			sigs[name] = FuncSig{Name: name, Args: []LLVMType{I64, I64}, ArgRegs: []Reg{AX, CX}, Ret: I64}
		}
	}
	oracle.WriteString(`int main(void) {
  for (unsigned seed=0; seed<256; seed++) {
    uint64_t a=UINT64_C(0x1313939382827272)*seed,b=~a;
` + checks.String() + `
  }
  puts("RAW_RET_NUMERICAL_ADDRESS_2048_OK");
  return 0;
}
`)
	file, err := Parse(ArchAMD64, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: execution.triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"-O0", "-O2"} {
		output := execution.compileAndRunLLVM(t, "raw-return-address", ir, oracle.String(), level)
		if string(output) != "RAW_RET_NUMERICAL_ADDRESS_2048_OK\n" {
			t.Fatalf("missing complete numerical original/LLVM oracle: %q", output)
		}
	}
}
