package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func arm64NZCVTransportMatrix() (source, original, driver, declarations string) {
	var assembly, goDeclarations, cDeclarations, goTable, cTable strings.Builder
	forms := 0
	for _, raw := range []bool{false, true} {
		for reg := 0; reg < 32; reg++ {
			if reg == 18 || reg == 28 || reg == 29 || reg == 30 {
				continue // Platform/g/FP/LR syntax/effects do not grant a native pointer-entry role.
			}
			name := fmt.Sprintf("compareNZCV%d", forms)
			forms++
			fmt.Fprintf(&goDeclarations, "func %s(*uint64,*uint64)\n", name)
			fmt.Fprintf(&cDeclarations, "extern void %s(uint64_t*,uint64_t*);\n", name)
			fmt.Fprintf(&goTable, "{%s,%v},\n", name, reg == 31)
			fmt.Fprintf(&cTable, "{%s,%d},\n", name, map[bool]int{true: 1, false: 0}[reg == 31])
			// Keep each address, canary and temporary independent of the tested
			// alias. This also covers every ordinary bank register, including
			// R27, without relying on the Go assembler's implicit scratch value.
			var safe []int
			for _, candidate := range []int{19, 20, 21, 22, 23} {
				if candidate != reg {
					safe = append(safe, candidate)
				}
			}
			in, out, tmp, canary := safe[0], safe[1], safe[2], safe[3]
			fmt.Fprintf(&assembly, "TEXT %s(SB),516,$0-16\nMOVD in+0(FP),R%d\nMOVD out+8(FP),R%d\n", name, in, out)
			fmt.Fprintf(&assembly, "MOVD $0x123456789abcdef0,R%d\n", canary)
			if reg != 31 {
				fmt.Fprintf(&assembly, "MOVD (R%d),R%d\n", in, reg)
			}
			fmt.Fprintln(&assembly, arm64NZCVInstruction(false, raw, reg))
			fmt.Fprintln(&assembly, arm64NZCVInstruction(true, raw, reg))
			// Reading into ZR discards only the GP result; NZCV is still live.
			if reg == 31 {
				fmt.Fprintf(&assembly, "MRS NZCV,R%d\nMOVD R%d,(R%d)\n", tmp, tmp, out)
			} else {
				fmt.Fprintf(&assembly, "MOVD R%d,(R%d)\n", reg, out)
			}
			for index, condition := range []string{"MI", "EQ", "CS", "VS"} {
				fmt.Fprintf(&assembly, "CSET %s,R%d\nMOVD R%d,%d(R%d)\n", condition, tmp, tmp, 8*(index+1), out)
			}
			fmt.Fprintf(&assembly, "ADC ZR,ZR,R%d\nMOVD R%d,40(R%d)\n", tmp, tmp, out)
			fmt.Fprintf(&assembly, "MOVD R%d,48(R%d)\n", canary, out)
			assembly.WriteString("RET\n")
		}
	}
	if forms != 56 {
		panic("NZCV fixture must cover both spellings of all 28 admissible pointer-entry register roles")
	}
	original = `package main
import "fmt"
` + goDeclarations.String() + `
func main() {
 forms := []struct{ fn func(*uint64,*uint64); zero bool }{
` + goTable.String() + `}
 rows:=0
 for form, f := range forms {
  for flags:=uint64(0);flags<16;flags++ {
   for _, padding:=range []uint64{0,0xffffffff0fffffff,0x1234567801234567,0x8000000000000000} {
    input:=flags<<28|padding
    var out [7]uint64
    f.fn(&input,&out[0])
    nibble:=flags
    if f.zero { nibble=0 }
    want:=[7]uint64{nibble<<28,nibble>>3&1,nibble>>2&1,nibble>>1&1,nibble&1,nibble>>1&1,0x123456789abcdef0}
    if out!=want { panic(fmt.Sprintf("form=%d flags=%x pad=%x got=%x want=%x",form,flags,padding,out,want)) }
    rows++
   }
  }
 }
 fmt.Printf("ARM64_COMPARE_ORIGINAL_PASS NZCV forms=%d rows=%d\n",len(forms),rows)
}
`
	driver = `#include <stdint.h>
#include <stdio.h>
` + cDeclarations.String() + `
int main(void) {
 struct { void (*fn)(uint64_t*,uint64_t*); int zero; } forms[]={
` + cTable.String() + `};
 uint64_t pads[]={0,UINT64_C(0xffffffff0fffffff),UINT64_C(0x1234567801234567),UINT64_C(0x8000000000000000)};
 for(unsigned form=0;form<sizeof(forms)/sizeof(forms[0]);form++) {
  for(uint64_t flags=0;flags<16;flags++) {
   for(unsigned p=0;p<4;p++) {
    uint64_t input=(flags<<28)|pads[p], out[7]={0};
    forms[form].fn(&input,out);
    uint64_t n=forms[form].zero ? 0 : flags;
    uint64_t want[]={n<<28,n>>3&1,n>>2&1,n>>1&1,n&1,n>>1&1,UINT64_C(0x123456789abcdef0)};
    for(unsigned field=0;field<7;field++) {
     if(out[field]!=want[field]) {
      fprintf(stderr,"NZCV form=%u flags=%llx padding=%u field=%u got=%llx want=%llx\n",form,(unsigned long long)flags,p,field,(unsigned long long)out[field],(unsigned long long)want[field]);
      return 1;
     }
    }
   }
  }
 }
 return 0;
}
`
	return assembly.String(), original, driver, "package compare\n" + goDeclarations.String()
}

func arm64NZCVMatrixRuntime(t *testing.T, triple, goos string, compiler, runner []string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	source, original, driver, declarations := arm64NZCVTransportMatrix()
	arm64ScalarCompareActualGo(t, source, original, goos, runner)
	arm64NZCVRunConsumers(t, llc, compiler, "nzcv_matrix", triple, source, declarations, driver, runner)
	t.Log("56 named/raw ordinary-GP/ZR alias forms × 16 NZCV states × 4 ignored-bit patterns = 3584 rows per executable")
}

func TestARM64NZCVCompleteStateNativeRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("Darwin host counterpart; required Linux/QEMU owner runs the same original-Go oracle")
	}
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	arm64NZCVMatrixRuntime(t, "aarch64-apple-darwin", "darwin", []string{clang}, nil)
}
