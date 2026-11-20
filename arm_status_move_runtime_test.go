package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARMStatusSaveRestore(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	conditions := []string{"EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL"}
	var source, modes, predicates strings.Builder
	source.WriteString("TEXT oracle(SB),4,$0-12\n MOVW out+8(FP),R4\n")
	lane := 0
	for mode := 0; mode < 7; mode++ {
		for condition, name := range conditions {
			source.WriteString(" MOVW initial+0(FP),R0\n MOVW R0,CPSR\n MOVW CPSR,R6\n")
			if mode < 5 {
				source.WriteString(" MOVW $0,R7\n MOVW R7,CPSR\n")
			}
			source.WriteString(" MOVW selector+4(FP),R1\n CMP $0,R1\n")
			switch mode {
			case 0:
				fmt.Fprintf(&source, " MOVW.%s R6,CPSR\n MOVW CPSR,R0\n", name)
			case 1, 2:
				word := uint32(condition)<<28 | 0x012cf006
				if mode == 2 {
					word = uint32(condition)<<28 | 0x0128f006
				}
				fmt.Fprintf(&source, " WORD $%#x\n MOVW CPSR,R0\n", word)
			case 3:
				fmt.Fprintf(&source, " MOVW.%s $0xff000000,CPSR\n MOVW CPSR,R0\n", name)
			case 4:
				fmt.Fprintf(&source, " WORD $%#x\n MOVW CPSR,R0\n", uint32(condition)<<28|0x032cf4ff)
			case 5:
				fmt.Fprintf(&source, " MOVW $0,R0\n MOVW.%s CPSR,R0\n", name)
			case 6:
				fmt.Fprintf(&source, " MOVW $0,R0\n WORD $%#x\n", uint32(condition)<<28|0x010f0000)
			}
			fmt.Fprintf(&source, " AND $0xf80f0000,R0\n MOVW R0,%d(R4)\n", lane*4)
			fmt.Fprintf(&modes, "%d,", mode)
			fmt.Fprintf(&predicates, "%d,", condition)
			lane++
		}
	}
	source.WriteString(" RET\n")
	// Expectations are independently derived from ARM condition truth tables,
	// CMP selector,#0, and the selected MSR field bytes. No translated helper
	// computes the expected values and no encode/decode roundtrip can cancel.
	main := fmt.Sprintf(`package main
import "fmt"
func oracle(initial, selector uint32, out *uint32)
func passed(condition int, flags uint32) bool {
 n,z,c,v := flags&8!=0, flags&4!=0, flags&2!=0, flags&1!=0
 return []bool{z,!z,c,!c,n,!n,v,!v,c&&!z,!c||z,n==v,n!=v,!z&&n==v,z||n!=v,true}[condition]
}
func main() {
 modes,conditions := []int{%s},[]int{%s}
 var out [%d]uint32
 for initialFlags:=uint32(0);initialFlags<16;initialFlags++ {
  for q:=uint32(0);q<2;q++ { for ge:=uint32(0);ge<16;ge++ {
   initial:=initialFlags<<28|q<<27|ge<<16
   for index,selector:=range []uint32{0,1,0xffffffff,0x80000000} {
    compareFlags:=[]uint32{6,2,10,10}[index]
    oracle(initial,selector,&out[0])
    for lane,mode:=range modes {
     want:=compareFlags<<28
     take:=passed(conditions[lane],compareFlags)
     if mode>=5 { want=0; if take { want=compareFlags<<28|initial&0x080f0000 } } else if take {
      switch mode {case 0,1:want=initial;case 2:want=initial&0xf8000000;case 3,4:want=0xf8000000}
     }
     if out[lane]!=want { panic(fmt.Sprintf("Go status initial=%%08x selector=%%08x lane=%%d mode=%%d condition=%%d got=%%08x want=%%08x",initial,selector,lane,mode,conditions[lane],out[lane],want)) }
    }
   }
  } }
 }
 fmt.Println("Go CPSR save/restore: 2048 inputs x %d typed/raw conditional lanes passed")
}
`, modes.String(), predicates.String(), lane, lane)
	runARMGoSourceOracle(t, source.String(), main)
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{
		"oracle": {Name: "oracle", Args: []LLVMType{I32, I32, Ptr}, Ret: Void, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: I32, Index: 0, Field: -1},
			{Offset: 4, Type: I32, Index: 1, Field: -1},
			{Offset: 8, Type: Ptr, Index: 2, Field: -1},
		}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	oracle := fmt.Sprintf(`#include <stdint.h>
#include <stdio.h>
extern void oracle(uint32_t,uint32_t,uint32_t*);
static int passed(unsigned condition,unsigned flags) {
 int n=(flags>>3)&1,z=(flags>>2)&1,c=(flags>>1)&1,v=flags&1;
 int result[]={z,!z,c,!c,n,!n,v,!v,c&&!z,!c||z,n==v,n!=v,!z&&n==v,z||n!=v,1};
 return result[condition];
}
int main(void) {
 const unsigned modes[]={%s},conditions[]={%s};
 const uint32_t selectors[]={0,1,0xffffffffu,0x80000000u},compareFlags[]={6,2,10,10};
 uint32_t out[%d];
 for(unsigned nzcv=0;nzcv<16;nzcv++) for(unsigned q=0;q<2;q++) for(unsigned ge=0;ge<16;ge++) {
  uint32_t initial=nzcv<<28|q<<27|ge<<16;
  for(unsigned index=0;index<4;index++) {
   oracle(initial,selectors[index],out);
   for(unsigned lane=0;lane<%d;lane++) {
    unsigned mode=modes[lane],take=passed(conditions[lane],compareFlags[index]);
    uint32_t want=compareFlags[index]<<28;
    if(mode>=5) {want=take?(compareFlags[index]<<28|initial&0x080f0000u):0;}
    else if(take) {switch(mode) {case 0:case 1:want=initial;break;case 2:want=initial&0xf8000000u;break;case 3:case 4:want=0xf8000000u;break;}}
    if(out[lane]!=want) {fprintf(stderr,"LLVM status initial=%%08x selector=%%08x lane=%%u mode=%%u condition=%%u got=%%08x want=%%08x\n",initial,selectors[index],lane,mode,conditions[lane],out[lane],want);return 1;}
   }
  }
 }
 puts("LLVM CPSR save/restore: 2048 inputs x %d typed/raw conditional lanes passed");
 return 0;
}
`, modes.String(), predicates.String(), lane, lane, lane)
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"}, "status_save_restore", "armv7-unknown-linux-gnueabihf", ir, oracle,
		[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
	t.Logf("actual LLVM22 ARM object, GCC link, and QEMU execution: 2048 inputs x %d typed/raw conditional status lanes passed", lane)
}
