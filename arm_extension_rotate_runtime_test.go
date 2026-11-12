package plan9asm

import (
	"fmt"
	"math/bits"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARMExtensionRotateZeroIsNotRRX(t *testing.T) {
	llc := requireARMScalarRuntime(t)
	var source, goVectors, cVectors strings.Builder
	source.WriteString("TEXT oracle(SB),4,$0-20\n MOVW value+0(FP),R0\n MOVW out+16(FP),R4\n MOVW status+12(FP),R6\n MOVW R6,CPSR\n")
	lane := 0
	for _, op := range []string{"MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU"} {
		for _, rotation := range []int{0, 8, 16, 24} {
			fmt.Fprintf(&source, " %s R0@>%d,R3\n MOVW R3,%d(R4)\n", op, rotation, lane*4)
			lane++
		}
	}
	fmt.Fprintf(&source, " MOVW CPSR,R6\n SRL $28,R6\n MOVW R6,%d(R4)\n RET\n", lane*4)
	for _, value := range []uint32{0, 0x80ff7f01, 0xffffffff, 0x12345678} {
		for flags := uint32(0); flags < 16; flags++ {
			fmt.Fprintf(&goVectors, "{%d,%d,[25]uint32{", value, flags<<28)
			fmt.Fprintf(&cVectors, "{%du,%du,{", value, flags<<28)
			for _, op := range []string{"MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU"} {
				for _, rotation := range []int{0, 8, 16, 24} {
					rotated := bits.RotateLeft32(value, -rotation)
					var want uint32
					switch op {
					case "MOVB", "MOVBS":
						want = uint32(int32(int8(rotated)))
					case "MOVBU":
						want = uint32(uint8(rotated))
					case "MOVH", "MOVHS":
						want = uint32(int32(int16(rotated)))
					case "MOVHU":
						want = uint32(uint16(rotated))
					}
					fmt.Fprintf(&goVectors, "%d,", want)
					fmt.Fprintf(&cVectors, "%du,", want)
				}
			}
			fmt.Fprintf(&goVectors, "%d}},\n", flags)
			fmt.Fprintf(&cVectors, "%du}},\n", flags)
		}
	}
	goMain := fmt.Sprintf(`package main
import "fmt"
func oracle(value,amount,lhs,status uint32,out *[25]uint32)
var vectors=[]struct{value,status uint32;want [25]uint32}{%s}
func main(){for i,v:=range vectors{var out [25]uint32;oracle(v.value,0,0,v.status,&out);if out!=v.want{panic(fmt.Sprintf("Go extension vector=%%d got=%%x want=%%x",i,out,v.want))}};fmt.Println("all extension rotations preserve NZCV; rotation zero is not RRX")}
`, goVectors.String())
	runARMGoSourceOracle(t, source.String(), goMain)
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: armShifterOracleSignature()})
	if err != nil {
		t.Fatal(err)
	}
	cMain := fmt.Sprintf(`#include <stdint.h>
#include <stdio.h>
extern void oracle(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t*);
static const struct{uint32_t value,status,want[25];}vectors[]={%s};
int main(void){for(unsigned i=0;i<sizeof(vectors)/sizeof(vectors[0]);i++){uint32_t out[25]={0};oracle(vectors[i].value,0,0,vectors[i].status,out);for(unsigned j=0;j<25;j++)if(out[j]!=vectors[i].want[j]){fprintf(stderr,"LLVM extension vector=%%u lane=%%u got=%%x want=%%x\n",i,j,out[j],vectors[i].want[j]);return 1;}}return 0;}
`, cVectors.String())
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{"arm-linux-gnueabihf-gcc", "-no-pie"}, "extension_rotations", "armv7-unknown-linux-gnueabihf", ir, cMain,
		[]string{"qemu-arm", "-L", "/usr/arm-linux-gnueabihf"})
}
