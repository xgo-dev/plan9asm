package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86SwapNumericalCase struct {
	row, setup, capture      string
	width, first, last, a, b int
	nop                      bool
}

// Independent numerical directory. first/last select logical output words,
// a/b select byte offsets. All payloads are snapshotted before either write.
var x86SwapNumericalCases = []x86SwapNumericalCase{
	{row: "XCHGB AH,AL", width: 1, a: 1},
	{row: "XCHGB AL,AH", width: 1, b: 1},
	{row: "XCHGB AL,BL", width: 1, last: 1},
	{row: "XCHGB AX,BX", width: 1, last: 1},
	{row: "XCHGB AX,AL", width: 1},
	{row: "XCHGW AX,BX", width: 2, last: 1},
	{row: "XCHGW AX,AX", width: 2, nop: true},
	{row: "XCHGL AX,BX", width: 4, last: 1},
	{row: "XCHGL BX,BX", width: 4, first: 1, last: 1},
	{row: "XCHGL AX,AX", width: 4, nop: true},
	{row: "XCHGQ AX,BX", width: 8, last: 1},
	{row: "XCHGQ AX,AX", width: 8, nop: true},
	{row: "XCHGB R11B,R12", setup: "MOVQ AX,R11\nMOVQ BX,R12\n", capture: "MOVQ R11,AX\nMOVQ R12,BX\n", width: 1, last: 1},
	{row: "XCHGW R11,R12", setup: "MOVQ AX,R11\nMOVQ BX,R12\n", capture: "MOVQ R11,AX\nMOVQ R12,BX\n", width: 2, last: 1},
	{row: "XCHGL R11,R12", setup: "MOVQ AX,R11\nMOVQ BX,R12\n", capture: "MOVQ R11,AX\nMOVQ R12,BX\n", width: 4, last: 1},
	{row: "XCHGQ R11,R12", setup: "MOVQ AX,R11\nMOVQ BX,R12\n", capture: "MOVQ R11,AX\nMOVQ R12,BX\n", width: 8, last: 1},
	{row: "XCHGB CL,CH", setup: "MOVQ AX,CX\nMOVQ BX,DX\n", capture: "MOVQ CX,AX\nMOVQ DX,BX\n", width: 1, b: 1},
	{row: "XCHGB SIB,DIB", setup: "MOVQ AX,SI\nMOVQ BX,DI\n", capture: "MOVQ SI,AX\nMOVQ DI,BX\n", width: 1, last: 1},
}

func x86SwapNumericalSource() (declarations, assembly, names, metadata string) {
	var decl, source, functions, rows strings.Builder
	for index, test := range x86SwapNumericalCases {
		name := fmt.Sprint("swap", index)
		fmt.Fprintf(&decl, "func %s(out *[64]byte,x,y uint64)\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-24\nMOVQ out+0(FP),R10\nMOVQ x+8(FP),AX\nMOVQ y+16(FP),BX\nSTMXCSR 24(R10)\nCMPQ AX,BX\n%s%s\n%s", name, test.setup, test.row, test.capture)
		// A memory address through R10 requires REX, which would turn an AH
		// spelling into SPL. Capture the actual high byte before that store.
		source.WriteString("MOVQ AX,0(R10)\nMOVQ BX,8(R10)\nSETCS 16(R10)\nSETEQ 17(R10)\nSETMI 18(R10)\nSETOS 19(R10)\nLAHF\nMOVB AH,CL\nMOVB CL,20(R10)\nSTMXCSR 28(R10)\nRET\n")
		fmt.Fprintf(&functions, "%s,", name)
		fmt.Fprintf(&rows, "{%d,%d,%d,%d,%d,%t},\n", test.width, test.first, test.last, test.a, test.b, test.nop)
	}
	return decl.String(), source.String(), functions.String(), rows.String()
}

func TestX86ResultSwapOriginalGoNumericalCanariesAndFlags(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	declaration, source, functions, metadata := x86SwapNumericalSource()
	// The shared original-Go producer owns compiler/executable process groups.
	// This helper executes first-party source only, not a discovered library.
	driver := strings.ReplaceAll(x86SwapOriginalGoDriver, "FUNCTIONS", functions)
	driver = strings.ReplaceAll(driver, "METADATA", metadata)
	x86WordMultiplyRunOriginalGo(t, execution, "package wordmultiply\n"+declaration, source, driver)
	t.Log("Original Go: 18 kernels ×49 inputs, complete output/input guards and flags/MXCSR. Rosetta is not native Linux.")
}

func TestX86ResultSwapLLVMNumericalCanariesAndFlags(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	declaration, source, _, _ := x86SwapNumericalSource()
	var prototypes, rows strings.Builder
	for index, test := range x86SwapNumericalCases {
		fmt.Fprintf(&prototypes, "extern void swap%d(uint8_t*,uint64_t,uint64_t);\n", index)
		fmt.Fprintf(&rows, "{swap%d,%d,%d,%d,%d,%d,%d},\n", index, test.width, test.first, test.last, test.a, test.b, x86FloatAddSubBoolInt(test.nop))
	}
	main := strings.ReplaceAll(x86SwapLLVMDriver, "PROTOTYPES", prototypes.String())
	main = strings.ReplaceAll(main, "ROWS", rows.String())
	ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", execution.triple, "Go")
	if err != nil {
		t.Fatal(err)
	}
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("IR_default_O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			for _, level := range []string{"-O0", "-O2"} {
				t.Run("backend"+level, func(t *testing.T) {
					output := execution.compileAndRunLLVM(t, "register-swap", text, main, level)
					if string(output) != "LLVM_SWAP_882_NUMERICAL_CANARY_FLAGS_MXCSR_PASS\n" {
						t.Fatalf("complete numerical result missing: %s", output)
					}
				})
			}
		})
	}
	t.Log("18 kernels ×49 inputs, complete output/input guards and flags/MXCSR; IR default<O2> and backend O0/O2 are separate axes. Rosetta is not native Linux.")
}

const x86SwapOriginalGoDriver = `package wordmultiply
import (
 "encoding/binary"
 "fmt"
 "math/bits"
 "testing"
 "unsafe"
)
func TestOriginal(t *testing.T) {
 functions:=[]func(*[64]byte,uint64,uint64){FUNCTIONS}
 metadata:=[]struct {width,first,last,a,b int; nop bool}{METADATA}
 samples:=[]uint64{0,1,0xffffffffffffffff,0x8000000000000000,0x0123456789abcdef,0xfedcba9876543210,0x8877665544332211}
 observations:=0
 for k,program:=range functions {
  rule:=metadata[k]
  for _,x:=range samples {
   for _,y:=range samples {
    var packet,want [80]byte
    for i:=range packet {packet[i]=byte(i*37+91)}
    want=packet
    values:=[2]uint64{x,y}
    mask:=uint64(^uint64(0))
    if rule.width<8 {mask=(uint64(1)<<uint(rule.width*8))-1}
    if !rule.nop {
     a,b:=(values[rule.first]>>uint(rule.a*8))&mask,(values[rule.last]>>uint(rule.b*8))&mask
     values[rule.first]=(values[rule.first]&^(mask<<uint(rule.a*8)))|(b<<uint(rule.a*8))
     values[rule.last]=(values[rule.last]&^(mask<<uint(rule.b*8)))|(a<<uint(rule.b*8))
     if rule.width==4 {values[rule.first]&=0xffffffff;values[rule.last]&=0xffffffff}
    }
    binary.LittleEndian.PutUint64(want[8:16],values[0])
    binary.LittleEndian.PutUint64(want[16:24],values[1])
    difference:=x-y
    flag:=func(value bool)byte {if value{return 1};return 0}
    cf,zf,sf,of,pf,af:=flag(x<y),flag(x==y),flag(difference>>63!=0),flag(((x^y)&(x^difference))>>63!=0),flag(bits.OnesCount8(byte(difference))%2==0),flag((x^y^difference)&16!=0)
    want[24],want[25],want[26],want[27]=cf,zf,sf,of
    want[28]=2|cf|(pf<<2)|(af<<4)|(zf<<6)|(sf<<7)
    // Numerical first-party transport; not a caller-memory proof producer.
    out:=(*[64]byte)(unsafe.Pointer(&packet[8]))
    program(out,x,y)
    before,after:=binary.LittleEndian.Uint32(packet[32:36]),binary.LittleEndian.Uint32(packet[36:40])
    if before!=after {t.Fatalf("kernel%d changed MXCSR %x ->%x",k,before,after)}
    copy(want[32:40],packet[32:40])
    if packet!=want {t.Fatalf("kernel%d x%x y%x got%x want%x",k,x,y,packet,want)}
    observations++
   }
  }
 }
 if observations!=882 {t.Fatalf("incomplete numerical denominator %d",observations)}
 fmt.Println("ORIGINAL_SWAP_882_NUMERICAL_CANARY_FLAGS_MXCSR_PASS")
}
`

const x86SwapLLVMDriver = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
PROTOTYPES
typedef struct { void (*program)(uint8_t*,uint64_t,uint64_t); unsigned width,first,last,a,b,nop; } rule;
static const rule rules[]={ROWS};
int main(void) {
 const uint64_t samples[]={0,1,UINT64_MAX,UINT64_C(0x8000000000000000),UINT64_C(0x0123456789abcdef),UINT64_C(0xfedcba9876543210),UINT64_C(0x8877665544332211)};
 unsigned observations=0;
 for(unsigned k=0;k<sizeof(rules)/sizeof(rules[0]);k++) {
  const rule r=rules[k];
  for(unsigned i=0;i<7;i++) for(unsigned j=0;j<7;j++) {
   uint64_t x=samples[i],y=samples[j],values[2]={x,y};
   uint8_t packet[80],want[80];
   for(unsigned n=0;n<80;n++) packet[n]=(uint8_t)(n*37+91);
   memcpy(want,packet,80);
   uint64_t mask=r.width==8?UINT64_MAX:(UINT64_C(1)<<(r.width*8))-1;
   if(!r.nop) {
    const uint64_t a=(values[r.first]>>(r.a*8))&mask,b=(values[r.last]>>(r.b*8))&mask;
    values[r.first]=(values[r.first]&~(mask<<(r.a*8)))|(b<<(r.a*8));
    values[r.last]=(values[r.last]&~(mask<<(r.b*8)))|(a<<(r.b*8));
    if(r.width==4) {values[r.first]&=UINT32_MAX;values[r.last]&=UINT32_MAX;}
   }
   memcpy(want+8,values,16);
   uint64_t d=x-y;
   uint8_t cf=x<y,zf=x==y,sf=d>>63,of=((x^y)&(x^d))>>63;
   uint8_t pf=(__builtin_popcount((unsigned)(uint8_t)d)&1)==0,af=((x^y^d)&16)!=0;
   want[24]=cf;want[25]=zf;want[26]=sf;want[27]=of;
   want[28]=2|cf|(pf<<2)|(af<<4)|(zf<<6)|(sf<<7);
   uint32_t csr0,csr1;
   __asm__ volatile("stmxcsr %0":"=m"(csr0));
   r.program(packet+8,x,y);
   __asm__ volatile("stmxcsr %0":"=m"(csr1));
   uint32_t before,after;
   memcpy(&before,packet+32,4);memcpy(&after,packet+36,4);
   if(before!=csr0||after!=csr0||csr1!=csr0) {fprintf(stderr,"kernel%u MXCSR changed\n",k);return 1;}
   memcpy(want+32,packet+32,8);
   if(memcmp(packet,want,80)) {
    for(unsigned n=0;n<80;n++) if(packet[n]!=want[n]) fprintf(stderr,"kernel%u input%u,%u byte%u got%x want%x\n",k,i,j,n,packet[n],want[n]);
    return 1;
   }
   observations++;
  }
 }
 if(observations!=882) {fprintf(stderr,"incomplete denominator %u\n",observations);return 1;}
 puts("LLVM_SWAP_882_NUMERICAL_CANARY_FLAGS_MXCSR_PASS");return 0;
}
`
