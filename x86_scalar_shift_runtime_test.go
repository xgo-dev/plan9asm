package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86ScalarShiftNumericalRule struct {
	row                                          string
	bits, kind, destination, source, count, high int
}

func x86ScalarShiftNumericalRules() []x86ScalarShiftNumericalRule {
	var rules []x86ScalarShiftNumericalRule
	for kind, stem := range x86ScalarShiftTestStems {
		for _, width := range []struct {
			suffix string
			bits   int
		}{{"B", 8}, {"W", 16}, {"L", 32}, {"Q", 64}} {
			for _, count := range []string{"CL", "CX"} {
				rules = append(rules, x86ScalarShiftNumericalRule{row: stem + width.suffix + " " + count + ",AX", bits: width.bits, kind: kind, count: 2})
			}
			if width.bits == 8 {
				rules = append(rules, x86ScalarShiftNumericalRule{row: stem + "B CL,AH", bits: 8, kind: kind, count: 2, high: 1})
			}
			// Immediate zero is a distinct physical encoding and still writes
			// r32's upper half, even though all flags remain unchanged.
			rules = append(rules, x86ScalarShiftNumericalRule{row: stem + width.suffix + " $0,AX", bits: width.bits, kind: kind, count: -1})
		}
	}
	for _, width := range []struct {
		suffix string
		bits   int
	}{{"W", 16}, {"L", 32}, {"Q", 64}} {
		for kind, stem := range []string{"SHL", "SHR"} {
			for _, count := range []string{"CL", "CX"} {
				rules = append(rules, x86ScalarShiftNumericalRule{row: stem + width.suffix + " " + count + ",BX,AX", bits: width.bits, kind: 8 + kind, source: 1, count: 2})
			}
			rules = append(rules, x86ScalarShiftNumericalRule{row: stem + width.suffix + " CL,AX,AX", bits: width.bits, kind: 8 + kind, count: 2})
		}
	}
	for kind, stem := range []string{"SARX", "SHLX", "SHRX", "RORX"} {
		for _, width := range []struct {
			suffix string
			bits   int
		}{{"L", 32}, {"Q", 64}} {
			if stem == "RORX" {
				rules = append(rules, x86ScalarShiftNumericalRule{row: stem + width.suffix + " $1,BX,AX", bits: width.bits, kind: 10 + kind, source: 1, count: -2})
				rules = append(rules, x86ScalarShiftNumericalRule{row: stem + width.suffix + " $0,AX,AX", bits: width.bits, kind: 10 + kind, count: -1})
				continue
			}
			for _, axes := range []struct {
				pair                       string
				destination, source, count int
			}{{"CX,BX,AX", 0, 1, 2}, {"AX,BX,AX", 0, 1, 0}, {"CX,CX,CX", 2, 2, 2}} {
				rules = append(rules, x86ScalarShiftNumericalRule{row: stem + width.suffix + " " + axes.pair, bits: width.bits, kind: 10 + kind, destination: axes.destination, source: axes.source, count: axes.count})
			}
		}
	}
	return rules
}

func x86ScalarShiftNumericalSource(t *testing.T, raw bool) (string, string, string, string) {
	t.Helper()
	var decl, asm, names, metadata strings.Builder
	for index, rule := range x86ScalarShiftNumericalRules() {
		name := fmt.Sprint("shift", index)
		fmt.Fprintf(&decl, "func %s(out *[64]byte,x,y,count uint64)\n", name)
		fmt.Fprintf(&asm, "TEXT ·%s(SB),4,$0-32\nMOVQ out+0(FP),R10\nMOVQ x+8(FP),AX\nMOVQ y+16(FP),BX\nMOVQ count+24(FP),CX\nSTMXCSR 32(R10)\nCMPQ AX,BX\n", name)
		emitX86GoEncodedTestInstruction(t, &asm, rule.row, raw)
		asm.WriteString("MOVQ AX,0(R10)\nMOVQ BX,8(R10)\nMOVQ CX,16(R10)\nSETCS 24(R10)\nSETEQ 25(R10)\nSETMI 26(R10)\nSETOS 27(R10)\nLAHF\nMOVB AH,DL\nMOVB DL,28(R10)\nSTMXCSR 36(R10)\nRET\n")
		fmt.Fprintf(&names, "%s,", name)
		fmt.Fprintf(&metadata, "{%d,%d,%d,%d,%d,%d},\n", rule.bits, rule.kind, rule.destination, rule.source, rule.count, rule.high)
	}
	return decl.String(), asm.String(), names.String(), metadata.String()
}

func TestX86ScalarShiftOriginalGoNumericalFlagsCanaries(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	declaration, source, names, metadata := x86ScalarShiftNumericalSource(t, false)
	driver := strings.ReplaceAll(x86ScalarShiftOriginalGoDriver, "FUNCTIONS", names)
	driver = strings.ReplaceAll(driver, "METADATA", metadata)
	x86WordMultiplyRunOriginalGo(t, execution, "package wordmultiply\n"+declaration, source, driver)
	t.Log("original Go physical legacy/BMI2 value, flags, full GP upper aliases, guards and MXCSR; undefined bits are not compared; Rosetta is not native Linux")
}

func TestX86ScalarShiftDoubleWordCount16LLVM(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	for _, op := range []string{"SHLW", "SHRW"} {
		t.Run(op, func(t *testing.T) {
			source := "TEXT ·Word(SB),4,$0-24\nMOVQ out+0(FP),R10\nMOVQ x+8(FP),AX\nMOVQ y+16(FP),BX\n" + op + " $16,BX,AX\nMOVQ AX,0(R10)\nRET\n"
			ir, err := x86ScalarFPBitViewAPI(t, source, "func Word(out *[64]byte,x,y uint64)", "amd64", execution.triple, "Go")
			if err != nil {
				t.Fatal(err)
			}
			main := `#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern void Word(uint8_t*,uint64_t,uint64_t);
int main(void) {
 uint8_t out[64]={0};
 Word(out,UINT64_C(0x1122334455661234),UINT64_C(0x887766554433abcd));
 uint64_t got; memcpy(&got,out,8);
 if(got!=UINT64_C(0x112233445566abcd)) {fprintf(stderr,"defined count16: got%llx want112233445566abcd\n",(unsigned long long)got);return 1;}
 puts("DOUBLE_WORD_DEFINED_COUNT16_PASS");return 0;
}`
			execution.compileAndRunLLVM(t, "defined-double-word", ir, main, "-O0")
		})
	}
}

func TestX86ScalarShiftLLVMNumericalFlagsCanaries(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
			declaration, source, _, _ := x86ScalarShiftNumericalSource(t, raw)
			var prototypes, rows strings.Builder
			for index, rule := range x86ScalarShiftNumericalRules() {
				fmt.Fprintf(&prototypes, "extern void shift%d(uint8_t*,uint64_t,uint64_t,uint64_t);\n", index)
				fmt.Fprintf(&rows, "{shift%d,%d,%d,%d,%d,%d,%d},\n", index, rule.bits, rule.kind, rule.destination, rule.source, rule.count, rule.high)
			}
			main := strings.ReplaceAll(x86ScalarShiftLLVMDriver, "PROTOTYPES", prototypes.String())
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
							output := execution.compileAndRunLLVM(t, "scalar-shift", text, main, level)
							if !strings.Contains(string(output), "LLVM_SCALAR_SHIFT_NUMERICAL_FLAGS_GUARDS_MXCSR_PASS") {
								t.Fatal(string(output))
							}
						})
					}
				})
			}
		})
	}
}

const x86ScalarShiftOriginalGoDriver = `package wordmultiply
import("encoding/binary";"fmt";"math/bits";"testing";"unsafe")
func TestOriginal(t *testing.T) {
 functions:=[]func(*[64]byte,uint64,uint64,uint64){FUNCTIONS}
 rules:=[]struct{bits,kind,destination,source,count,high int}{METADATA}
 samples:=[]uint64{0,1,^uint64(0),0x8000000080000000,0x0123456789abcdef,0xfedcba9876543210,0x8877665544332211}
 observations:=0
 for k,program:=range functions { r:=rules[k]
  for n:=uint64(0);n<256;n++ { for s,x:=range samples {y:=samples[(s+3)%len(samples)];words:=[3]uint64{x,y,n|0x1234567800000000};d:=x-y
   cf,zf,sf,of,pf,af:=x<y,x==y,d>>63!=0,((x^y)&(x^d))>>63!=0,bits.OnesCount8(byte(d))%2==0,(x^y^d)&16!=0
   mask:=^uint64(0);if r.bits<64 {mask=(uint64(1)<<uint(r.bits))-1};v:=(words[r.destination]>>uint(r.high*8))&mask;src:=words[r.source]&mask
   count:=uint64(0);if r.count>=0 {count=words[r.count]} else if r.count==-2 {count=1};count&=31;if r.bits==64 {if r.count>=0 {count=words[r.count]&63}}
   flagmask:=byte(63);definedValue:=true;old:=v
   if r.kind>=10 {v=src;if r.kind==13 {for i:=uint64(0);i<count;i++ {v=(v>>1)|((v&1)<<uint(r.bits-1))}} else {for i:=uint64(0);i<count;i++ {switch r.kind {case 10:v=(v>>1)|(v&(uint64(1)<<uint(r.bits-1)));case 11:v=(v<<1)&mask;case 12:v>>=1}}}
   } else if r.kind>=8 {if count>uint64(r.bits) {definedValue=false;flagmask=0} else if count!=0 {for i:=uint64(0);i<count;i++ {if r.kind==8 {cf=v>>uint(r.bits-1)!=0;v=((v<<1)|((src>>uint(r.bits-int(i)-1))&1))&mask} else {cf=v&1!=0;v=(v>>1)|(((src>>i)&1)<<uint(r.bits-1))}};zf=v==0;sf=v>>uint(r.bits-1)!=0;pf=bits.OnesCount8(byte(v))%2==0;flagmask&^=4;if count==1 {of=(old^v)>>uint(r.bits-1)!=0} else {flagmask&^=32}}
   } else if count!=0 {effective:=count;if r.kind<2&&(r.bits==8||r.bits==16) {effective%=uint64(r.bits+1)} else if r.kind==2||r.kind==3 {effective%=uint64(r.bits)}
    for i:=uint64(0);i<effective;i++ {switch r.kind {case 0:next:=v>>uint(r.bits-1)!=0;v=(v<<1)&mask;if cf {v|=1};cf=next;case 1:next:=v&1!=0;v>>=1;if cf {v|=uint64(1)<<uint(r.bits-1)};cf=next;case 2:cf=v>>uint(r.bits-1)!=0;v=((v<<1)|bool64(cf))&mask;case 3:cf=v&1!=0;v=(v>>1)|(bool64(cf)<<uint(r.bits-1));case 4,6:cf=v>>uint(r.bits-1)!=0;v=(v<<1)&mask;case 5:cf=v&1!=0;v=(v>>1)|(v&(uint64(1)<<uint(r.bits-1)));case 7:cf=v&1!=0;v>>=1}}
    if r.kind<4 {if r.kind==2 {cf=v&1!=0};if r.kind==3 {cf=v>>uint(r.bits-1)!=0};if count==1 {if r.kind==0||r.kind==2 {of=(v>>uint(r.bits-1)!=0)!=cf} else {of=((v>>uint(r.bits-1))^(v>>uint(r.bits-2)))&1!=0}} else {flagmask&^=32}
    } else {zf=v==0;sf=v>>uint(r.bits-1)!=0;pf=bits.OnesCount8(byte(v))%2==0;flagmask&^=4;if (r.kind==4||r.kind==6||r.kind==7)&&count>=uint64(r.bits) {flagmask&^=1};if count==1 {switch r.kind {case 4,6:of=(v>>uint(r.bits-1)!=0)!=cf;case 5:of=false;case 7:of=old>>uint(r.bits-1)!=0}} else {flagmask&^=32}}
   }
   var packet,want [80]byte;for i:=range packet {packet[i]=byte(i*37+91)};want=packet
   words[r.destination]=(words[r.destination]&^(mask<<uint(r.high*8)))|(v<<uint(r.high*8));if r.bits==32 {words[r.destination]&=0xffffffff}
   for i,v:=range words {binary.LittleEndian.PutUint64(want[8+8*i:],v)}
   values:=[]bool{cf,zf,sf,of};for i,v:=range values {want[32+i]=byte(bool64(v))};want[36]=2|byte(bool64(cf))|byte(bool64(pf)<<2)|byte(bool64(af)<<4)|byte(bool64(zf)<<6)|byte(bool64(sf)<<7)
   program((*[64]byte)(unsafe.Pointer(&packet[8])),x,y,n|0x1234567800000000)
   if !definedValue {for b:=0;b<r.bits/8;b++ {want[8+8*r.destination+r.high+b]=packet[8+8*r.destination+r.high+b]}}
   for i,bit:=range []byte{1,8,16,32} {if flagmask&bit==0 {want[32+i]=packet[32+i]}}
   lahfmask:=byte(2);for i,bit:=range []byte{1,2,4,8,16} {if flagmask&bit!=0 {lahfmask|=[]byte{1,4,16,64,128}[i]}};want[36]=(want[36]&lahfmask)|(packet[36]&^lahfmask)
   before,after:=binary.LittleEndian.Uint32(packet[40:44]),binary.LittleEndian.Uint32(packet[44:48]);if before!=after {t.Fatal("MXCSR changed")};copy(want[40:48],packet[40:48])
   if packet!=want {t.Fatalf("kernel%d %v sample%d count%d got%x want%x",k,r,s,n,packet,want)};observations++
  }}
 }
 if observations!=len(functions)*256*7 {t.Fatal("incomplete numerical denominator")};fmt.Println("ORIGINAL_SCALAR_SHIFT_NUMERICAL_FLAGS_GUARDS_MXCSR_PASS",observations)
}
func bool64(v bool)uint64 {if v{return 1};return 0}
`

const x86ScalarShiftLLVMDriver = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
PROTOTYPES
typedef struct {void(*program)(uint8_t*,uint64_t,uint64_t,uint64_t);unsigned bits,kind,destination,source;int count;unsigned high;} rule;
static const rule rules[]={ROWS};
int main(void) {
 const uint64_t samples[]={0,1,UINT64_MAX,UINT64_C(0x8000000080000000),UINT64_C(0x0123456789abcdef),UINT64_C(0xfedcba9876543210),UINT64_C(0x8877665544332211)};
 unsigned observations=0;
 for(unsigned k=0;k<sizeof(rules)/sizeof(rules[0]);k++) {const rule r=rules[k];
  for(unsigned n=0;n<256;n++) for(unsigned s=0;s<7;s++) {uint64_t x=samples[s],y=samples[(s+3)%7],words[]={x,y,n|UINT64_C(0x1234567800000000)},d=x-y;
   unsigned cf=x<y,zf=x==y,sf=d>>63,of=((x^y)&(x^d))>>63,pf=(__builtin_popcount((uint8_t)d)&1)==0,af=((x^y^d)&16)!=0;
   uint64_t mask=r.bits==64?UINT64_MAX:(UINT64_C(1)<<r.bits)-1,v=(words[r.destination]>>(r.high*8))&mask,src=words[r.source]&mask,old=v;
   unsigned count=r.count>=0?words[r.count]:r.count==-2?1:0;count&=r.bits==64?63:31;
   unsigned flagmask=63,definedValue=1;
   if(r.kind>=10) {v=src;for(unsigned i=0;i<count;i++) {switch(r.kind) {case 10:v=(v>>1)|(v&(UINT64_C(1)<<(r.bits-1)));break;case 11:v=(v<<1)&mask;break;case 12:v>>=1;break;case 13:v=(v>>1)|((v&1)<<(r.bits-1));break;}}
   } else if(r.kind>=8) {if(count>r.bits) {definedValue=0;flagmask=0;} else if(count) {for(unsigned i=0;i<count;i++) {if(r.kind==8) {cf=v>>(r.bits-1);v=((v<<1)|((src>>(r.bits-i-1))&1))&mask;} else {cf=v&1;v=(v>>1)|(((src>>i)&1)<<(r.bits-1));}};zf=v==0;sf=v>>(r.bits-1);pf=(__builtin_popcount((uint8_t)v)&1)==0;flagmask&=~4;if(count==1) of=(old^v)>>(r.bits-1);else flagmask&=~32;}
   } else if(count) {unsigned effective=count;if(r.kind<2&&(r.bits==8||r.bits==16)) effective%=r.bits+1;else if(r.kind==2||r.kind==3) effective%=r.bits;
    for(unsigned i=0;i<effective;i++) {unsigned next;switch(r.kind) {case 0:next=v>>(r.bits-1);v=((v<<1)|cf)&mask;cf=next;break;case 1:next=v&1;v=(v>>1)|((uint64_t)cf<<(r.bits-1));cf=next;break;case 2:cf=v>>(r.bits-1);v=((v<<1)|cf)&mask;break;case 3:cf=v&1;v=(v>>1)|((uint64_t)cf<<(r.bits-1));break;case 4:case 6:cf=v>>(r.bits-1);v=(v<<1)&mask;break;case 5:cf=v&1;v=(v>>1)|(v&(UINT64_C(1)<<(r.bits-1)));break;case 7:cf=v&1;v>>=1;break;}}
    if(r.kind<4) {if(r.kind==2) cf=v&1;if(r.kind==3) cf=v>>(r.bits-1);if(count==1) {if(r.kind==0||r.kind==2) of=(v>>(r.bits-1))^cf;else of=((v>>(r.bits-1))^(v>>(r.bits-2)))&1;} else flagmask&=~32;
    } else {zf=v==0;sf=v>>(r.bits-1);pf=(__builtin_popcount((uint8_t)v)&1)==0;flagmask&=~4;if((r.kind==4||r.kind==6||r.kind==7)&&count>=r.bits) flagmask&=~1;if(count==1) {switch(r.kind) {case 4:case 6:of=(v>>(r.bits-1))^cf;break;case 5:of=0;break;case 7:of=old>>(r.bits-1);break;}} else flagmask&=~32;}
   }
   uint8_t packet[80],want[80];for(unsigned i=0;i<80;i++) packet[i]=(uint8_t)(i*37+91);memcpy(want,packet,80);
   words[r.destination]=(words[r.destination]&~(mask<<(r.high*8)))|(v<<(r.high*8));if(r.bits==32) words[r.destination]&=UINT32_MAX;memcpy(want+8,words,24);
   want[32]=cf;want[33]=zf;want[34]=sf;want[35]=of;want[36]=2|cf|(pf<<2)|(af<<4)|(zf<<6)|(sf<<7);
   uint32_t csr0,csr1;__asm__ volatile("stmxcsr %0":"=m"(csr0));r.program(packet+8,x,y,n|UINT64_C(0x1234567800000000));__asm__ volatile("stmxcsr %0":"=m"(csr1));
   if(!definedValue) for(unsigned b=0;b<r.bits/8;b++) want[8+8*r.destination+r.high+b]=packet[8+8*r.destination+r.high+b];
   const unsigned bits[]={1,8,16,32};for(unsigned i=0;i<4;i++) if(!(flagmask&bits[i])) want[32+i]=packet[32+i];
   const unsigned lahfbits[]={1,4,16,64,128};unsigned lahfmask=2;for(unsigned i=0;i<5;i++) if(flagmask&(1<<i)) lahfmask|=lahfbits[i];want[36]=(want[36]&lahfmask)|(packet[36]&~lahfmask);
   uint32_t before,after;memcpy(&before,packet+40,4);memcpy(&after,packet+44,4);if(before!=csr0||after!=csr0||csr1!=csr0) {fprintf(stderr,"kernel%u MXCSR changed\n",k);return 1;}memcpy(want+40,packet+40,8);
   if(memcmp(packet,want,80)) {for(unsigned i=0;i<80;i++) if(packet[i]!=want[i]) fprintf(stderr,"kernel%u kind%u bits%u count%u sample%u byte%u got%x want%x\n",k,r.kind,r.bits,n,s,i,packet[i],want[i]);return 1;}observations++;
  }
 }
 if(observations!=sizeof(rules)/sizeof(rules[0])*256*7) return 1;puts("LLVM_SCALAR_SHIFT_NUMERICAL_FLAGS_GUARDS_MXCSR_PASS");return 0;
}
`
