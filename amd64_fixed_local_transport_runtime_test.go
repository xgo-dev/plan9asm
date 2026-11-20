package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalTransportByteValues(t *testing.T) {
	t.Setenv("GOCACHE", t.TempDir())
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	declarations := `func Bool(a []byte, p *uint64, b bool, n uint64) bool
func Pointer(a []byte, p *uint64, b bool, n uint64) *uint64
func Slice(a []byte, p *uint64, b bool, n uint64) []byte
`
	assembly := fixedLocalTransportAssembly("Bool", 49, fixedLocalTransportBoolBody)
	assembly += fixedLocalTransportAssembly("Pointer", 56, "MOVQ p+24(FP),CX\nMOVQ CX,128(BP)\nMOVQ 128(BP),DX\nMOVQ DX,ret+48(FP)")
	assembly += fixedLocalTransportAssembly("Slice", 72, "MOVQ a_base+0(FP),CX\nMOVQ a_len+8(FP),DX\nMOVQ a_cap+16(FP),BX\nMOVQ CX,128(BP)\nMOVQ 128(BP),CX\nMOVQ CX,ret_base+48(FP)\nMOVQ DX,ret_len+56(FP)\nMOVQ BX,ret_cap+64(FP)")
	// Only the unchanged legacy SSE move is executed on the local Rosetta
	// counterpart. The separate three-OS object matrix covers the Y form.
	assembly = strings.ReplaceAll(assembly, "VMOVDQA", "MOVOA")
	assembly = strings.ReplaceAll(assembly, "Y14", "X14")
	conditions, conditionDeclarations, originalObservers, observerDeclarations, goConditions, llvmConditions, cConditions := fixedLocalTransportConditionOracles()
	assembly += conditions
	declarations += conditionDeclarations
	pkg, request, _, options := fixedLocalTransportFixture(t, assembly, declarations, runtime.GOOS+"/amd64", execution.triple)
	fixedLocalConversionPrepareToolCache(t, request)
	goOracle := `package framefixture
import "testing"
func TestOriginal(t *testing.T) {
    checkConditions(t)
    buffer := [4]byte{0x11,0x22,0x33,0x44}
    word := uint64(0x123456789abcdef0)
    for _, a := range [][]byte{nil,buffer[:2],buffer[:4]} {
        for _, p := range []*uint64{nil,&word} {
            for _, b := range []bool{false,true} {
                for _, n := range []uint64{0,1,^uint64(0),0x8000000000000000} {
                    if Bool(a,p,b,n)!=b || Pointer(a,p,b,n)!=p { t.Fatal("scalar transport") }
                    s:=Slice(a,p,b,n)
                    if len(s)!=len(a)||cap(s)!=cap(a) { t.Fatal("slice component") }
                    if len(a)>0 && &s[0]!=&a[0] { t.Fatal("slice identity") }
                    if a==nil && s!=nil { t.Fatal("nil identity") }
                    if buffer!=[4]byte{0x11,0x22,0x33,0x44}||word!=0x123456789abcdef0 { t.Fatal("pointee mutation") }
                }
            }
        }
    }
}
` + goConditions
	fixedLocalPackedRunOriginal(t, execution, assembly+originalObservers, declarations+observerDeclarations, goOracle, true)
	// Call the translated aggregate ABI from an exact LLVM wrapper, not a
	// guessed C struct ABI. C only crosses a scalar wrapper signature.
	const wrapper = `
define i32 @transport_probe(ptr %data, i64 %len, i64 %cap, ptr %p, i1 %b, i64 %n) {
entry:
  %a0 = insertvalue {ptr,i64,i64} zeroinitializer, ptr %data, 0
  %a1 = insertvalue {ptr,i64,i64} %a0, i64 %len, 1
  %a2 = insertvalue {ptr,i64,i64} %a1, i64 %cap, 2
  %b2 = call i1 @"example.invalid/framefixture.Bool"({ptr,i64,i64} %a2, ptr %p, i1 %b, i64 %n)
  %p2 = call ptr @"example.invalid/framefixture.Pointer"({ptr,i64,i64} %a2, ptr %p, i1 %b, i64 %n)
  %s2 = call {ptr,i64,i64} @"example.invalid/framefixture.Slice"({ptr,i64,i64} %a2, ptr %p, i1 %b, i64 %n)
  %d2 = extractvalue {ptr,i64,i64} %s2, 0
  %l2 = extractvalue {ptr,i64,i64} %s2, 1
  %c2 = extractvalue {ptr,i64,i64} %s2, 2
  %badb = icmp ne i1 %b2, %b
  %badp = icmp ne ptr %p2, %p
  %badd = icmp ne ptr %d2, %data
  %badl = icmp ne i64 %l2, %len
  %badc = icmp ne i64 %c2, %cap
  %bad0 = or i1 %badb, %badp
  %bad1 = or i1 %bad0, %badd
  %bad2 = or i1 %bad1, %badl
  %bad3 = or i1 %bad2, %badc
  %result = zext i1 %bad3 to i32
  ret i32 %result
}
`
	oracle := `#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
` + cConditions + `
extern int transport_probe(void *,uint64_t,uint64_t,void *,bool,uint64_t);
int main(void) {
    if(check_conditions()) return 3;
    volatile uint8_t buffer[4]={0x11,0x22,0x33,0x44};
    volatile uint64_t word=UINT64_C(0x123456789abcdef0);
    uint64_t inputs[]={0,1,UINT64_MAX,UINT64_C(0x8000000000000000)};
    for(unsigned a=0;a<3;a++) for(unsigned p=0;p<2;p++)
    for(unsigned b=0;b<2;b++) for(unsigned n=0;n<4;n++) {
        void *data=a?(void *)buffer:0;
        uint64_t len=a==1?2:a==2?4:0,cap=a?4:0;
        if(transport_probe(data,len,cap,p?(void *)&word:0,b,inputs[n])) return 1;
        if(buffer[0]!=0x11||buffer[1]!=0x22||buffer[2]!=0x33||buffer[3]!=0x44||word!=UINT64_C(0x123456789abcdef0)) return 2;
    }
    return 0;
}
`
	fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
		if err != nil {
			t.Fatal(err)
		}
		for _, optimized := range []bool{false, true} {
			input, level := ir+wrapper+llvmConditions, "-O0"
			if optimized {
				input, level = x86MulDivRoundOptimize(t, input), "-O2"
			}
			execution.compileAndRunLLVM(t, fmt.Sprintf("transport-%v", optimized), input, oracle, level)
		}
	})
	t.Log("48 inputs x bool/pointer/slice plus all16 SETcc true/false and original physical bool-byte canaries; LLVM three APIs O0/O2; pointees unchanged")
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		t.Log("Rosetta SSE diagnostic, not native AVX/AVX512 execution")
	}
}

func fixedLocalTransportConditionOracles() (string, string, string, string, string, string, string) {
	var assembly, declarations, observers, observerDeclarations strings.Builder
	var goRows, llvmRows, cDeclarations, cRows strings.Builder
	names := strings.Fields("SETCC SETCS SETEQ SETGE SETGT SETHI SETLE SETLS SETLT SETMI SETNE SETOC SETOS SETPC SETPL SETPS")
	var bodies []string
	for _, name := range names {
		bodies = append(bodies, "MOVQ a_len+8(FP),DX\nCMPQ AX,DX\n"+name+" BX\nMOVB BX,ret+48(FP)")
	}
	bodies = append(bodies, fixedLocalCanonicalBoolBodies...)
	bodies = append(bodies, "MOVQ $-1,BX\nMOVB $1,BX\nMOVB BX,ret+48(FP)")
	for index, body := range bodies {
		function := fmt.Sprintf("Condition%d", index)
		kernel := fixedLocalTransportAssembly(function, 49, body)
		kernel = strings.ReplaceAll(strings.ReplaceAll(kernel, "VMOVDQA", "MOVOA"), "Y14", "X14")
		assembly.WriteString(kernel)
		fmt.Fprintf(&declarations, "func %s(%s) bool\n", function, fixedLocalTransportParams)
		fmt.Fprintf(&observerDeclarations, "func Observe%d(%s) (raw, adjacent, input uint64)\n", index, fixedLocalTransportParams)
		// Original-only ABI0 adapter. The callee and this NOSPLIT observer
		// contain no Go calls, allocation or pointee access. It snapshots the
		// actual output word and neighbors, not a Go-normalized bool value.
		fmt.Fprintf(&observers, `TEXT ·Observe%d(SB),4,$64-72
MOVQ a_base+0(FP),AX
MOVQ AX,0(SP)
MOVQ a_len+8(FP),AX
MOVQ AX,8(SP)
MOVQ a_cap+16(FP),AX
MOVQ AX,16(SP)
MOVQ p+24(FP),AX
MOVQ AX,24(SP)
MOVB b+32(FP),AX
MOVB AX,32(SP)
MOVQ n+40(FP),AX
MOVQ AX,40(SP)
MOVQ $0x5a5a5a5a5a5a5a5a,AX
MOVQ AX,48(SP)
MOVQ $0x6b6b6b6b6b6b6b6b,AX
MOVQ AX,56(SP)
CALL ·%s(SB)
MOVQ 48(SP),AX
MOVQ AX,raw+48(FP)
MOVQ 56(SP),AX
MOVQ AX,adjacent+56(FP)
MOVQ 40(SP),AX
MOVQ AX,input+64(FP)
RET
`, index, function)
		fmt.Fprintf(&goRows, "{Condition%d,Observe%d},\n", index, index)
		fmt.Fprintf(&llvmRows, `
define i32 @condition_probe%d(i64 %%n, i64 %%len) {
  %%a0 = insertvalue {ptr,i64,i64} zeroinitializer, i64 %%len, 1
  %%a1 = insertvalue {ptr,i64,i64} %%a0, i64 %%len, 2
  %%flag = trunc i64 %%len to i1
  %%b = call i1 @"example.invalid/framefixture.%s"({ptr,i64,i64} %%a1, ptr null, i1 %%flag, i64 %%n)
  %%result = zext i1 %%b to i32
  ret i32 %%result
}
`, index, function)
		fmt.Fprintf(&cDeclarations, "extern int condition_probe%d(uint64_t,uint64_t);\n", index)
		fmt.Fprintf(&cRows, "condition_probe%d,", index)
	}
	goOracle := `
func checkConditions(t *testing.T) {
    rows:=[]struct{
        call func([]byte,*uint64,bool,uint64) bool
        observe func([]byte,*uint64,bool,uint64)(uint64,uint64,uint64)
    }{
` + goRows.String() + `
    }
    inputs:=[]uint64{0,1,2,3,1<<63,(1<<63)-1,^uint64(0)}
    buffer:=[4]byte{1,2,3,4}
    for i,row:=range rows {
        seen:=0
        for _,a:=range inputs { for b:=uint64(0);b<4;b++ {
            r:=a-b
            cf,zf,sf:=a<b,r==0,r>>63!=0
            of:=(a^b)&(a^r)>>63!=0
            parity:=byte(r); parity^=parity>>4; parity^=parity>>2; parity^=parity>>1
            pf:=parity&1==0
            want:=[]bool{!cf,cf,zf,sf==of,!zf&&sf==of,!cf&&!zf,zf||sf!=of,cf||zf,sf!=of,sf,!zf,!of,of,!pf,!sf,pf,false,true,true,b&1!=0,a==0,a==0,a==0,true}[i]
            if row.call(buffer[:b],nil,b&1!=0,a)!=want { t.Fatalf("condition %%d",i) }
            value:=uint64(0); if want { value=1 }
            raw,adjacent,input:=row.observe(buffer[:b],nil,b&1!=0,a)
            if raw!=0x5a5a5a5a5a5a5a00|value||adjacent!=0x6b6b6b6b6b6b6b6b||input!=a { t.Fatalf("physical byte/canary %%d %%x %%x %%x",i,raw,adjacent,input) }
            seen|=1<<value
        } }
        if i<16 && seen!=3 { t.Fatalf("condition %%d lacked both outcomes",i) }
    }
}
`
	goOracle = strings.ReplaceAll(goOracle, "%%", "%")
	cOracle := cDeclarations.String() + `
static int (*condition_probes[])(uint64_t,uint64_t)={` + cRows.String() + `};
static int check_conditions(void) {
    const uint64_t inputs[]={0,1,2,3,UINT64_C(0x8000000000000000),UINT64_C(0x7fffffffffffffff),UINT64_MAX};
    for(unsigned i=0;i<sizeof(condition_probes)/sizeof(condition_probes[0]);i++) {
        unsigned seen=0;
        for(unsigned v=0;v<7;v++) for(uint64_t b=0;b<4;b++) {
            uint64_t a=inputs[v],r=a-b;
            bool cf=a<b,zf=r==0,sf=r>>63,of=((a^b)&(a^r))>>63;
            uint8_t parity=r; parity^=parity>>4; parity^=parity>>2; parity^=parity>>1;
            bool pf=(parity&1)==0;
            bool want[]={!cf,cf,zf,sf==of,!zf&&sf==of,!cf&&!zf,zf||sf!=of,cf||zf,sf!=of,sf,!zf,!of,of,!pf,!sf,pf,false,true,true,(b&1)!=0,a==0,a==0,a==0,true};
            int actual=condition_probes[i](a,b);
            if(actual!=want[i]) {
                fprintf(stderr,"condition=%u a=%llx b=%llx actual=%d expected=%d\n",i,(unsigned long long)a,(unsigned long long)b,(int)actual,(int)want[i]);
                return 1;
            }
            seen|=1U<<want[i];
        }
        if(i<16 && seen!=3) return 2;
    }
    return 0;
}
`
	return assembly.String(), declarations.String(), observers.String(), observerDeclarations.String(), goOracle, llvmRows.String(), cOracle
}
