package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

// Intel SDM Vol.2A Table 3-1 supplies the relation truth columns and signaling
// column. The relation reference uses only integer IEEE encodings; neither it
// nor the native original scalar CMP exception oracle calls a production helper.
// COMIS/UCOMIS and quiet imm0 are not substituted for legacy predicates: their
// observed exception priority differs for NaN/denormal pairs under Rosetta.
const x86FloatCompareIndependentC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static const unsigned relation_truth[32]={
 4,2,6,8,11,13,9,7,12,10,14,0,3,5,1,15,
 4,2,6,8,11,13,9,7,12,10,14,0,3,5,1,15};
static int is_nan(unsigned bits,uint64_t a) {
 uint64_t fraction=bits==32?0x7fffff:UINT64_C(0xfffffffffffff);
 uint64_t exponent=bits==32?0x7f800000:UINT64_C(0x7ff0000000000000);
 return (a&exponent)==exponent && (a&fraction)!=0;
}
static uint64_t normalized(unsigned bits,uint64_t a,unsigned csr) {
 uint64_t sign=bits==32?0x80000000:UINT64_C(0x8000000000000000);
 uint64_t exponent=bits==32?0x7f800000:UINT64_C(0x7ff0000000000000);
 if(bits==32) a&=UINT64_C(0xffffffff);
 if((csr&64) && !(a&exponent)) a&=sign;
 return a;
}
static int independent_compare(unsigned bits,uint64_t a,uint64_t b,unsigned pred,unsigned csr) {
 a=normalized(bits,a,csr); b=normalized(bits,b,csr);
 unsigned relation;
 if(is_nan(bits,a)||is_nan(bits,b)) relation=8;
 else {
  uint64_t sign=bits==32?0x80000000:UINT64_C(0x8000000000000000);
  uint64_t mask=bits==32?UINT64_C(0xffffffff):UINT64_MAX;
  if(a==b || (!(a&~sign)&&!(b&~sign))) relation=4;
  else {
   uint64_t ak=(a&sign)?(~a&mask):(a^sign);
   uint64_t bk=(b&sign)?(~b&mask):(b^sign);
   relation=ak<bk?2:1;
  }
 }
 return (relation_truth[pred&31]&relation)!=0;
}
static unsigned original_effect(unsigned bits,uint64_t a,uint64_t b,unsigned pred,unsigned csr) {
 unsigned saved,after;
 __asm__ volatile("stmxcsr %0":"=m"(saved));
 __asm__ volatile("ldmxcsr %0"::"m"(csr));
 // The eight original SSE predicates have actual, independently emitted
 // instructions. Extended predicates use only the documented quiet/signaling
 // class for inputs without the diagnostic NaN/denormal ambiguity.
 unsigned native_pred=pred<8?pred:((UINT32_C(0x99996666)>>(pred&31))&1);
#define CMP_EFFECT(op) do { \
 switch(native_pred) { \
 case 0: __asm__ volatile(op " $0,%1,%0":"+x"(x):"x"(y));break; \
 case 1: __asm__ volatile(op " $1,%1,%0":"+x"(x):"x"(y));break; \
 case 2: __asm__ volatile(op " $2,%1,%0":"+x"(x):"x"(y));break; \
 case 3: __asm__ volatile(op " $3,%1,%0":"+x"(x):"x"(y));break; \
 case 4: __asm__ volatile(op " $4,%1,%0":"+x"(x):"x"(y));break; \
 case 5: __asm__ volatile(op " $5,%1,%0":"+x"(x):"x"(y));break; \
 case 6: __asm__ volatile(op " $6,%1,%0":"+x"(x):"x"(y));break; \
 case 7: __asm__ volatile(op " $7,%1,%0":"+x"(x):"x"(y));break; \
 } \
} while(0)
 if(bits==32) {
  uint32_t av=(uint32_t)a,bv=(uint32_t)b; float x,y;
  memcpy(&x,&av,4); memcpy(&y,&bv,4);
  CMP_EFFECT("cmpss");
 } else {
  double x,y; memcpy(&x,&a,8); memcpy(&y,&b,8);
  CMP_EFFECT("cmpsd");
 }
#undef CMP_EFFECT
 __asm__ volatile("stmxcsr %0":"=m"(after));
 __asm__ volatile("ldmxcsr %0"::"m"(saved));
 return after;
}
static int is_denormal(unsigned bits,uint64_t a) {
 uint64_t fraction=bits==32?0x7fffff:UINT64_C(0xfffffffffffff);
 uint64_t exponent=bits==32?0x7f800000:UINT64_C(0x7ff0000000000000);
 return !(a&exponent) && (a&fraction)!=0;
}
static const uint64_t edges32[]={0,0x80000000,1,0x80000001,0x7fffff,0x800000,
 0x3f800000,0xbf800000,0x3f800001,0x7f7fffff,0xff7fffff,0x7f800000,
 0xff800000,0x7fc12345,0xffc45678,0x7f812345,0xff845678,0x7fffffff};
static const uint64_t edges64[]={0,UINT64_C(0x8000000000000000),1,
 UINT64_C(0x8000000000000001),UINT64_C(0xfffffffffffff),UINT64_C(0x10000000000000),
 UINT64_C(0x3ff0000000000000),UINT64_C(0xbff0000000000000),UINT64_C(0x3ff0000000000001),
 UINT64_C(0x7fefffffffffffff),UINT64_C(0xffefffffffffffff),UINT64_C(0x7ff0000000000000),
 UINT64_C(0xfff0000000000000),UINT64_C(0x7ff8123456789abc),UINT64_C(0xfff8fedcba987654),
 UINT64_C(0x7ff0123456789abc),UINT64_C(0xfff0fedcba987654),UINT64_C(0x7fffffffffffffff)};
static const unsigned controls[]={0x1f80,0x1fc0,0x9f80,0x9fc0,0x1fbf,0x7fc5};
static uint64_t read_bits(const uint8_t *p,unsigned bytes) {
 uint64_t value=0; memcpy(&value,p,bytes); return value;
}
`

// An actual SSE instruction has a compile-time immediate. This switch covers
// all eight legacy predicates, independently of LLVM's predicate selection.
func x86FloatCompareOriginalC() string {
	var source strings.Builder
	source.WriteString(x86FloatCompareIndependentC)
	for index, op := range []string{"cmpps", "cmppd", "cmpss", "cmpsd"} {
		fmt.Fprintf(&source, "static void original%d(uint8_t *out,const uint8_t *a,const uint8_t *b,unsigned pred,unsigned csr){\n unsigned saved,after; __asm__ volatile(\"stmxcsr %%0\":\"=m\"(saved));\n __asm__ volatile(\"ldmxcsr %%0\"::\"m\"(csr));\n typedef uint8_t v16 __attribute__((vector_size(16))); v16 x,y; memcpy(&x,a,16); memcpy(&y,b,16);\n switch(pred){\n", index)
		for pred := 0; pred < 8; pred++ {
			fmt.Fprintf(&source, " case %d: __asm__ volatile(\"%s $%d,%%1,%%0\":\"+x\"(x):\"x\"(y)); break;\n", pred, op, pred)
		}
		source.WriteString(" }\n __asm__ volatile(\"stmxcsr %0\":\"=m\"(after));\n __asm__ volatile(\"ldmxcsr %0\"::\"m\"(saved)); memcpy(out,&x,16); memcpy(out+16,&after,4);\n}\n")
	}
	source.WriteString("typedef void (*original_fn)(uint8_t*,const uint8_t*,const uint8_t*,unsigned,unsigned);\n static original_fn originals[]={original0,original1,original2,original3};\n")
	return source.String()
}

func x86FloatCompareCaptureCommand(t *testing.T, command *exec.Cmd) []byte {
	t.Helper()
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	// Keep one lifecycle/deadline per actual command, including the original-Go
	// driver and the independently compiled native SSE reference.
	bounded := exec.CommandContext(ctx, command.Path, command.Args[1:]...)
	bounded.Dir, bounded.Env = command.Dir, command.Env
	output, err := runtimeOracleCombinedOutput(ctx, bounded)
	if err != nil {
		t.Fatalf("compare oracle command %q: %v\n%s", command.Args, err, output)
	}
	return output
}

func TestCrossLinuxRuntimeMatrixX86FloatingCompareOriginalLegacyPredicates(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	dir := t.TempDir()
	var assembly, declarations strings.Builder
	assembly.WriteString("#include \"textflag.h\"\n")
	for index, op := range []string{"CMPPS", "CMPPD", "CMPSS", "CMPSD"} {
		for pred := 0; pred < 8; pred++ {
			name := fmt.Sprintf("legacy%d_%d", index, pred)
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),NOSPLIT,$8-32\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\nSTMXCSR 0(SP)\nLDMXCSR csr+24(FP)\nMOVOU (BX),X0\nMOVOU (CX),X1\n%s X1,X0,$%d\nMOVOU X0,(AX)\nSTMXCSR 16(AX)\nLDMXCSR 0(SP)\nRET\n", name, op, pred)
			fmt.Fprintf(&declarations, "func %s(out,a,b *[20]byte,csr uint32)\n", name)
		}
	}
	var functions strings.Builder
	for index := 0; index < 4; index++ {
		for pred := 0; pred < 8; pred++ {
			fmt.Fprintf(&functions, "legacy%d_%d,", index, pred)
		}
	}
	const goDriver = `package main
import("encoding/binary";"fmt")
func main(){
 functions:=[]func(*[20]byte,*[20]byte,*[20]byte,uint32){FUNCTIONS}
 edges32:=[]uint64{0,0x80000000,1,0x80000001,0x7fffff,0x800000,0x3f800000,0xbf800000,0x3f800001,0x7f7fffff,0xff7fffff,0x7f800000,0xff800000,0x7fc12345,0xffc45678,0x7f812345,0xff845678,0x7fffffff}
 edges64:=[]uint64{0,0x8000000000000000,1,0x8000000000000001,0xfffffffffffff,0x10000000000000,0x3ff0000000000000,0xbff0000000000000,0x3ff0000000000001,0x7fefffffffffffff,0xffefffffffffffff,0x7ff0000000000000,0xfff0000000000000,0x7ff8123456789abc,0xfff8fedcba987654,0x7ff0123456789abc,0xfff0fedcba987654,0x7fffffffffffffff}
 controls:=[]uint32{0x1f80,0x1fc0,0x9f80,0x9fc0,0x1fbf,0x7fc5}
 hash:=uint64(1469598103934665603)
 for index,fn:=range functions{
  bytes,edges:=4,edges32
  if index/8==1||index/8==3{bytes,edges=8,edges64}
  for _,av:=range edges{for _,bv:=range edges{for _,csr:=range controls{
   var a,b [20]byte
   out:=struct{before byte;data [20]byte;after byte}{before:0xa7,after:0xb9}
   for i:=0;i<16;i+=bytes{
    if bytes==4{binary.LittleEndian.PutUint32(a[i:],uint32(av));binary.LittleEndian.PutUint32(b[i:],uint32(bv))}else{binary.LittleEndian.PutUint64(a[i:],av);binary.LittleEndian.PutUint64(b[i:],bv)}
   }
   beforeA,beforeB:=a,b;fn(&out.data,&a,&b,csr)
   if a!=beforeA||b!=beforeB||out.before!=0xa7||out.after!=0xb9{panic("input/output canary mutation")}
   for _,v:=range out.data{hash^=uint64(v);hash*=1099511628211}
  }}}
 }
 fmt.Printf("%016x\n",hash)
}
`
	for name, source := range map[string]string{
		"go.mod":           "module originalcompare\n\ngo 1.20\n",
		"main.go":          strings.Replace(goDriver, "FUNCTIONS", functions.String(), 1) + declarations.String(),
		"original_amd64.s": assembly.String(),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	goExecutable := filepath.Join(dir, gotoolchain.HostExecutable("original-go"))
	command := exec.Command("go", "build", "-p=2", "-o", goExecutable, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS="+runtime.GOOS, "GOARCH=amd64", "CGO_ENABLED=0", "GOWORK=off", "GOENV=off", "GOTOOLCHAIN=local")
	x86FloatCompareCaptureCommand(t, command)
	actualGo := execution.run(t, goExecutable)
	const main = `
int main(void){
 uint64_t hash=UINT64_C(1469598103934665603);
 for(unsigned op=0;op<4;op++) for(unsigned pred=0;pred<8;pred++){
  unsigned bytes=(op==1||op==3)?8:4; const uint64_t *edges=bytes==4?edges32:edges64;
  for(unsigned i=0;i<18;i++) for(unsigned j=0;j<18;j++) for(unsigned c=0;c<6;c++){
   uint8_t a[20]={0},b[20]={0},storage[22],want[16];
   uint8_t *out=storage+1;memset(storage,0xc3,sizeof(storage));
   for(unsigned lane=0;lane<16;lane+=bytes){memcpy(a+lane,edges+i,bytes);memcpy(b+lane,edges+j,bytes);}
   uint8_t beforeA[20],beforeB[20];memcpy(beforeA,a,20);memcpy(beforeB,b,20);
   originals[op](out,a,b,pred,controls[c]); memcpy(want,a,16);
   if(storage[0]!=0xc3||storage[21]!=0xc3||memcmp(a,beforeA,20)||memcmp(b,beforeB,20))return 2;
   unsigned compared=op>=2?bytes:16;
   for(unsigned lane=0;lane<compared;lane+=bytes) memset(want+lane,independent_compare(bytes*8,edges[i],edges[j],pred,controls[c])?255:0,bytes);
   unsigned expected=original_effect(bytes*8,edges[i],edges[j],pred,controls[c]);
   if(memcmp(out,want,16)||read_bits(out+16,4)!=expected){fprintf(stderr,"original SSE truth/effect op=%u pred=%u a=%llx b=%llx csr=%x observed=%llx scalar-CMP-policy=%x mask=%llx want=%llx\n",op,pred,(unsigned long long)edges[i],(unsigned long long)edges[j],controls[c],(unsigned long long)read_bits(out+16,4),expected,(unsigned long long)read_bits(out,bytes),(unsigned long long)read_bits(want,bytes));return 1;}
   for(unsigned k=0;k<20;k++){hash^=out[k];hash*=UINT64_C(1099511628211);}
  }
 }
 printf("%016llx\n",(unsigned long long)hash);return 0;
}
`
	cSource, cExecutable := filepath.Join(dir, "original.c"), filepath.Join(dir, "original-c")
	if err := os.WriteFile(cSource, []byte(x86FloatCompareOriginalC()+main), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, cSource, cExecutable)
	actualC := execution.run(t, cExecutable)
	if string(actualGo) != string(actualC) || len(actualC) != 17 {
		t.Fatalf("actual Go/native SSE original mismatch Go=%q C=%q", actualGo, actualC)
	}
	t.Logf("32 actual Go legacy programs ×1944 input/control pairs; independent original SSE, bit truth and complete same-predicate scalar CMP MXCSR agree: %s transport=%v", strings.TrimSpace(string(actualC)), execution.prefix)
}
