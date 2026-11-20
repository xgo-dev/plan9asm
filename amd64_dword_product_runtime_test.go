package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86DwordProductIROptimize(t *testing.T, ir string) string {
	t.Helper()
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := parseIRModuleInContext(ctx, ir)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	options := llvm.NewPassBuilderOptions()
	defer options.Dispose()
	if err := module.RunPasses("default<O2>", llvm.TargetMachine{}, options); err != nil {
		t.Fatalf("LLVM22 dword-product IR default<O2>: %v", err)
	}
	return module.String()
}

// This scalar reference is independent of the production lane model, typed
// specifications and LLVM operations. All products fit widened 64-bit math.
const x86DwordProductCReference = `
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <xmmintrin.h>
static uint32_t dword(const uint8_t *p) {
 return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static uint64_t product(uint32_t x,uint32_t y,int sign) {
 if(!sign) return (uint64_t)x*y;
 int64_t a=x<UINT32_C(0x80000000)?x:(int64_t)x-INT64_C(0x100000000);
 int64_t b=y<UINT32_C(0x80000000)?y:(int64_t)y-INT64_C(0x100000000);
 return (uint64_t)(a*b);
}
static const uint32_t edges[]={0,1,2,0x7ffffffe,0x7fffffff,0x80000000,0x80000001,0xfffffffe,0xffffffff};
static const uint64_t masks[]={0,1,0x5555555555555555,UINT64_MAX};
struct Aligned {_Alignas(64) uint8_t before[64],value[80],after[64];};
typedef void(*Program)(uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,uint64_t,uint64_t,uint32_t);
static int check(Program program,const char*name,int width,int sign,int source,int alias,int masking,int legacy) {
 for(int sample=0;sample<97;sample++) for(int state=0;state<2;state++) for(int m=0;m<4;m++) {
  struct Aligned a,b,old,out;
  memset(&a,0xa7,sizeof(a));memset(&b,0xb9,sizeof(b));memset(&old,0x6d,sizeof(old));memset(&out,0xc3,sizeof(out));
  for(int i=0;i<64;i+=4) {
   uint32_t x=edges[(sample+i/4)%9],y=edges[(sample/9+i*3)%9];
   if(sample>81) {x=(uint32_t)(sample*7919+i*104729);y=(uint32_t)(sample*65537+i*37);}
   for(int j=0;j<4;j++) {a.value[i+j]=(uint8_t)(x>>(j*8));b.value[i+j]=(uint8_t)(y>>(j*8));}
  }
  struct Aligned beforeA=a,beforeB=b,beforeOld=old;
  uint64_t seed=state?UINT64_C(0x8d5):0;
  uint32_t profile=(uint32_t)(0x1f80|((sample%4)<<13)|(sample%64)),saved=_mm_getcsr();
  _mm_setcsr(profile);
  program(out.value,a.value,b.value,old.value,masks[m],seed,profile);
  uint32_t after=_mm_getcsr();_mm_setcsr(saved);
  uint64_t flags=0;uint32_t csr=0;memcpy(&flags,out.value+64,8);memcpy(&csr,out.value+72,4);
  if((flags&0x8d5)!=seed||csr!=profile||after!=profile||memcmp(&a,&beforeA,sizeof(a))||memcmp(&b,&beforeB,sizeof(b))||memcmp(&old,&beforeOld,sizeof(old))) return 1;
  const uint8_t *retained=alias==0?a.value:alias==1?b.value:old.value;
  for(int i=0;i<64;i++) {
   int active=!masking||((masks[m]>>(i/8))&1);
   int broadcast=source==2||source>=5;
   int displacement=source==3?width:source==4?-width:source==5?8:source==6?-8:0;
   const uint8_t *sourceBytes=(const uint8_t *)&a+offsetof(struct Aligned,value);
   uint64_t value=product(dword(sourceBytes+displacement+(broadcast?0:i/8*8)),dword(b.value+i/8*8),sign);
   uint8_t want=i<width?(active?(uint8_t)(value>>((i%8)*8)):(masking==2?0:retained[i])):(legacy?retained[i]:0);
   if(out.value[i]!=want) {fprintf(stderr,"%s sample%d mask%llx byte%d got%x want%x\n",name,sample,(unsigned long long)masks[m],i,out.value[i],want);return 2;}
  }
  for(int i=0;i<64;i++) if(out.before[i]!=0xc3||out.after[i]!=0xc3) return 3;
  for(int i=76;i<80;i++) if(out.value[i]!=0xc3) return 4;
 }
 return 0;
}
`

func TestCrossLinuxRuntimeMatrixX86DwordProductIndependentWholeBytes(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var assembly, declarations, reference, checks strings.Builder
	declarations.WriteString("package narroworacle\n")
	reference.WriteString(x86DwordProductCReference)
	count := 0
	for _, name := range x86DwordProductOracleNames {
		legacy, sign := 0, 0
		if !strings.HasPrefix(name, "V") {
			legacy = 1
		}
		if strings.Contains(name, "MULDQ") {
			sign = 1
		}
		widths := []int{16}
		if legacy == 0 {
			widths = append(widths, 32, 64)
		}
		for _, width := range widths {
			bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[width]
			for source := 0; source < 7; source++ {
				if legacy != 0 && source >= 2 {
					continue
				}
				for alias := 0; alias < 3; alias++ {
					if legacy != 0 && alias != 1 {
						continue
					}
					for masking := 0; masking < 3; masking++ {
						if legacy != 0 && masking != 0 {
							continue
						}
						fn := fmt.Sprintf("P%d", count)
						count++
						first := bank + "0"
						op := name
						if source != 0 {
							first = "(CX)"
						}
						if source == 2 || source >= 5 {
							op += ".BCST"
						}
						if source == 3 || source == 4 {
							displacement := width
							if source == 4 {
								displacement = -width
							}
							first = fmt.Sprintf("%d(CX)", displacement)
						} else if source >= 5 {
							displacement := 8
							if source == 6 {
								displacement = -8
							}
							first = fmt.Sprintf("%d(CX)", displacement)
						}
						if masking == 2 {
							op += ".Z"
						}
						args := first + "," + bank + "1"
						if legacy == 0 {
							if masking != 0 {
								args += ",K1"
							}
							args += fmt.Sprintf(",%s%d", bank, alias)
						}
						instruction := op + " " + args
						if source >= 3 {
							actual := x86OrderingHintGoBytes(t, "amd64", "TEXT original(SB),4,$0-0\n"+instruction+"\nRET\n")
							instruction = x86DwordProductDirectives(actual[:len(actual)-1])
						}
						fmt.Fprintf(&declarations, "func %s(out *[80]byte,a,b,old *[64]byte,mask,flags uint64,csr uint32)\n", fn)
						fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-52\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),CX\nMOVQ b+16(FP),DX\nMOVQ old+24(FP),R8\nMOVQ mask+32(FP),R9\nVMOVUPS (CX),Z0\nVMOVUPS (DX),Z1\nVMOVUPS (R8),Z2\nKMOVQ R9,K1\nLDMXCSR csr+48(FP)\nPUSHQ flags+40(FP)\nPOPFQ\n%s\nVMOVUPS Z%d,(AX)\nPUSHFQ\nPOPQ R9\nMOVQ R9,64(AX)\nSTMXCSR 72(AX)\nRET\n", fn, instruction, alias)
						fmt.Fprintf(&reference, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,uint64_t,uint64_t,uint32_t);\n", fn)
						fmt.Fprintf(&checks, "if(check(%s,%q,%d,%d,%d,%d,%d,%d))return 1;\n", fn, op+" "+args, width, sign, source, alias, masking, legacy)
					}
				}
			}
		}
	}
	reference.WriteString("int main(void){\n" + checks.String() + "return 0;}\n")
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	ir := x86NarrowOracleIR(t, assembly.String(), declarations.String(), execution.triple)
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			execution.compileAndRunLLVM(t, "dword-product-full", ir, reference.String(), level)
		})
	}
	t.Run("IR_O2/backend_O2", func(t *testing.T) {
		execution.compileAndRunLLVM(t, "dword-product-ir-o2", x86DwordProductIROptimize(t, ir), reference.String(), "-O2")
	})
	t.Logf("%d LLVM kernels ×97 initialized samples ×2 six-flag seeds ×4 masks; all64 output bytes, both operand/destination aliases, actual-original-Go raw ±Full/±m64bcst offsets, odd dwords, full MXCSR/input/canaries; explicit IR default<O2> distinct from llc backend O0/O2. Portable LLVM execution does not execute original AVX512.", count)
}

func TestCrossLinuxRuntimeMatrixX86DwordProductOriginalGoSSE(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var declarations, assembly, tests strings.Builder
	declarations.WriteString("package oracle\nfunc ReadCSR() uint32\nfunc SetCSR(value uint32)\n")
	assembly.WriteString("TEXT ·ReadCSR(SB),4,$0-4\nSTMXCSR ret0+0(FP)\nRET\nTEXT ·SetCSR(SB),4,$0-4\nLDMXCSR value+0(FP)\nRET\n")
	tests.WriteString(`package oracle
import("testing";"unsafe";"runtime")
func TestOriginal(t *testing.T) {
 runtime.LockOSThread();defer runtime.UnlockOSThread()
 // Exercise the runtime's floating-point heap-sampling path between kernels.
 // LockOSThread alone does not preserve MXCSR across ordinary Go allocations.
 oldRate:=runtime.MemProfileRate;runtime.MemProfileRate=2
 defer func(){runtime.MemProfileRate=oldRate}()
 saved:=ReadCSR();defer SetCSR(saved)
 edges:=[...]uint32{0,1,2,0x7fffffff,0x80000000,0x80000001,0xfffffffe,0xffffffff}
 for sample:=0;sample<97;sample++ {for _,seed:=range []uint64{0,0x8d5} {
 var a,b,out [160]byte
 align:=func(value *[160]byte)(*[64]byte,int){at:=16+int((-uintptr(unsafe.Pointer(&value[16])))&15);return (*[64]byte)(unsafe.Pointer(&value[at])),at}
 ap,_:=align(&a);bp,_:=align(&b);op,offset:=align(&out)
 for i:=range a {a[i]=0xa7;b[i]=0xb9;out[i]=0xc3}
 for i:=0;i<64;i+=4 {x,y:=edges[(sample+i/4)%8],edges[(sample/8+i*3)%8];for j:=0;j<4;j++ {ap[i+j]=byte(x>>uint(j*8));bp[i+j]=byte(y>>uint(j*8))}}
 originalA,originalB:=a,b
 profile:=uint32(0x1f80|((sample%4)<<13)|(sample%64))
`)
	count := 0
	for _, name := range x86DwordProductOracleNames[:2] {
		for _, source := range []string{"X0", "X1", "(DI)"} {
			fn := fmt.Sprintf("S%d", count)
			count++
			fmt.Fprintf(&declarations, "func %s(out,a,b *[64]byte,flags *uint64,csr *uint32,seed uint64,profile uint32)\n", fn)
			// Own the complete state window in assembly. A Go allocation (even
			// on a locked thread) can set MXCSR.PE in runtime heap sampling.
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-52\nMOVQ out+0(FP),DX\nMOVQ a+8(FP),DI\nMOVQ b+16(FP),SI\nMOVQ flags+24(FP),CX\nMOVQ csr+32(FP),BX\nMOVOU (DI),X0\nMOVOU (SI),X1\nLDMXCSR profile+48(FP)\nPUSHQ seed+40(FP)\nPOPFQ\n%s %s,X1\nMOVOU X1,(DX)\nPUSHFQ\nPOPQ AX\nMOVQ AX,(CX)\nSTMXCSR (BX)\nRET\n", fn, name, source)
			alias, signed := 0, 0
			if source == "X1" {
				alias = 1
			}
			if name == "PMULDQ" {
				signed = 1
			}
			fmt.Fprintf(&tests, `{
 flags:=struct{before,value,after uint64}{0x11223344,0,0x44332211};csr:=struct{before,value,after uint32}{0x55667788,0,0x88776655}
 // This deliberate prior-state difference makes loss of per-kernel setup
 // deterministic, without relying on when the runtime happens to sample.
 SetCSR(profile^0x20)
 %s(op,ap,bp,&flags.value,&csr.value,seed,profile)
 after:=ReadCSR()
 if flags.value&0x8d5!=seed||csr.value!=profile||after!=profile||flags.before!=0x11223344||flags.after!=0x44332211||csr.before!=0x55667788||csr.after!=0x88776655||a!=originalA||b!=originalB {
  t.Fatalf("%s sample%%d flags=%%x want=%%x csr=%%x after=%%x want=%%x flagCanaries=%%x/%%x csrCanaries=%%x/%%x inputChanges=%%t/%%t",
   sample,flags.value,seed,csr.value,after,profile,flags.before,flags.after,csr.before,csr.after,a!=originalA,b!=originalB)
 }
 for i,value:=range out {want:=byte(0xc3);if i>=offset&&i<offset+16 {
  index:=i-offset;at:=index/8*8
  read:=func(p *[64]byte)uint32{return uint32(p[at])|uint32(p[at+1])<<8|uint32(p[at+2])<<16|uint32(p[at+3])<<24}
  x,y:=read(ap),read(bp);if %d!=0 {x=y}
  product:=uint64(x)*uint64(y);if %d!=0 {product=uint64(int64(int32(x))*int64(int32(y)))}
  want=byte(product>>uint((index%%8)*8))
 };if value!=want {t.Fatalf("%s sample%%d byte%%d got%%x want%%x",sample,i,value,want)}}
}
`, fn, fn, alias, signed, fn)
		}
	}
	tests.WriteString("}}\n}\n")
	x86WordMultiplyRunOriginalGo(t, execution, declarations.String(), assembly.String(), tests.String())
	t.Logf("%d actual original Go SSE kernels ×97 samples ×2 seeds, complete bytes, signed/unsigned extreme products, ignored odd dwords, flags/MXCSR/canaries. Rosetta is diagnostic; native Linux axis remains required.", count)
}
