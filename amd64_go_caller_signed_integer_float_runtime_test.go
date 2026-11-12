package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestCrossLinuxRuntimeMatrixX86SignedIntegerScalarFloatActualCaller(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	for _, op := range []string{"CVTSL2SS", "CVTSL2SD", "CVTSQ2SS", "CVTSQ2SD", "VCVTSI2SSL", "VCVTSI2SDL", "VCVTSI2SSQ", "VCVTSI2SDQ"} {
		t.Run(op, func(t *testing.T) {
			goSource, bits, resultBits := x86CallerFixtureSource, 32, 32
			load, store, args := "MOVL (DI),AX", "MOVSS X1,(DX)", "AX,X1"
			if strings.Contains(op, "Q") {
				bits, load = 64, "MOVQ (DI),AX"
			}
			if strings.Contains(op, "SD") {
				resultBits, store = 64, "MOVSD X1,(DX)"
				goSource = strings.Replace(goSource, ") float32 {", ") float64 {", 1)
				goSource = strings.Replace(goSource, "var res float32", "var res float64", 1)
			}
			if strings.HasPrefix(op, "V") {
				args = "AX,X0,X1"
			}
			body := load + "\n" + op + " " + args + "\n" + store
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, goSource, assembly)
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			translation, err := translateGoModuleInContext(ctx, pkg, []byte(assembly), GoModuleOptions{
				FileName: "kernel_amd64.s", GOARCH: "amd64", TargetTriple: triple,
				ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) },
			})
			if translation != nil && !translation.Module.IsNil() {
				defer translation.Module.Dispose()
			}
			if err != nil {
				t.Fatal(err)
			}
			main := x86SignedIntegerFloatSSEOracle + fmt.Sprintf(`
#if defined(__APPLE__)
#define LABEL(name) "_" name
#else
#define LABEL(name) name
#endif
extern void kernel(const void*,const void*,void*,const void*) __asm__(LABEL("caller.kernel"));
int main(void){
 for(unsigned sample=0;sample<256;sample++)for(unsigned mode=0;mode<4;mode++){
  uint64_t a[2]={UINT64_C(0xd31733a6287fbbc3)*sample+UINT64_C(0x1000001),UINT64_C(0x789abcdef1234567)};
  uint64_t b[2]={12,13},aCopy[2],bCopy[2];memcpy(aCopy,a,sizeof(a));memcpy(bCopy,b,sizeof(b));
  uint8_t out[16];memset(out,0xc3,sizeof(out));uint64_t length=4;
  unsigned csr=0x9fc5|(mode<<13),after;uint64_t want=sse_convert(a[0],%d,%d,csr);unsigned expectedCSR=sse_csr;
  __asm__ volatile("ldmxcsr %%0"::"m"(csr):"memory");kernel(a,b,out+1,&length);
  __asm__ volatile("stmxcsr %%0":"=m"(after));uint64_t got=0;memcpy(&got,out+1,%d);
  if(got!=want||after!=expectedCSR){fprintf(stderr,"actual caller %s input=%%llx got=%%llx want=%%llx csr=%%x want=%%x\n",(unsigned long long)a[0],(unsigned long long)got,(unsigned long long)want,after,expectedCSR);return 1;}
  for(unsigned i=0;i<sizeof(out);i++)if((i==0||i>%d)&&out[i]!=0xc3)return 2;
  if(memcmp(a,aCopy,sizeof(a))||memcmp(b,bCopy,sizeof(b))||length!=4)return 3;
 }
 unsigned csr=0x1f80;__asm__ volatile("ldmxcsr %%0"::"m"(csr));return 0;
}
`, bits, resultBits, resultBits/8, op, resultBits/8)
			compileAndRunRuntimeTestForTarget(t, llc, clang, "signed-float-caller", triple, x86SignedIntegerFloatOptimize(t, translation.Module.String()), main, prefix)
		})
	}
}
