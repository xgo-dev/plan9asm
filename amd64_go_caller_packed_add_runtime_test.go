package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestCrossLinuxRuntimeMatrixX86PackedWrappingAddActualTypedCaller(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var goSource, assembly, declarations, checks strings.Builder
	goSource.WriteString("package caller\nimport \"unsafe\"\n")
	declarations.WriteString(`#include <stdint.h>
#include <string.h>
#if defined(__APPLE__)
#define LABEL(name) "_" name
#else
#define LABEL(name) name
#endif
`)
	count := 0
	for opcodeIndex, opcode := range x86WrappingAddOpcodes {
		banks := []string{"X"}
		if strings.HasPrefix(opcode, "V") {
			banks = []string{"X", "Y", "Z"}
		}
		for _, bank := range banks {
			name := fmt.Sprintf("calleradd%d", count)
			count++
			declaration := x86CallerFixtureSource[strings.Index(x86CallerFixtureSource, "//go:noescape"):]
			declaration = strings.ReplaceAll(declaration, "kernel", name)
			declaration = strings.Replace(declaration, "func Call(", "func Call"+name+"(", 1)
			declaration = strings.Replace(declaration, ") float32 {", ") uint32 {", 1)
			declaration = strings.Replace(declaration, "var res float32", "var res uint32", 1)
			goSource.WriteString(declaration)
			body := "MOVSS (DI),X0\nMOVSS (SI),X1\n" + opcode + " X0,X1\nMOVSS X1,(DX)"
			if strings.HasPrefix(opcode, "V") {
				body = "VMOVUPS (DI)," + bank + "0\nVMOVUPS (SI)," + bank + "1\n" + opcode + " " + bank + "0," + bank + "1," + bank + "2\nVMOVSS X2,(DX)"
			}
			machine := strings.Replace(x86CallerFixtureAssembly, "·kernel", "·"+name, 1)
			assembly.WriteString(strings.Replace(machine, "MOVL AX,(DX)", body, 1))
			fmt.Fprintf(&declarations, "extern void %s(const void*,const void*,void*,const void*) __asm__(LABEL(\"caller.%s\"));\n", name, name)
			fmt.Fprintf(&checks, `
 for(int round=0;round<32;++round) {
  uint8_t a[70],b[70],out[12],before[12];uint64_t length=16;
  memset(a,0xa7,70);memset(b,0xb9,70);memset(out,0xc3,12);memcpy(before,out,12);
  for(int i=0;i<64;++i){a[i+1]=(uint8_t)(i*17+round*31);b[i+3]=(uint8_t)(i*23+round*41);}
  %[1]s(a+1,b+3,out+5,&length);
  for(int i=0;i<4;i+=%[2]d) {
   uint64_t sum=0,av=0,bv=0;int bytes=%[2]d;
   if(bytes>4)bytes=4;
   for(int j=0;j<bytes;++j){av|=(uint64_t)a[i+j+1]<<(8*j);bv|=(uint64_t)b[i+j+3]<<(8*j);}
   sum=av+bv;for(int j=0;j<bytes;++j)before[i+j+5]=(uint8_t)(sum>>(8*j));
  }
  if(memcmp(out,before,12)||length!=16||a[0]!=0xa7||a[65]!=0xa7||b[2]!=0xb9||b[67]!=0xb9)return 1;
 }
`, name, 1<<uint(opcodeIndex%4))
		}
	}
	requireX86GoAssemblerResult(t, "amd64", assembly.String(), true)
	pkg := x86CallerRuntimePackage(t, goSource.String(), assembly.String())
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	translation, err := translateGoModuleInContext(ctx, pkg, []byte(assembly.String()), GoModuleOptions{
		FileName: "value_amd64.s", GOARCH: "amd64", TargetTriple: triple,
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) },
	})
	if translation != nil && !translation.Module.IsNil() {
		defer translation.Module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	main := declarations.String() + "int main(void){\n" + checks.String() + "return 0;}\n"
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
			text := translation.Module.String()
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "packed-add-typed-caller", triple, text, main, prefix)
		})
	}
	t.Logf("%d actual complete typed original caller programs × 32 independent numerical/canary cases at O0/O2", count)
}
