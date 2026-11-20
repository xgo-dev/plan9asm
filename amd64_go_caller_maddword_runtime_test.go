package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestCrossLinuxRuntimeMatrixX86WordMultiplyAddActualTypedCaller(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var declarations, assembly, checks strings.Builder
	declarations.WriteString("package caller\nimport \"unsafe\"\n")
	checks.WriteString(`#include <stdint.h>
#include <string.h>
#if defined(__APPLE__)
#define LABEL(name) "_" name
#else
#define LABEL(name) name
#endif
`)
	for index, bank := range []string{"legacy", "X", "Y", "Z"} {
		name := fmt.Sprintf("madd%d", index)
		goSource := strings.ReplaceAll(x86CallerFixtureSource, "kernel", name)
		goSource = strings.TrimPrefix(goSource, "package caller\nimport \"unsafe\"\n")
		goSource = strings.Replace(goSource, "func Call(", "func Call"+name+"(", 1)
		goSource = strings.Replace(goSource, ") float32 {", ") uint32 {", 1)
		goSource = strings.Replace(goSource, "var res float32", "var res uint32", 1)
		declarations.WriteString(goSource)
		body := "MOVSS (DI),X0\nMOVSS (SI),X1\nPMADDWL X0,X1\nMOVSS X1,(DX)"
		if bank != "legacy" {
			body = "VMOVUPS (DI)," + bank + "0\nVMOVUPS (SI)," + bank + "1\nVPMADDWD " + bank + "0," + bank + "1," + bank + "2\nVMOVSS X2,(DX)"
		}
		machine := strings.Replace(x86CallerFixtureAssembly, "·kernel", "·"+name, 1)
		machine = strings.Replace(machine, "MOVL AX,(DX)", body, 1)
		assembly.WriteString(machine)
		fmt.Fprintf(&checks, "extern void %s(const void*,const void*,void*,const void*) __asm__(LABEL(\"caller.%s\"));\n", name, name)
	}
	goTests := `package caller
import("testing";"unsafe")
func TestOriginalSSEPair(t *testing.T) {
 values:=[]uint32{0,1,0x80008000,0x7fff7fff,0xffff0001,0x1234abcd,0xfffe8000}
 signed:=func(v uint32) int64 {x:=int64(v&65535);if x>=32768{x-=65536};return x}
 for _,a:=range values {for _,b:=range values {
  var x,y [16]float32
  *(*uint32)(unsafe.Pointer(&x[0]))=a;*(*uint32)(unsafe.Pointer(&y[0]))=b
  got:=Callmadd0(x[:],y[:]);want:=uint32(signed(a)*signed(b)+signed(a>>16)*signed(b>>16))
  if got!=want || *(*uint32)(unsafe.Pointer(&x[0]))!=a || *(*uint32)(unsafe.Pointer(&y[0]))!=b {t.Fatalf("pair %x/%x got%x want%x",a,b,got,want)}
 }}
}
`
	dir := t.TempDir()
	for name, source := range map[string]string{"go.mod": "module caller\n\ngo 1.20\n", "value.go": declarations.String(), "value_amd64.s": assembly.String(), "value_test.go": goTests} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-vet=off", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("original actual typed SSE caller: %v\n%s", err, output)
	}
	checks.WriteString(`
static int64_t signedWord(uint32_t bits) {uint32_t v=bits&65535;return v<32768 ? (int64_t)v : (int64_t)v-65536;}
int main(void) {
 const uint32_t values[]={0,1,0x80008000,0x7fff7fff,0xffff0001,0x1234abcd,0xfffe8000};
`)
	for index := 0; index < 4; index++ {
		fmt.Fprintf(&checks, `
 for(int i=0;i<7;++i) for(int j=0;j<7;++j) {
  uint8_t a[70],b[70],out[12],before[12];uint64_t length=16;uint32_t got;
  memset(a,0xa7,sizeof(a));memset(b,0xb9,sizeof(b));memset(out,0xc3,sizeof(out));memcpy(before,out,sizeof(out));
  memcpy(a+1,values+i,4);memcpy(b+3,values+j,4);
  madd%d(a+1,b+3,out+5,&length);
  uint32_t want=(uint32_t)(signedWord(values[i])*signedWord(values[j])+signedWord(values[i]>>16)*signedWord(values[j]>>16));
  memcpy(&got,out+5,4);memcpy(before+5,&want,4);
  if(got!=want || memcmp(before,out,sizeof(out)) || length!=16 || a[0]!=0xa7 || a[65]!=0xa7 || b[2]!=0xb9 || b[67]!=0xb9) return 1;
 }
`, index)
	}
	checks.WriteString("return 0;\n}\n")
	pkg := x86CallerRuntimePackage(t, declarations.String(), assembly.String())
	llvmContext := llvm.NewContext()
	defer llvmContext.Dispose()
	translation, err := translateGoModuleInContext(llvmContext, pkg, []byte(assembly.String()), GoModuleOptions{
		FileName: "value_amd64.s", GOARCH: "amd64", TargetTriple: triple,
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) },
	})
	if err != nil {
		if translation != nil && !translation.Module.IsNil() {
			translation.Module.Dispose()
		}
		t.Fatal(err)
	}
	defer translation.Module.Dispose()
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("O2=%t", optimized), func(t *testing.T) {
			text := translation.Module.String()
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "word-madd-actual-caller", triple, text, checks.String(), prefix)
		})
	}
}
