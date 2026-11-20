package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestCrossLinuxRuntimeMatrixX86GoLogicalAndNotOperandOrder(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires Linux/amd64 runtime counterpart")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 tools missing")
	}
	var declarations, assembly, tests, oracle strings.Builder
	declarations.WriteString("package caller\nimport \"unsafe\"\n")
	tests.WriteString(`package caller
import "testing"
func TestOriginalLogicalMathematics(t *testing.T) {
 values:=[]uint64{0,1,7,0x0ff00ff0a55aa55a,0x33cc55aa5aa5f00f,1<<63,^uint64(0)}
`)
	oracle.WriteString(`#include <stdint.h>
#include <string.h>
#if defined(__APPLE__)
#define LABEL(name) "_" name
#else
#define LABEL(name) name
#endif
`)
	for _, op := range []string{"ANDNPS", "ANDNPD", "PANDN"} {
		name := strings.ToLower(op)
		fmt.Fprintf(&declarations, `
//go:noescape
func %[1]s(a,b,res,length unsafe.Pointer)
func Call%[1]s(x,y []uint64) uint64 {
 var res uint64
 length:=len(x)
 %[1]s(unsafe.Pointer(unsafe.SliceData(x)),unsafe.Pointer(unsafe.SliceData(y)),unsafe.Pointer(&res),unsafe.Pointer(&length))
 return res
}
`, name)
		body := "MOVSD (DI),X0\nMOVSD (SI),X1\n" + op + " X0,X1\nMOVSD X1,(DX)"
		machine := strings.Replace(x86CallerFixtureAssembly, "·kernel", "·"+name, 1)
		machine = strings.Replace(machine, "MOVL AX,(DX)", body, 1)
		assembly.WriteString(machine)
		fmt.Fprintf(&tests, `
 for _,a:=range values { for _,b:=range values {
  x,y:=[]uint64{a,17},[]uint64{b,23}
  got:=Call%[1]s(x[:1],y[:1]); want:=a &^ b
  if got!=want || x[0]!=a || x[1]!=17 || y[0]!=b || y[1]!=23 { t.Fatalf("%[1]s(%%x,%%x)=%%x want %%x",a,b,got,want) }
 } }
`, name)
		fmt.Fprintf(&oracle, "extern void %s(const void*,const void*,void*,const void*) __asm__(LABEL(\"caller.%s\"));\n", name, name)
	}
	tests.WriteString("}\n")
	oracle.WriteString(`int main(void) {
 const uint64_t values[]={0,1,7,UINT64_C(0x0ff00ff0a55aa55a),UINT64_C(0x33cc55aa5aa5f00f),UINT64_C(1)<<63,UINT64_MAX};
`)
	for _, name := range []string{"andnps", "andnpd", "pandn"} {
		fmt.Fprintf(&oracle, `
 for(int i=0;i<7;++i) for(int j=0;j<7;++j) {
  uint8_t a[18],b[18],out[18],before[18]; uint64_t length=1,got;
  memset(a,0xa7,18); memset(b,0xb9,18); memset(out,0xc3,18); memcpy(before,out,18);
  memcpy(a+1,values+i,8); memcpy(b+3,values+j,8);
  %s(a+1,b+3,out+5,&length);
  uint64_t want=values[i]&~values[j]; memcpy(&got,out+5,8); memcpy(before+5,&want,8);
  if(got!=want || memcmp(before,out,18) || length!=1 || a[0]!=0xa7 || a[9]!=0xa7 || b[2]!=0xb9 || b[11]!=0xb9) return 1;
 }
`, name)
	}
	oracle.WriteString("return 0;\n}\n")
	dir := t.TempDir()
	for name, src := range map[string]string{"go.mod": "module caller\n\ngo 1.20\n", "value.go": declarations.String(), "value_amd64.s": assembly.String(), "value_test.go": tests.String()} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-p=2", "-vet=off", "-count=1", ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	if output, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("original Go ANDNOT operand order: %v\n%s", err, output)
	}
	pkg := x86CallerRuntimePackage(t, declarations.String(), assembly.String())
	llvmContext := llvm.NewContext()
	defer llvmContext.Dispose()
	triple := testTargetTriple(runtime.GOOS, "amd64")
	translation, err := translateGoModuleInContext(llvmContext, pkg, []byte(assembly.String()), GoModuleOptions{
		FileName: "value_amd64.s", GOARCH: "amd64", TargetTriple: triple, ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer translation.Module.Dispose()
	var prefix []string
	if crossRosetta {
		prefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "logical_andnot_order", triple, translation.Module.String(), oracle.String(), prefix)
}
