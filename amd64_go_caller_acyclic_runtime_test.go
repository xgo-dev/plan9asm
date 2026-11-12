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

func x86CallerAcyclicRuntimeSources() (goSource, assembly, goTest, cOracle string) {
	forms := []struct {
		name, body string
		width      int
	}{
		{"inputjoin", "CMPQ AX,$1\nJE joined\nADDQ $4,DI\nCMPQ AX,$1\njoined:\nMOVL (DI),AX\nMOVL AX,(DX)", 4},
		{"copyjoin", "CMPQ AX,$1\nJE joined\nADDQ $4,DI\nCMPQ AX,$1\njoined:\nMOVQ DI,BX\nLEAQ 8(BX),R11\nSUBQ $8,R11\nMOVL (R11),AX\nMOVL AX,(DX)", 4},
		{"reversedjoin", "CMPQ AX,$1\nJNE changed\nJMP joined\nchanged:\nADDQ $4,DI\nCMPQ AX,$1\njoined:\nMOVL (DI),AX\nMOVL AX,(DX)", 4},
		{"lowjoin", "CMPQ AX,$1\nJE narrow\nMOVL $42,BX\nJMP joined\nnarrow:\nMOVB $42,BL\njoined:\nMOVB BL,(DX)", 1},
	}
	var declarations, machine, tests, c strings.Builder
	declarations.WriteString("package caller\nimport \"unsafe\"\n")
	tests.WriteString(`package caller
import "testing"
func TestOriginalAcyclicCallerValues(t *testing.T) {
 values := []uint32{0,1,7,0x80000000,0xffffffff,0x12345678}
 for _, value := range values {
  for length:=1; length<=4; length++ {
   x := []uint32{value,value^0xaabbccdd,19,23}
   y := []uint32{31,37,41,43}
   originalX, originalY := [4]uint32{x[0],x[1],x[2],x[3]}, [4]uint32{31,37,41,43}
   canary := [4]uint64{11,17,29,53}
   want := x[0]
   if length!=1 { want=x[1] }
`)
	c.WriteString(`#include <stdint.h>
#include <string.h>
#if defined(__APPLE__)
#define LABEL(name) "_" name
#else
#define LABEL(name) name
#endif
`)
	for _, form := range forms {
		declaration := strings.ReplaceAll(x86CallerFixtureSource, "float32", "uint32")
		declaration = declaration[strings.Index(declaration, "//go:noescape"):]
		declaration = strings.ReplaceAll(declaration, "kernel", form.name)
		declaration = strings.Replace(declaration, "func Call(", "func Call"+form.name+"(", 1)
		declarations.WriteString(declaration)
		source := strings.ReplaceAll(x86CallerFixtureAssembly, "·kernel", "·"+form.name)
		source = strings.Replace(source, "MOVL $7,AX", "MOVQ (CX),AX", 1)
		machine.WriteString(strings.Replace(source, "MOVL AX,(DX)", form.body, 1))
		want := "want"
		if form.width == 1 {
			want = "uint32(42)"
		}
		fmt.Fprintf(&tests, `
   if got:=Call%s(x[:length],y); got!=%s ||
    [4]uint32{x[0],x[1],x[2],x[3]}!=originalX || [4]uint32{y[0],y[1],y[2],y[3]}!=originalY ||
    canary!=[4]uint64{11,17,29,53} { t.Fatalf("%s length=%%d got=%%#x",length,got) }
`, form.name, want, form.name)
		fmt.Fprintf(&c, "extern void %s(void*,void*,void*,void*) __asm__(LABEL(\"caller.%s\"));\n", form.name, form.name)
	}
	tests.WriteString("  }\n }\n}\n")
	c.WriteString(`int main(void) {
 const uint32_t values[]={0,1,7,0x80000000u,0xffffffffu,0x12345678u};
 for (unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++) {
  for (uint64_t length=1;length<=4;length++) {
   uint8_t a[33],b[35],output[29],before[29],a_before[33],b_before[35];
   uint32_t x[4]={values[i],values[i]^0xaabbccddu,19,23},y[4]={31,37,41,43};
   memset(a,0xa3,sizeof(a));memset(b,0xb7,sizeof(b));
   memcpy(a+1,x,sizeof(x));memcpy(b+3,y,sizeof(y));
   memcpy(a_before,a,sizeof(a));memcpy(b_before,b,sizeof(b));
   const uint64_t old_length=length;
`)
	for _, form := range forms {
		want := "x[length==1?0:1]"
		if form.width == 1 {
			want = "42"
		}
		fmt.Fprintf(&c, `
   memset(output,0xc9,sizeof(output));memcpy(before,output,sizeof(output));
   { uint32_t want=%s;memcpy(before+5,&want,%d);
     %s(a+1,b+3,output+5,&length);
     if (memcmp(output,before,sizeof(output)) || memcmp(a,a_before,sizeof(a)) ||
      memcmp(b,b_before,sizeof(b)) || length!=old_length) return 1;
   }
`, want, form.width, form.name)
	}
	c.WriteString("  }\n }\n return 0;\n}\n")
	return declarations.String(), machine.String(), tests.String(), c.String()
}

func TestCrossLinuxRuntimeMatrixX86GoCallerAcyclicJoinValuesAndCanaries(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("requires the separately required Linux/amd64 caller runtime counterpart")
	}
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	goSource, assembly, goTest, cOracle := x86CallerAcyclicRuntimeSources()
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module caller\n\ngo 1.20\n", "value.go": goSource,
		"value_amd64.s": assembly, "value_test.go": goTest,
	} {
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
		t.Fatalf("actual original Go caller branch/canary oracle: %v\n%s", err, output)
	}
	pkg := x86CallerRuntimePackage(t, goSource, assembly)
	llvmContext := llvm.NewContext()
	defer llvmContext.Dispose()
	triple := testTargetTriple(runtime.GOOS, "amd64")
	translation, err := translateGoModuleInContext(llvmContext, pkg, []byte(assembly), GoModuleOptions{
		FileName: "value_amd64.s", GOARCH: "amd64", TargetTriple: triple,
		ResolveSym: func(symbol string) string { return strings.Replace(symbol, "·", "caller.", 1) },
	})
	if translation != nil && !translation.Module.IsNil() {
		defer translation.Module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	var runner []string
	if crossRosetta {
		runner = []string{"/usr/bin/arch", "-x86_64"}
	}
	compileAndRunRuntimeTestForTarget(t, llc, clang, "caller_acyclic_join", triple, translation.Module.String(), cOracle, runner)
}
