//go:build linux && amd64

package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The Linux AMD64 owner must execute both native ISA modes. Other hosts retain
// portable objects and source checks; no missing compiler/ISA counts as a pass.
func TestCrossLinuxRuntimeMatrixX86DirectTailPCResultAliasesAndExternal(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	for _, arch := range []string{"amd64", "386"} {
		t.Run(arch, func(t *testing.T) {
			goType, cType, values := "uint64", "uint64_t", "0,1,7,0x80000000,0xffffffff,0xffffffffffffffff"
			triple, compiler := "x86_64-unknown-linux-gnu", []string{clang, "-target", "x86_64-unknown-linux-gnu"}
			checks := 24
			if arch == "386" {
				goType, cType, values = "uint32", "uint32_t", "0,1,7,0x80000000,0xffffffff"
				triple = "i386-unknown-linux-gnu"
				cross, err := exec.LookPath("i686-linux-gnu-gcc")
				if err != nil {
					t.Fatal("native i386 owner requires the static cross compiler", err)
				}
				compiler, checks = []string{cross, "-static", "-no-pie"}, 20
			}
			execution := x86FloatCompareExecution{llc: llc, triple: triple, compiler: compiler}
			source, declarations := x86DirectTailFollowupFixture(arch)
			declarations = strings.Replace(declarations, "func ordinary(a "+goType+") "+goType+"\n",
				"func ordinary(a "+goType+") "+goType+" {return a*3+11}\n", 1)
			goDriver := fmt.Sprintf(`package main
import "fmt"
%s
//go:noinline
func snapshot(p *[2]uint64) [2]uint64 {return *p}
func main() {
 values:=[]%s{%s}
 canaries:=[2]uint64{0x1122334455667788,0xaabbccddeeff0099}
 before:=snapshot(&canaries)
 for _,a:=range values {
  forward:=a*3+11; if a==0 {forward=7}
  b:=a^%s(0x87654321)
  n:=(a&7)+1
  got:=[]%s{Forward(a),Address(a),Alternate(a,b),Backward(n)}
  want:=[]%s{forward,a+7,a+b+7,n+7}
  for i:=range got {if got[i]!=want[i] {panic(fmt.Sprintf("case %%d got %%x want %%x",i,got[i],want[i]))}}
  if snapshot(&canaries)!=before {panic("original caller canary changed")}
 }
 fmt.Println("direct-tail followup: %d checks")
}
`, declarations, goType, values, goType, goType, goType, checks)
			dir := t.TempDir()
			for name, contents := range map[string]string{"go.mod": "module directfollowup\n\ngo 1.20\n", "main.go": goDriver, "tail_" + arch + ".s": source} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			original := filepath.Join(dir, "original")
			command := exec.Command("go", "build", "-p=1", "-o", original, ".")
			command.Dir = dir
			command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0", "GOMAXPROCS=2")
			x86FloatCompareCaptureCommand(t, command)
			want := fmt.Sprintf("direct-tail followup: %d checks\n", checks)
			if output := execution.run(t, original); string(output) != want {
				t.Fatalf("incomplete original Go: %s", output)
			}
			cDriver := fmt.Sprintf(`#include <stdint.h>
#include <stdio.h>
typedef %s U;
extern U Forward(U),Address(U),Alternate(U,U),Backward(U);
U ordinary(U a) {return a*3+11;}
int main(void) {
 const U values[]={%s};
 volatile uint64_t canaries[]={UINT64_C(0x1122334455667788),UINT64_C(0xaabbccddeeff0099)};
 for(unsigned v=0;v<sizeof(values)/sizeof(values[0]);v++) {
  U a=values[v], b=a^(U)0x87654321, n=(a&7)+1;
  U actual[]={Forward(a),Address(a),Alternate(a,b),Backward(n)};
  U reference[]={a==0?7:a*3+11,a+7,a+b+7,n+7};
  for(unsigned i=0;i<4;i++) if(actual[i]!=reference[i]) {fprintf(stderr,"case %%u got %%llx want %%llx\n",i,(unsigned long long)actual[i],(unsigned long long)reference[i]);return 1;}
  if(canaries[0]!=UINT64_C(0x1122334455667788)||canaries[1]!=UINT64_C(0xaabbccddeeff0099)) return 1;
 }
 puts("direct-tail followup: %d checks");
 return 0;
}
`, cType, values, checks)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					if output := execution.compileAndRunLLVM(t, "direct-tail-followup", ir, cDriver, level); string(output) != want {
						t.Fatalf("%s/%s incomplete LLVM: %s", api, level, output)
					}
					t.Log(api, level, strings.TrimSpace(want))
				}
			}
		})
	}
}
