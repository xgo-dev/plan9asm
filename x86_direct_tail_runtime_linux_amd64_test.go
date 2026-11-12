//go:build linux && amd64

package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This owner executes the complete ordinary Go ABI0 file, not hand-replayed
// registers or a zero-argument helper ABI. Other hosts retain the portable
// source/identity tests; no skip counts as runtime evidence.
func TestCrossLinuxRuntimeMatrixAMD64DirectTailWholeSourceOriginalGoAndLLVM(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("native Linux AMD64 direct-tail owner requires LLVM22 llc/clang")
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "x86_64-unknown-linux-gnu",
		compiler: []string{clang, "-target", "x86_64-unknown-linux-gnu"}}
	fixture := x86DirectTailRuntimeSources("amd64")
	goDriver := `package main
import "fmt"
` + fixture.declarations + `
func reference(row int,a,b uint64) uint64 {
 switch row {
 case 2: if a==b {return 1}; return 0
 case 3: result:=a+b; if a<b {result++}; return result
 case 4: return uint64(uint32(a))+b
 case 6: if a==b {return a+b+5}; return a+b+3
 }
 return a+b
}
//go:noinline
func snapshot(p *[4]uint64) [4]uint64 {return *p}
func main() {
 values:=[]uint64{0,1,7,8,0xffffffff,0x100000000,0x8000000000000000,0xffffffffffffffff}
 canaries:=[4]uint64{0x1122334455667788,0xaabbccddeeff0099,0x9876543210abcdef,0xfedcba9876543210}
 before:=snapshot(&canaries)
 calls:=0
 for _,a:=range values {
` + fixture.goCalls + `
  if snapshot(&canaries)!=before {panic("original Go caller canaries changed")}
 }
 fmt.Printf("whole direct-tail original/LLVM: %d independent value checks\n",calls)
}
`
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod": "module directtail\n\ngo 1.20\n", "main.go": goDriver, "tail_amd64.s": fixture.assembly,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	original := filepath.Join(dir, "original")
	command := exec.Command("go", "build", "-p=1", "-o", original, ".")
	command.Dir = dir
	command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOMAXPROCS=2")
	x86FloatCompareCaptureCommand(t, command)
	want := "whole direct-tail original/LLVM: 504 independent value checks\n"
	if output := execution.run(t, original); string(output) != want {
		t.Fatalf("incomplete actual original Go execution: %s", output)
	}
	driver := `#include <stdint.h>
#include <stdio.h>
` + fixture.prototypes + `
static uint64_t reference(unsigned row,uint64_t a,uint64_t b) {
    if(row==2) return a==b;
    if(row==3) return a+b+(a<b);
    if(row==4) return (uint32_t)a+b;
    if(row==6) return a+b+(a==b?5:3);
    return a+b;
}
int main(void) {
    const uint64_t values[]={0,1,7,8,UINT64_C(0xffffffff),UINT64_C(0x100000000),UINT64_C(0x8000000000000000),UINT64_MAX};
    volatile uint64_t canaries[]={UINT64_C(0x1122334455667788),UINT64_C(0x9876543210abcdef)};
    unsigned calls=0;
    for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++) {
        uint64_t a=values[i];
` + fixture.cCalls + `
        if(canaries[0]!=UINT64_C(0x1122334455667788)||canaries[1]!=UINT64_C(0x9876543210abcdef)) return 1;
    }
    printf("whole direct-tail original/LLVM: %u independent value checks\n",calls);
    return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, fixture.assembly, fixture.declarations, "amd64", execution.triple, api)
		if err != nil {
			t.Fatal(api, err)
		}
		for _, level := range []string{"-O0", "-O2"} {
			output := execution.compileAndRunLLVM(t, "whole-direct-tail", ir, driver, level)
			if string(output) != want {
				t.Fatalf("%s/%s incomplete LLVM execution: %s", api, level, output)
			}
			t.Log(api, level, strings.TrimSpace(string(output)))
		}
	}
}
