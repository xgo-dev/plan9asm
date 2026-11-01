//go:build go1.27
// +build go1.27

package plan9asm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestCrossLinuxRuntimeMatrixARM64DCZVAEffects(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	original, err := os.ReadFile(filepath.Join(testGOROOT(t), "src/runtime/memclr_arm64.s"))
	if err != nil {
		t.Fatal(err)
	}
	// Rename only the entry symbol for a standalone native oracle. All source
	// instructions and the private block-size cache are the real implementation.
	source := strings.ReplaceAll(string(original), "runtime·memclrNoHeapPointers", "·Memclr") + `
TEXT ·ReadDCZID<ABIInternal>(SB),4,$0
MRS DCZID_EL0,R0
RET
TEXT ·ZeroGranule<ABIInternal>(SB),4,$0
MOVD R0,R2
CMP $0,R1
DC ZVA,R0
EOR R2,R0,R3
ADD R3,R1,R0
ADD $9,R0
CINC NE,R0,R0
RET
TEXT ·ZeroGranuleRaw<ABIInternal>(SB),4,$0
MOVD R0,R2
CMP $0,R1
WORD $0xd50b7420
EOR R2,R0,R3
ADD R3,R1,R0
ADD $9,R0
CINC NE,R0,R0
RET
`
	const declarations = `func Memclr(*byte,uintptr)
func ReadDCZID() uint64
func ZeroGranule(*byte,uint64) uint64
func ZeroGranuleRaw(*byte,uint64) uint64
`
	goMain := "package main\nimport \"unsafe\"\n" + declarations + `
func main() {
  d:=ReadDCZID()
  if d&16!=0 { panic("actual DCZID_EL0 prohibits ZVA; native execution not established") }
  n:=int(uint64(4)<<(d&15))
  a:=make([]byte,12*n+512)
  base:=int((-uintptr(unsafe.Pointer(&a[0])))&uintptr(n-1))+n
  fill:=func() { for i:=range a { a[i]=byte(i*7+3)|1 } }
  check:=func(start,count int) {
    for i,b:=range a {
      want:=byte(i*7+3)|1
      if i>=start && i<start+count { want=0 }
      if b!=want { panic("zero extent/canary mismatch") }
    }
  }
  for _,zero:=range []func(*byte,uint64)uint64{ZeroGranule,ZeroGranuleRaw} {
    for _,offset:=range []int{0,1,n/2,n-1,n,n+1,2*n-1} {
      for _,input:=range []uint64{0,1,123,1<<63,^uint64(0)} {
        fill()
        want:=input+9; if input!=0 { want++ }
        if zero(&a[base+offset],input)!=want { panic("ZVA GP/NZCV effect mismatch") }
        check(base+(offset/n)*n,n)
      }
    }
  }
  for _,offset:=range []int{0,1,15,16,63,n-1} {
    for _,count:=range []int{0,1,2,3,4,7,8,15,16,17,31,32,63,64,127,128,n-1,n,n+1,2*n+63,8*n+127} {
      fill()
      Memclr(&a[base+offset],uintptr(count))
      check(base+offset,count)
    }
  }
}
`
	runARM64GoInternalOracle(t, source, goMain, len(runner) != 0)
	pkg := mustGoPackage(t, "test/dczva", "package dczva\n"+declarations)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	tr, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: triple,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Module.Dispose()
	const main = `#include <stdint.h>
#include <stdlib.h>
#include <string.h>
extern void Memclr(uint8_t*,uintptr_t);
extern uint64_t ReadDCZID(void), ZeroGranule(uint8_t*,uint64_t), ZeroGranuleRaw(uint8_t*,uint64_t);
static void fill(uint8_t *a,size_t size) {
  for (size_t i=0;i<size;i++) a[i]=(uint8_t)(i*7+3)|1;
}
static int check(uint8_t *a,size_t size,size_t start,size_t count) {
  for (size_t i=0;i<size;i++) {
    uint8_t want=(uint8_t)(i*7+3)|1;
    if (i>=start && i<start+count) want=0;
    if (a[i]!=want) return 0;
  }
  return 1;
}
int main(void) {
  uint64_t d;
  __asm__ volatile("mrs %0, DCZID_EL0" : "=r"(d));
  if (ReadDCZID()!=d || (d&16)) return 1;
  size_t n=UINT64_C(4)<<(d&15),size=12*n+512;
  uint8_t *a=malloc(size),*native=malloc(size);
  if (!a || !native) return 2;
  size_t base=(-(uintptr_t)a&(n-1))+n;
  size_t nativebase=(-(uintptr_t)native&(n-1))+n;
  const uint64_t inputs[]={0,1,123,UINT64_C(1)<<63,UINT64_MAX};
  const size_t offsets[]={0,1,n/2,n-1,n,n+1,2*n-1};
  uint64_t (*zeros[])(uint8_t*,uint64_t)={ZeroGranule,ZeroGranuleRaw};
  for (unsigned z=0;z<2;z++) for (unsigned o=0;o<7;o++) for (unsigned k=0;k<5;k++) {
    fill(a,size); fill(native,size);
    uint64_t want=inputs[k]+9+(inputs[k]!=0);
    if (zeros[z](a+base+offsets[o],inputs[k])!=want) return 3;
    __asm__ volatile("dc zva,%0" :: "r"(native+nativebase+offsets[o]) : "memory");
    if (!check(a,size,base+(offsets[o]/n)*n,n) ||
        !check(native,size,nativebase+(offsets[o]/n)*n,n)) return 4;
  }
  const size_t starts[]={0,1,15,16,63,n-1};
  const size_t counts[]={0,1,2,3,4,7,8,15,16,17,31,32,63,64,127,128,n-1,n,n+1,2*n+63,8*n+127};
  for (unsigned o=0;o<6;o++) for (unsigned k=0;k<21;k++) {
    fill(a,size);
    Memclr(a+base+starts[o],counts[k]);
    if (!check(a,size,base+starts[o],counts[k])) return 5;
  }
  free(a); free(native);
  return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "dc_zva_effects", triple, tr.Module.String(), main, runner)
}
