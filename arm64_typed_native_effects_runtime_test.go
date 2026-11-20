package plan9asm

import (
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestCrossLinuxRuntimeMatrixARM64TypedNativeEffects(t *testing.T) {
	llc, triple, compiler, runner := arm64FPPairRuntimeTools(t)
	var source strings.Builder
	fmt.Fprintln(&source, "TEXT ·ReadDCZID<ABIInternal>(SB),4,$0\nMRS DCZID_EL0,R0\nRET")
	spec := arm64GoSystemRegisters["DCZID_EL0"]
	fmt.Fprintf(&source, "TEXT ·ReadDCZIDRaw<ABIInternal>(SB),4,$0\nWORD $0x%08x\nRET\n", uint32(0xd5300000)|uint32(spec.encoding)<<5)
	fmt.Fprintln(&source, "TEXT ·PrefetchHints<ABIInternal>(SB),4,$0\nCMP $0,R1")
	// PRFM hints are not loads/stores, and do not alter GP registers or NZCV.
	// RPRFM is object-tested separately: executing its newer ISA without an
	// independently established CPU feature would not be a valid oracle.
	for _, hint := range []string{
		"PLDL1KEEP", "PLDL1STRM", "PLDL2KEEP", "PLDL2STRM", "PLDL3KEEP", "PLDL3STRM",
		"PLIL1KEEP", "PLIL1STRM", "PLIL2KEEP", "PLIL2STRM", "PLIL3KEEP", "PLIL3STRM",
		"PSTL1KEEP", "PSTL1STRM", "PSTL2KEEP", "PSTL2STRM", "PSTL3KEEP", "PSTL3STRM",
	} {
		fmt.Fprintf(&source, "PRFM (R0),%s\n", hint)
	}
	fmt.Fprintln(&source, "MRS DCZID_EL0,R3\nADD $9,R1,R0\nCINC NE,R0,R0\nRET")
	const declarations = "func ReadDCZID() uint64\nfunc ReadDCZIDRaw() uint64\nfunc PrefetchHints(*byte,uint64) uint64\n"
	goMain := "package main\n" + declarations + `func main() {
  a := [64]byte{}
  for i:=range a { a[i]=byte(i*7+3) }
  saved:=a
  for _,input:=range []uint64{0,1,123,0x8000000000000000,^uint64(0)} {
    want:=input+9; if input!=0 { want++ }
    if PrefetchHints(&a[3],input)!=want || a!=saved { panic("prefetch data/GP/NZCV effect") }
    if ReadDCZID()!=ReadDCZIDRaw() { panic("named/raw DCZID mismatch") }
  }
}
`
	runARM64GoInternalOracle(t, source.String(), goMain, len(runner) != 0)
	pkg := mustGoPackage(t, "test/nativeeffects", "package nativeeffects\n"+declarations)
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	tr, err := translateGoModuleInContext(ctx, pkg, []byte(source.String()), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: triple,
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Module.Dispose()
	const main = `#include <stdint.h>
#include <string.h>
extern uint64_t ReadDCZID(void), ReadDCZIDRaw(void);
extern uint64_t PrefetchHints(uint8_t*,uint64_t);
int main(void) {
  uint8_t a[64], saved[64];
  for (unsigned i=0;i<64;i++) a[i]=(uint8_t)(i*7+3);
  memcpy(saved,a,64);
  const uint64_t inputs[]={0,1,123,UINT64_C(0x8000000000000000),UINT64_MAX};
  for (unsigned i=0;i<5;i++) {
    uint64_t native;
    __asm__ volatile("mrs %0, DCZID_EL0" : "=r"(native));
    if (ReadDCZID()!=native || ReadDCZIDRaw()!=native) return 1;
    if (PrefetchHints(a+3,inputs[i])!=inputs[i]+9+(inputs[i]!=0)) return 2;
    if (memcmp(a,saved,64)!=0) return 3;
  }
  return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "typed_native_effects", triple, tr.Module.String(), main, runner)
}
