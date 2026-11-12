package plan9asm

import (
	"fmt"
	"go/types"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type arm64NZCVConsumerIR struct{ name, ir string }

// All consumers use signatures obtained from the same Go declarations as the
// original executable. Dispose each module before moving to the next consumer.
func arm64NZCVConsumerIRs(t *testing.T, source, declarations, triple string) []arm64NZCVConsumerIR {
	t.Helper()
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "compare", declarations)
	sizes := types.SizesFor("gc", "arm64")
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, nil)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "arm64", TargetTriple: triple, Sigs: sigs, ResolveSym: resolve}
	text, err := Translate(file, options)
	if err != nil {
		t.Fatal(err)
	}
	public, err := TranslateModule(file, options)
	if err != nil {
		t.Fatal(err)
	}
	publicIR := public.String()
	public.Dispose()
	context := llvm.NewContext()
	defer context.Dispose()
	module, err := TranslateModuleInContext(context, file, options)
	if err != nil {
		t.Fatal(err)
	}
	direct := module.String()
	module.Dispose()
	bound, err := translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: triple, ResolveSym: resolve,
	})
	if err != nil {
		t.Fatal(err)
	}
	goBound := bound.Module.String()
	bound.Module.Dispose()
	return []arm64NZCVConsumerIR{
		{"text", text}, {"public-module", publicIR},
		{"in-context", direct}, {"typed-go", goBound},
	}
}

func arm64NZCVRunConsumers(t *testing.T, llc string, compiler []string, name, triple, source, declarations, driver string, runner []string) {
	t.Helper()
	for _, consumer := range arm64NZCVConsumerIRs(t, source, declarations, triple) {
		t.Run(consumer.name, func(t *testing.T) {
			for _, variant := range []struct{ name, ir string }{{"none", consumer.ir}, {"O2", armFloatEffectOptimizedIR(t, consumer.ir)}} {
				for _, level := range []int{0, 2} {
					t.Run(fmt.Sprintf("IR_%s/backend_O%d", variant.name, level), func(t *testing.T) {
						compileAndRunRuntimeTestWithCompiler(t, llc, compiler, name, triple, variant.ir, driver, runner, level)
					})
				}
			}
		})
	}
}

// Independent first-party counterexample: integer CMP sets source NZCV=0110.
// MRS must read that source state, not whichever flags LLVM's own bookkeeping
// last left in the physical processor.
const arm64NZCVReadSource = `TEXT compareNZCV(SB),4,$0-16
MOVD in+0(FP),R0
MOVD out+8(FP),R1
MOVD (R0),R2
CMP R2,R2
MRS NZCV,R3
MOVD R3,(R1)
RET
`

func arm64NZCVReadRuntime(t *testing.T, triple, goos string, compiler, runner []string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	original := `package main
import "fmt"
func compareNZCV(*uint64,*uint64)
func main() {
 for _, input := range []uint64{0,1,0x8000000000000000,0xffffffffffffffff} {
  var output uint64
  compareNZCV(&input,&output)
  if output != 0x60000000 { panic(fmt.Sprintf("original NZCV=%x",output)) }
 }
 fmt.Println("ARM64_COMPARE_ORIGINAL_PASS NZCV=0x60000000")
}
`
	arm64ScalarCompareActualGo(t, arm64NZCVReadSource, original, goos, runner)
	driver := `#include <stdint.h>
#include <stdio.h>
extern void compareNZCV(uint64_t*,uint64_t*);
int main(void) {
 uint64_t inputs[]={0,1,UINT64_C(0x8000000000000000),UINT64_MAX};
 for(unsigned i=0;i<4;i++) {
  uint64_t output=0;
  compareNZCV(&inputs[i],&output);
  if(output!=0x60000000) {
   fprintf(stderr,"source NZCV input=%u got=%llx want=60000000\n",i,(unsigned long long)output);
   return 1;
  }
 }
 return 0;
}
`
	declarations := "package compare\nfunc compareNZCV(*uint64,*uint64)\n"
	arm64NZCVRunConsumers(t, llc, compiler, "nzcv_read", triple, arm64NZCVReadSource, declarations, driver, runner)
}

func TestARM64NZCVReadOriginalGoNativeRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("Darwin host counterpart; required Linux/QEMU owner runs the same original-Go oracle")
	}
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	arm64NZCVReadRuntime(t, "aarch64-apple-darwin", "darwin", []string{clang}, nil)
}
