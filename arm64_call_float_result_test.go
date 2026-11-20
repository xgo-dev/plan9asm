package plan9asm

import (
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestCrossLinuxRuntimeMatrixARM64TypedCallFloatBits(t *testing.T) {
	llc, target, compiler, runner := arm64FPPairRuntimeTools(t)
	const source = `TEXT ·FloatResult(SB),4,$24-16
MOVD a+0(FP),R5
MOVD R5,8(RSP)
CALL ·X(SB)
FMOVD 16(RSP),F0
FMOVD F0,R5
MOVD R5,ret+8(FP)
RET
`
	runARM64LocalRegisterGoOracle(t, source, `package main
import "math"
func FloatResult(uint64) uint64
func X(a uint64) float64 { return math.Float64frombits(a) }
func main() {
 for _, a := range []uint64{0,1,0x3ff0000000000000,0x7ff8123456789abc,0x8000000000000000,^uint64(0)} {
  if got:=FloatResult(a); got!=a { println(got,a); panic("actual Go unsigned-to-floating bit transport") }
 }
}
`, len(runner) != 0, "1.20")
	pkg := mustGoPackage(t, "test/floatbits", "package floatbits\nfunc FloatResult(uint64) uint64\nfunc X(uint64) float64\n")
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
		GOARCH: "arm64", TargetTriple: target,
		ResolveSym: func(sym string) string { return strings.TrimPrefix(sym, "·") },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Module.Dispose()
	const driver = `#include <stdint.h>
#include <string.h>
extern uint64_t FloatResult(uint64_t);
double X(uint64_t value) {
 double result;
 memcpy(&result,&value,sizeof result);
 return result;
}
int main(void) {
 const uint64_t inputs[]={0,1,UINT64_C(0x3ff0000000000000),UINT64_C(0x7ff8123456789abc),UINT64_C(0x8000000000000000),UINT64_MAX};
 for(unsigned i=0;i<sizeof inputs/sizeof inputs[0];i++) {
  if(FloatResult(inputs[i])!=inputs[i]) return 1;
 }
 return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "typed_call_float_bits", target, bound.Module.String(), driver, runner)
}
