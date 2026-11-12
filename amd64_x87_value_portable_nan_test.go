package plan9asm

import (
	"fmt"
	"runtime"
	"testing"
)

// Exact 10-byte results observed from independent original FLDS/FLDL followed
// by FSTPT, with invalid masked. Hardware IE was recorded separately; these
// value tests neither implement nor claim a software status-word exception.
var x87PortableNativeLoads = []struct {
	width int
	input uint64
	kind  string
	want  x87PortableBits
}{
	{64, 0x7ff0000000000001, "SNaN", x87PortableBits{0xc000000000000800, 0x7fff}},
	{64, 0xfff0000000000001, "SNaN", x87PortableBits{0xc000000000000800, 0xffff}},
	{64, 0x7ff8000000000001, "QNaN", x87PortableBits{0xc000000000000800, 0x7fff}},
	{64, 0xfff8000000000001, "QNaN", x87PortableBits{0xc000000000000800, 0xffff}},
	{64, 0x7ff0000000000000, "Inf", x87PortableBits{0x8000000000000000, 0x7fff}},
	{64, 0xfff0000000000000, "Inf", x87PortableBits{0x8000000000000000, 0xffff}},
	{32, 0x7f800001, "SNaN", x87PortableBits{0xc000010000000000, 0x7fff}},
	{32, 0xff800001, "SNaN", x87PortableBits{0xc000010000000000, 0xffff}},
	{32, 0x7fc00001, "QNaN", x87PortableBits{0xc000010000000000, 0x7fff}},
	{32, 0xffc00001, "QNaN", x87PortableBits{0xc000010000000000, 0xffff}},
	{32, 0x7f800000, "Inf", x87PortableBits{0x8000000000000000, 0x7fff}},
	{32, 0xff800000, "Inf", x87PortableBits{0x8000000000000000, 0xffff}},
}

func TestCrossLinuxRuntimeMatrixX87PortableNativeLoadAnchors(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang are required")
	}
	ir := x87PortableScalarModule(t)
	for _, observed := range x87PortableNativeLoads {
		t.Run(fmt.Sprintf("f%d-%s-%x", observed.width, observed.kind, observed.input), func(t *testing.T) {
			oracle := fmt.Sprintf(`#include <stdint.h>
#include <stdio.h>
extern void widen%d(uint64_t*,uint%d_t);
int main(void) {
    uint64_t out[3]={0,0,19};
    widen%d(out,UINT64_C(%d));
    if (out[0]!=UINT64_C(%d)||out[1]!=%d||out[2]!=19) {
        fprintf(stderr,"observed native load got=%%llx/%%llx expected=%%llx/%%x\n",
            (unsigned long long)out[0],(unsigned long long)out[1],
            (unsigned long long)UINT64_C(%d),%d);
        return 1;
    }
    return 0;
}
`, observed.width, observed.width, observed.width, observed.input,
				observed.want.significand, observed.want.signExponent,
				observed.want.significand, observed.want.signExponent)
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "portable80-native-load", testTargetTriple(runtime.GOOS, runtime.GOARCH), ir, oracle, nil, 0)
		})
	}
}
