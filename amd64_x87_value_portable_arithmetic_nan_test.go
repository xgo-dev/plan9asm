package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Independent Intel native fadd/fsub/fmul/fdiv observations, with masked
// exceptions and CW=0x037f. The full 144-row raw record digest is
// 926c61f256f6cd0d8fa43b504cd2f08bf36c45bb4063d49c96088b99903a4031.
// Software exception flags and other control words are not asserted here.
func x87PortableNativeArithmeticProgram() string {
	var c strings.Builder
	c.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for _, op := range []string{"fadd", "fsub", "fmul", "fdiv"} {
		fmt.Fprintf(&c, "extern void binary_%s(uint64_t*,uint64_t,uint16_t,uint64_t,uint16_t,uint16_t);\n", op)
	}
	c.WriteString("typedef void (*binary)(uint64_t*,uint64_t,uint16_t,uint64_t,uint16_t,uint16_t);\n")
	c.WriteString("static binary operations[]={binary_fadd,binary_fsub,binary_fmul,binary_fdiv};\n")
	c.WriteString("struct row {unsigned op;uint64_t a;uint16_t ae;uint64_t b;uint16_t be;uint64_t want;uint16_t we;};\nstatic struct row rows[]={\n")
	add := func(op int, a, b, want x87PortableBits) {
		fmt.Fprintf(&c, "{%d,UINT64_C(%d),%d,UINT64_C(%d),%d,UINT64_C(%d),%d},\n", op, a.significand, a.signExponent, b.significand, b.signExponent, want.significand, want.signExponent)
	}
	// These twelve native NaN results were identical across all four operations
	// and both operand orders. No emitter selection formula computes the literals.
	nanPairs := []struct{ left, right, want x87PortableBits }{
		{ // QQ-different-payload
			left:  x87PortableBits{0xc000000000000001, 0x7fff},
			right: x87PortableBits{0xc00000000000ffff, 0x7fff},
			want:  x87PortableBits{0xc00000000000ffff, 0x7fff},
		},
		{ // QQ-equal-payload-opposite-sign
			left:  x87PortableBits{0xc000000000000001, 0x7fff},
			right: x87PortableBits{0xc000000000000001, 0xffff},
			want:  x87PortableBits{0xc000000000000001, 0x7fff},
		},
		{ // QQ-different-payload-opposite-sign
			left:  x87PortableBits{0xc000000000000001, 0x7fff},
			right: x87PortableBits{0xc00000000000ffff, 0xffff},
			want:  x87PortableBits{0xc00000000000ffff, 0xffff},
		},
		{ // SS-different-payload
			left:  x87PortableBits{0x8000000000000001, 0x7fff},
			right: x87PortableBits{0x800000000000ffff, 0x7fff},
			want:  x87PortableBits{0xc00000000000ffff, 0x7fff},
		},
		{ // SS-equal-payload-opposite-sign
			left:  x87PortableBits{0x8000000000000001, 0x7fff},
			right: x87PortableBits{0x8000000000000001, 0xffff},
			want:  x87PortableBits{0xc000000000000001, 0x7fff},
		},
		{ // SS-different-payload-opposite-sign
			left:  x87PortableBits{0x8000000000000001, 0x7fff},
			right: x87PortableBits{0x800000000000ffff, 0xffff},
			want:  x87PortableBits{0xc00000000000ffff, 0xffff},
		},
		{ // SQ-small-S-large-Q
			left:  x87PortableBits{0x8000000000000001, 0x7fff},
			right: x87PortableBits{0xc00000000000ffff, 0x7fff},
			want:  x87PortableBits{0xc00000000000ffff, 0x7fff},
		},
		{ // SQ-large-S-small-Q
			left:  x87PortableBits{0x800000000000ffff, 0x7fff},
			right: x87PortableBits{0xc000000000000001, 0x7fff},
			want:  x87PortableBits{0xc000000000000001, 0x7fff},
		},
		{ // SQ-equal-low-payload-opposite-sign
			left:  x87PortableBits{0x8000000000000001, 0x7fff},
			right: x87PortableBits{0xc000000000000001, 0xffff},
			want:  x87PortableBits{0xc000000000000001, 0xffff},
		},
		{ // SQ-opposite-sign-large-S-small-Q
			left:  x87PortableBits{0x800000000000ffff, 0xffff},
			right: x87PortableBits{0xc000000000000001, 0x7fff},
			want:  x87PortableBits{0xc000000000000001, 0x7fff},
		},
		{ // S-finite
			left:  x87PortableBits{0x8000000000000001, 0x7fff},
			right: x87PortableBits{0x8000000000000000, 0x3fff},
			want:  x87PortableBits{0xc000000000000001, 0x7fff},
		},
		{ // Q-finite
			left:  x87PortableBits{0xc00000000000ffff, 0x7fff},
			right: x87PortableBits{0x8000000000000000, 0xbfff},
			want:  x87PortableBits{0xc00000000000ffff, 0x7fff},
		},
	}
	for _, pair := range nanPairs {
		for op := 0; op < 4; op++ {
			add(op, pair.left, pair.right, pair.want)
			add(op, pair.right, pair.left, pair.want)
		}
	}
	controls := []struct {
		left, right x87PortableBits
		want        [8]x87PortableBits // Operation order, forward then reversed.
	}{
		{ // finite-noncommuting
			left:  x87PortableBits{0x8000000000000000, 0x3fff},
			right: x87PortableBits{0x8000000000000000, 0x4000},
			want: [8]x87PortableBits{
				{0xc000000000000000, 0x4000},
				{0xc000000000000000, 0x4000},
				{0x8000000000000000, 0xbfff},
				{0x8000000000000000, 0x3fff},
				{0x8000000000000000, 0x4000},
				{0x8000000000000000, 0x4000},
				{0x8000000000000000, 0x3ffe},
				{0x8000000000000000, 0x4000},
			},
		},
		{ // finite-cancellation
			left:  x87PortableBits{0x8000000000000000, 0x3fff},
			right: x87PortableBits{0x8000000000000000, 0xbfff},
			want: [8]x87PortableBits{
				{0x0000000000000000, 0x0000},
				{0x0000000000000000, 0x0000},
				{0x8000000000000000, 0x4000},
				{0x8000000000000000, 0xc000},
				{0x8000000000000000, 0xbfff},
				{0x8000000000000000, 0xbfff},
				{0x8000000000000000, 0xbfff},
				{0x8000000000000000, 0xbfff},
			},
		},
		{ // signed-zero-finite
			left:  x87PortableBits{0x0000000000000000, 0x8000},
			right: x87PortableBits{0x8000000000000000, 0x3fff},
			want: [8]x87PortableBits{
				{0x8000000000000000, 0x3fff},
				{0x8000000000000000, 0x3fff},
				{0x8000000000000000, 0xbfff},
				{0x8000000000000000, 0x3fff},
				{0x0000000000000000, 0x8000},
				{0x0000000000000000, 0x8000},
				{0x0000000000000000, 0x8000},
				{0x8000000000000000, 0xffff},
			},
		},
		{ // infinity-finite
			left:  x87PortableBits{0x8000000000000000, 0x7fff},
			right: x87PortableBits{0x8000000000000000, 0x4000},
			want: [8]x87PortableBits{
				{0x8000000000000000, 0x7fff},
				{0x8000000000000000, 0x7fff},
				{0x8000000000000000, 0x7fff},
				{0x8000000000000000, 0xffff},
				{0x8000000000000000, 0x7fff},
				{0x8000000000000000, 0x7fff},
				{0x8000000000000000, 0x7fff},
				{0x0000000000000000, 0x0000},
			},
		},
		{ // opposite-infinities
			left:  x87PortableBits{0x8000000000000000, 0x7fff},
			right: x87PortableBits{0x8000000000000000, 0xffff},
			want: [8]x87PortableBits{
				{0xc000000000000000, 0xffff},
				{0xc000000000000000, 0xffff},
				{0x8000000000000000, 0x7fff},
				{0x8000000000000000, 0xffff},
				{0x8000000000000000, 0xffff},
				{0x8000000000000000, 0xffff},
				{0xc000000000000000, 0xffff},
				{0xc000000000000000, 0xffff},
			},
		},
		{ // infinity-zero
			left:  x87PortableBits{0x8000000000000000, 0x7fff},
			right: x87PortableBits{0x0000000000000000, 0x0000},
			want: [8]x87PortableBits{
				{0x8000000000000000, 0x7fff},
				{0x8000000000000000, 0x7fff},
				{0x8000000000000000, 0x7fff},
				{0x8000000000000000, 0xffff},
				{0xc000000000000000, 0xffff},
				{0xc000000000000000, 0xffff},
				{0x8000000000000000, 0x7fff},
				{0x0000000000000000, 0x0000},
			},
		},
	}
	for _, pair := range controls {
		for op := 0; op < 4; op++ {
			add(op, pair.left, pair.right, pair.want[2*op])
			add(op, pair.right, pair.left, pair.want[2*op+1])
		}
	}
	c.WriteString(`};
int main(void) {
    unsigned errors=0;
    unsigned total=sizeof(rows)/sizeof(rows[0]);
    if(total!=144)return 2;
    for(unsigned index=0;index<total;index++) {
        struct row r=rows[index];
        uint64_t out[3]={0,0,19};
        operations[r.op](out,r.a,r.ae,r.b,r.be,0x037f);
        if(out[0]!=r.want||out[1]!=r.we||out[2]!=19) {
            errors++;
            fprintf(stderr,"native anchor row=%u op=%u a=%llx/%x b=%llx/%x got=%llx/%llx want=%llx/%x\n",
                index,r.op,(unsigned long long)r.a,r.ae,(unsigned long long)r.b,r.be,
                (unsigned long long)out[0],(unsigned long long)out[1],(unsigned long long)r.want,r.we);
        }
    }
    if(errors)fprintf(stderr,"native anchors rows=%u mismatches=%u\n",total,errors);
    return errors!=0;
}
`)
	return c.String()
}

func TestCrossLinuxRuntimeMatrixX87PortableArithmeticNativeAnchors(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM 22 llc/clang are required")
	}
	ir, oracle := x87PortableArithmeticModule(t), x87PortableNativeArithmeticProgram()
	for _, optimization := range []int{0, 2} {
		t.Run(fmt.Sprintf("backend%d", optimization), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "portable80-arithmetic-native-anchors", testTargetTriple(runtime.GOOS, runtime.GOARCH), ir, oracle, nil, optimization)
		})
	}
}
