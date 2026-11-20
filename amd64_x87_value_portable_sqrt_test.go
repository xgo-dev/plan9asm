package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func x87PortableSquareRootModule(t *testing.T) string {
	t.Helper()
	var ir strings.Builder
	ir.WriteString("declare i64 @llvm.ctlz.i64(i64, i1)\ndefine void @sqrt80(ptr %out,i64 %sig,i16 %se,i16 %cw){\n")
	ctx := amd64Ctx{b: &ir}
	value, err := ctx.x87PortableSquareRoot(ctx.packX87("%sig", "%se"), "%cw")
	if err != nil {
		t.Fatal(err)
	}
	sig, se := ctx.partsX87(value)
	fmt.Fprintf(&ir, "  store i64 %s,ptr %%out,align 1\n  %%high = getelementptr i8,ptr %%out,i32 8\n  store i16 %s,ptr %%high,align 1\n  ret void\n}\n", sig, se)
	return ir.String()
}

func x87PortableSquareRootRepresentativeInputs() []x87PortableBits {
	return []x87PortableBits{
		{0, 0}, {0, 0x8000}, {1 << 63, 0x3fff}, {1 << 63, 0x4000},
		{0xc000000000000000, 0x4000}, {1 << 63, 0x4001},
		{0x8000000000000001, 0x3fff}, {0xffffffffffffffff, 0x3ffe},
		{1, 0}, {0x7fffffffffffffff, 0}, {1 << 63, 1}, {0xffffffffffffffff, 0x7ffe},
		{0xc90fdaa22168c235, 0x4000},
		{0x8000010000007fff, 0x3fff}, {0x8000010000008000, 0x3fff},
		{0x8000010000008001, 0x3fff}, {0x8000030000048000, 0x3fff},
		{1 << 63, 16383 + 2000}, {1 << 63, 16383 - 2000},
		{1 << 63, 16383 + 16000}, {1 << 63, 16383 - 16000},
	}
}

func x87PortableSquareRootFiniteProgram(t *testing.T) string {
	t.Helper()
	inputs := x87PortableSquareRootRepresentativeInputs()
	state := uint64(0x1c5789b614fd302e)
	for index := 0; index < 64; index++ {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		inputs = append(inputs, x87PortableBits{state | 1<<63, uint16(1 + state%32766)})
	}
	var rows strings.Builder
	for _, input := range inputs {
		value, valid := x87PortableRational(input)
		if !valid || value.Sign() < 0 {
			t.Fatal("finite oracle received a noncanonical or negative input", input)
		}
		for _, precision := range []int{24, 53, 64} {
			pc := map[int]int{24: 0, 53: 0x200, 64: 0x300}[precision]
			for rounding := 0; rounding < 4; rounding++ {
				want := x87PortableSqrtSquareOracle(value, precision, rounding)
				if input.significand == 0 {
					want.signExponent = input.signExponent
				}
				fmt.Fprintf(&rows, "{UINT64_C(%d),%d,%d,UINT64_C(%d),%d},\n", input.significand, input.signExponent, 0x7f|pc|rounding<<10, want.significand, want.signExponent)
			}
		}
	}
	return x87PortableSquareRootCheckProgram(rows.String(), 1020)
}

func x87PortableSquareRootCheckProgram(rows string, count int) string {
	var c strings.Builder
	c.WriteString("#include <stdint.h>\n#include <stdio.h>\nextern void sqrt80(uint64_t*,uint64_t,uint16_t,uint16_t);\n")
	c.WriteString("struct row {uint64_t input;uint16_t se;uint16_t cw;uint64_t want;uint16_t we;};\nstatic struct row rows[]={\n")
	c.WriteString(rows)
	c.WriteString(`};
int main(void){
    unsigned errors=0,total=sizeof(rows)/sizeof(rows[0]);
`)
	fmt.Fprintf(&c, "    if(total!=%d)return 2;\n", count)
	c.WriteString(`
    for(unsigned index=0;index<total;index++){
        struct row r=rows[index];
        uint64_t out[3]={0,0,19};
        sqrt80(out,r.input,r.se,r.cw);
        if(out[0]!=r.want||out[1]!=r.we||out[2]!=19){
            errors++;
            fprintf(stderr,"sqrt row=%u input=%llx/%x cw=%x got=%llx/%llx want=%llx/%x\n",index,
                (unsigned long long)r.input,r.se,r.cw,(unsigned long long)out[0],
                (unsigned long long)out[1],(unsigned long long)r.want,r.we);
        }
    }
    if(errors)fprintf(stderr,"sqrt finite rows=%u mismatches=%u\n",total,errors);
    return errors!=0;
}
`)
	return c.String()
}

func TestX87PortableSquareRootObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	ir := x87PortableSquareRootModule(t)
	if strings.Contains(ir, "sqrt.f") || strings.Contains(ir, "x86_fp80") || strings.Contains(ir, "fp128") {
		t.Fatal("portable square root entered a floating approximation or target-specific carrier")
	}
	for _, target := range []string{"i386-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
		t.Run(target, func(t *testing.T) {
			for _, level := range []string{"-O0", "-O2"} {
				t.Run(level, func(t *testing.T) {
					x86PackedStringCompileObject(t, llc, target, ir, level)
				})
			}
		})
	}
}

func TestCrossLinuxRuntimeMatrixX87PortableSquareRootFinite(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang are required")
	}
	ir, oracle := x87PortableSquareRootModule(t), x87PortableSquareRootFiniteProgram(t)
	for _, level := range []int{0, 2} {
		t.Run(fmt.Sprintf("backend%d", level), func(t *testing.T) {
			compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "portable-sqrt-finite", testTargetTriple(runtime.GOOS, runtime.GOARCH), ir, oracle, nil, level)
		})
	}
}
