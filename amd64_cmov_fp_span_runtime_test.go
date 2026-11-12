package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86CMOVFPPartialCrossSlotWholeBytes(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var declarations, assembly, prototypes, checks, goChecks strings.Builder
	declarations.WriteString("package oracle\n")
	for index, row := range []struct{ declaration, width, source, ctype, call, goCall, raw string }{
		{"f float32,old uint64", "W", "f+2(FP)", "float,uint64_t", "f,old", "math.Float32frombits(a),old", "uint64_t(a)>>16"},
		{"f float64,old uint64", "W", "f+6(FP)", "double,uint64_t", "d,old", "math.Float64frombits(q),old", "q>>48"},
		{"f float64,old uint64", "L", "f+4(FP)", "double,uint64_t", "d,old", "math.Float64frombits(q),old", "q>>32"},
		{"f,g float32,old uint64", "Q", "f+0(FP)", "float,float,uint64_t", "f,g,old", "math.Float32frombits(a),math.Float32frombits(b),old", "uint64_t(a)|(uint64_t(b)<<32)"},
		{"f,g float32,old uint64", "L", "f+2(FP)", "float,float,uint64_t", "f,g,old", "math.Float32frombits(a),math.Float32frombits(b),old", "(uint64_t(a)|(uint64_t(b)<<32))>>16"},
		{"f float32,g uint32,old uint64", "Q", "f+0(FP)", "float,uint32_t,uint64_t", "f,b,old", "math.Float32frombits(a),b,old", "uint64_t(a)|(uint64_t(b)<<32)"},
	} {
		fn := fmt.Sprintf("S%d", index)
		fmt.Fprintf(&declarations, "func %s(%s) uint64\n", fn, row.declaration)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-24\nMOVQ old+8(FP),AX\nCLC\nCMOV%sCC %s,AX\nMOVQ AX,ret+16(FP)\nRET\n", fn, row.width, row.source)
		fmt.Fprintf(&prototypes, "extern uint64_t %s(%s);\n", fn, row.ctype)
		raw := strings.ReplaceAll(row.raw, "uint64_t(", "uint64(")
		craw := strings.ReplaceAll(row.raw, "uint64_t(", "(uint64_t)(")
		want, goWant := "("+craw+")", "("+raw+")"
		if row.width == "W" {
			want, goWant = "((old&~UINT64_C(0xffff))|(("+craw+")&0xffff))", "((old&^uint64(0xffff))|(("+raw+")&0xffff))"
		} else if row.width == "L" {
			want, goWant = "(("+craw+")&UINT64_C(0xffffffff))", "(("+raw+")&uint64(0xffffffff))"
		}
		fmt.Fprintf(&checks, "if(%s(%s)!=%s) {fprintf(stderr,\"span%d mismatch\\n\");return 1;} count++;\n", fn, row.call, want, index)
		fmt.Fprintf(&goChecks, "if got,want:=%s(%s),%s;got!=want {t.Fatalf(\"span%d got=%%x want=%%x\",got,want)};count++\n", fn, row.goCall, goWant, index)
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	ir := x86NarrowOracleIR(t, assembly.String(), declarations.String(), execution.triple)
	if x86CMOVFPHasNumericConversion(ir) {
		t.Fatal("partial/cross-slot bits numerically converted")
	}
	reference := fmt.Sprintf(x86CMOVFPSpanC, prototypes.String(), checks.String())
	for _, pipeline := range []struct{ name, backend, ir string }{
		{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir}, {"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			output := execution.compileAndRunLLVM(t, "cmov-fp-spans", pipeline.ir, reference, pipeline.backend)
			if string(output) != "cmov FP partial/cross-slot whole-byte outcomes 384 failures 0\n" {
				t.Fatal("independent exact FP bytes", string(output))
			}
			t.Log(strings.TrimSpace(string(output)))
		})
	}
	x86WordMultiplyRunOriginalGo(t, execution, declarations.String(), assembly.String(), fmt.Sprintf(x86CMOVFPSpanGo, goChecks.String()))
}

const x86CMOVFPSpanC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
%s
int main(void) {
 const uint32_t bits[]={0,0x80000000,0x7fc00001,0x7f800001,0xffc12345,0x7f800000,0xffffffff,1};
 const uint64_t wide[]={0,UINT64_C(0x8000000000000000),UINT64_C(0x7ff8000000000001),UINT64_C(0x7ff0000000000001),UINT64_C(0xfff8123456789abc),UINT64_C(0x7ff0000000000000),UINT64_MAX,1};
 unsigned count=0;
 for(unsigned x=0;x<8;x++) for(unsigned y=0;y<8;y++) {
  uint32_t a=bits[x],b=bits[y];uint64_t q=wide[x],old=UINT64_C(0x87654321fedcba98)^((uint64_t)y<<40);
  float f,g;double d;memcpy(&f,&a,4);memcpy(&g,&b,4);memcpy(&d,&q,8);
  %s
 }
 printf("cmov FP partial/cross-slot whole-byte outcomes %%u failures 0\n",count);return 0;
}
`

const x86CMOVFPSpanGo = `package oracle
import("math";"testing")
func TestOriginal(t *testing.T) {
 bits:=[]uint32{0,0x80000000,0x7fc00001,0x7f800001,0xffc12345,0x7f800000,0xffffffff,1}
 wide:=[]uint64{0,0x8000000000000000,0x7ff8000000000001,0x7ff0000000000001,0xfff8123456789abc,0x7ff0000000000000,0xffffffffffffffff,1}
 count:=0
 for x,a:=range bits {for y,b:=range bits {q:=wide[x];old:=uint64(0x87654321fedcba98)^(uint64(y)<<40)
 %s
 }}
 if count!=384 {t.Fatal(count)};t.Logf("actual Go partial/cross-slot outcomes %%d failures 0",count)
}
`
