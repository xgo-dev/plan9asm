package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

func TestX86X87CompareNamedHostSoftwareValues(t *testing.T) {
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM22 llc and clang are required")
	}
	catalog, err := goasmrules.LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	rows, err := x86X87CompareNamedRows(catalog, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	var cases []x86OfficialPackedCase
	for _, row := range rows {
		for _, witness := range row.Witnesses {
			cases = append(cases, x86OfficialPackedCase{row: row.ID, witness: witness})
		}
	}
	if len(cases) != 38 {
		t.Fatal("incomplete legal named compare counterpart inventory", len(cases))
	}

	var main strings.Builder
	main.WriteString(`#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
typedef double (*compare_fn)(uint64_t, float, double, int16_t, int32_t, double);
`)
	for index := range cases {
		fmt.Fprintf(&main, "extern double X87Compare%d(uint64_t,float,double,int16_t,int32_t,double);\n", index)
		fmt.Fprintf(&main, "extern double X87Top%d(uint64_t,float,double,int16_t,int32_t,double);\n", index)
	}
	main.WriteString("struct entry {compare_fn flags, top; int memory, direct, pop;};\nstatic const struct entry entries[]={\n")
	for index, fixture := range cases {
		op := strings.Fields(fixture.witness.Instruction)[0]
		memory := 0
		if strings.Contains(fixture.witness.Instruction, "(AX)") {
			switch op {
			case "FCOMF", "FCOMFP":
				memory = 1
			case "FCOMW", "FCOMWP":
				memory = 2
			case "FCOML", "FCOMLP":
				memory = 3
			}
		}
		direct, pop := 0, 0
		switch op {
		case "FCOMI", "FCOMIP", "FUCOMI", "FUCOMIP":
			direct = 1
		}
		switch op {
		case "FCOMDPP", "FUCOMPP":
			pop = 2
		case "FCOMDP", "FCOMFP", "FCOMLP", "FCOMWP", "FCOMIP", "FUCOMIP", "FUCOMP":
			pop = 1
		}
		fmt.Fprintf(&main, "{X87Compare%d,X87Top%d,%d,%d,%d},\n", index, index, memory, direct, pop)
	}
	main.WriteString(`};
static const uint64_t values[]={
 UINT64_C(0xc025000000000000), UINT64_C(0x8000000000000000), 0,
 UINT64_C(0x3ff0000000000000), UINT64_C(0x4010000000000000),
 UINT64_C(0x7ff0000000000000), UINT64_C(0xfff0000000000000),
 UINT64_C(0x7ff8000000000042), 1
};
int main(void) {
 unsigned checks=0;
 for(unsigned k=0;k<sizeof(entries)/sizeof(entries[0]);k++) {
  for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++) {
   for(unsigned j=0;j<sizeof(values)/sizeof(values[0]);j++) {
    volatile uint64_t left_bits=values[i], right_bits=values[j];
    double left,right;
    uint64_t a=left_bits,b=right_bits;
    memcpy(&left,&a,8); memcpy(&right,&b,8);
    float f=(float)right;
    int16_t w=(i&1)?-7:2;
    int32_t l=(j&1)?-17:4;
    double rhs=right;
    if(entries[k].memory==1) rhs=(double)f;
    if(entries[k].memory==2) rhs=w;
    if(entries[k].memory==3) rhs=l;
    int unordered=isnan(left)||isnan(rhs);
    int less=unordered||left<rhs, equal=unordered||left==rhs;
    uint64_t expected;
    if(entries[k].direct) {
     expected=(uint64_t)equal|((uint64_t)less<<8)|((uint64_t)unordered<<16);
    } else {
     expected=UINT64_C(0x0000000101010000);
     expected|=(uint64_t)less<<8|(uint64_t)unordered<<10|(uint64_t)equal<<14;
    }
    double result=entries[k].flags(0,f,right,w,l,left);
    uint64_t actual;memcpy(&actual,&result,8);
    if(actual!=expected) {
     fprintf(stderr,"row=%u input=%u,%u flags=%llx expected=%llx\n",k,i,j,(unsigned long long)actual,(unsigned long long)expected);
     return 1;
    }
    checks++;
    result=entries[k].top(0,f,right,w,l,left);
    memcpy(&actual,&result,8);
    expected=entries[k].pop?b:a;
    if(entries[k].pop==2) expected=UINT64_C(0x3ff0000000000000);
    if(actual!=expected) {
     fprintf(stderr,"row=%u input=%u,%u remaining-top=%llx expected=%llx\n",k,i,j,(unsigned long long)actual,(unsigned long long)expected);
     return 2;
    }
    checks++;
   }
  }
 }
 if(checks!=38*9*9*2) return 3;
 printf("38 named counterparts: %u independent flag/status and remaining-top checks\n",checks);
 return 0;
}
`)
	source, declaration := x86X87CompareNamedAssembly(append([]x86OfficialPackedCase(nil), cases...), "amd64", false)
	topSource, topDeclaration := x86X87CompareNamedAssembly(append([]x86OfficialPackedCase(nil), cases...), "amd64", true)
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := x86X87InitializedWordAPI(t, source+topSource, declaration+topDeclaration, "amd64", triple, "Go", X87Software)
	if err != nil || ir == "" {
		t.Fatal("complete named software counterparts did not translate", err)
	}
	for _, optimized := range []bool{false, true} {
		input := ir
		if optimized {
			input = x86DwordProductIROptimize(t, ir)
		}
		for _, backend := range []int{0, 2} {
			t.Run(fmt.Sprintf("IR-O2-%t/backend%d", optimized, backend), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "x87-named-compare", triple, input, main.String(), nil, backend)
			})
		}
	}
	t.Log("portable logical software execution, not original x87 hardware, FP80, exceptions or a physical entry contract")
}
