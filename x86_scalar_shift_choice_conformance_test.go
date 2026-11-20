package plan9asm

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func x86ShiftChoiceOriginalConformance(t *testing.T) string {
	t.Helper()
	source, err := os.ReadFile("testdata/conformance/amd64/conformance_amd64.s")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(source), "TEXT ·scalarShiftRotateSemantics(SB)")
	if start < 0 {
		t.Fatal("original initialized conformance source disappeared")
	}
	body := string(source[start:])
	if next := strings.Index(body, "\nTEXT "); next >= 0 {
		body = body[:next]
	}
	if strings.Count(body, "SHLW CL, AX, DX") != 1 || strings.Count(body, "SHRW CX, AX, DX") != 1 {
		t.Fatal("original variable W double shifts were rewritten or removed")
	}
	return body
}

const x86ShiftChoiceConformanceDeclaration = "func scalarShiftRotateSemantics(out *[14]uint64,value,count uint64)\n"

func TestX86ScalarShiftArchitecturalChoiceOriginalNumericalObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required for unchanged numerical/FLAGS/MXCSR source")
	}
	for _, raw := range []bool{false, true} {
		declaration, source, _, _ := x86ScalarShiftNumericalSource(t, raw)
		kind := "named"
		if raw {
			kind = "raw"
		}
		for _, triple := range x86AddressMemoryTargets("amd64") {
			t.Run(kind+"/"+triple, func(t *testing.T) {
				x86LEAActualTargetGoObject(t, "amd64", triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", triple, api)
						if err != nil || ir == "" {
							t.Error("unchanged original numerical source lost initialized count/data/FLAGS observations", err)
							return
						}
						for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
							compileLLVMToObject(t, llc, triple, "original-numerical-choice.ll", "original-numerical-choice.o", body)
						}
					})
				}
			})
		}
	}
}

func TestX86ScalarShiftArchitecturalChoiceOriginalConformanceObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required for original initialized scalar conformance")
	}
	source := x86ShiftChoiceOriginalConformance(t)
	for _, triple := range x86AddressMemoryTargets("amd64") {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, "#include \"textflag.h\"\n"+source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, x86ShiftChoiceConformanceDeclaration, "amd64", triple, api)
					if err != nil || ir == "" {
						t.Error("original fully initialized scalar program cannot observe defined/choice outcomes", err)
						return
					}
					for _, body := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						compileLLVMToObject(t, llc, triple, "original-scalar-choice.ll", "original-scalar-choice.o", body)
					}
				})
			}
		})
	}
}

// The original source is unchanged. This independent companion extends its
// original legal-count vectors to all 256 counts without assigning a numerical
// expectation to undefined low16 results. Untouched high bytes and every other
// defined result remain mandatory, including count16's exact source value.
const x86ShiftChoiceConformanceC = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
extern void scalarShiftRotateSemantics(uint64_t*,uint64_t,uint64_t);
static uint64_t lane(uint64_t value,unsigned bits,unsigned count,unsigned kind) {
    uint64_t mask=bits==64?UINT64_MAX:(UINT64_C(1)<<bits)-1;
    uint64_t sign=UINT64_C(1)<<(bits-1);
    value&=mask;
    if(kind<2) count%=bits;
    for(unsigned i=0;i<count;i++) {
        if(kind==0) value=((value<<1)|(value>>(bits-1)))&mask;
        else if(kind==1) value=(value>>1)|((value&1)<<(bits-1));
        else if(kind==2) value>>=1;
        else if(kind==3) value=(value>>1)|(value&sign);
        else value=(value<<1)&mask;
    }
    return value;
}
static uint64_t replace(uint64_t old,uint64_t value,unsigned bits) {
    uint64_t mask=(UINT64_C(1)<<bits)-1;
    return (old&~mask)|(value&mask);
}
static uint16_t double_word(uint16_t old,uint16_t source,unsigned count,int left) {
    uint16_t value=old;
    for(unsigned i=0;i<count;i++) {
        if(left) value=(uint16_t)((value<<1)|((source>>(15-i))&1));
        else value=(uint16_t)((value>>1)|(((source>>i)&1)<<15));
    }
    return value;
}
int main(void) {
    const uint64_t values[]={0,1,UINT64_MAX,UINT64_C(0x8123456789abcdef),
        UINT64_C(0x7fffffffffffffff),UINT64_C(0x8000000080000000),UINT64_C(0x1122334455667788)};
    const uint64_t old=UINT64_C(0xfedcba9876543210);
    unsigned observations=0;
    for(unsigned sample=0;sample<7;sample++) for(unsigned count=0;count<256;count++) {
        uint64_t value=values[sample],packet[18],want[18];
        for(unsigned i=0;i<18;i++) packet[i]=UINT64_C(0xa5c391e7b6d8024f)^(UINT64_C(0x1020304050607)*i);
        memcpy(want,packet,sizeof(want));
        unsigned n=count&31;
        uint64_t *out=want+2;
        out[0]=replace(value,lane(value,8,n,0),8);
        out[1]=replace(value,lane(value,8,n,1),8);
        out[2]=replace(value,lane(value,8,n,3),8);
        out[3]=replace(value,lane(value,8,n,2),8);
        out[4]=replace(value,lane(value,16,n,0),16);
        out[5]=replace(value,lane(value,16,n,3),16);
        out[6]=lane(value,32,n,4);
        out[7]=lane(value,64,count&63,1);
        out[8]=out[3];
        out[9]=out[4];
        out[10]=old;
        out[11]=old;
        if(n<=16) {
            out[10]=replace(old,double_word((uint16_t)old,(uint16_t)value,n,1),16);
            out[11]=replace(old,double_word((uint16_t)old,(uint16_t)value,n,0),16);
        }
        out[12]=replace(value,lane(value,8,3,4),8);
        out[13]=lane(value,32,3,3);
        scalarShiftRotateSemantics(packet+2,value,count);
        if(n>16) {
            for(unsigned i=10;i<12;i++) {
                out[i]=(out[i]&~UINT64_C(65535))|(packet[2+i]&65535);
            }
        }
        if(memcmp(packet,want,sizeof(packet))) {
            fprintf(stderr,"original scalar choice sample=%u count=%u\n",sample,count);
            return 1;
        }
        observations++;
    }
    if(observations!=1792) return 2;
    puts("ORIGINAL_SCALAR_DEFINED_AND_CHOICE_1792_VALUES_CANARIES_PASS");
    return 0;
}
`

func TestX86ScalarShiftArchitecturalChoiceOriginalConformancePortableValues(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required for full-count original scalar source")
	}
	source := x86ShiftChoiceOriginalConformance(t)
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", "#include \"textflag.h\"\n"+source)
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, x86ShiftChoiceConformanceDeclaration, "amd64", triple, api)
			if err != nil || ir == "" {
				t.Fatal("actual initialized original rejected before all-count finite-value execution", err)
			}
			for _, pipeline := range []struct {
				input string
				level int
			}{{ir, 0}, {ir, 2}, {x86DwordProductIROptimize(t, ir), 2}} {
				compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "original-scalar-outcomes", triple,
					pipeline.input, x86ShiftChoiceConformanceC, nil, pipeline.level)
			}
		})
	}
	t.Log("original scalar source, 7 values x 256 counts x 3 APIs x 3 optimization paths; exact defined outputs, count16, preserved upper bytes and full canaries; undefined low16 has no guessed CPU value")
}
