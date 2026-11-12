package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86TernaryAllTruthTablesAndForms(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, cases strings.Builder
	sigs := map[string]FuncSig{}
	count := 0
	add := func(op, bank string, width, bits, immediate, maskMode, memory int, aliases [3]int) {
		name := fmt.Sprint("ternaryRuntime", count)
		count++
		suffix, mask := "", ""
		if memory == 2 {
			suffix = ".BCST"
		}
		if maskMode > 0 {
			mask = ",K3"
		}
		if maskMode == 2 {
			suffix += ".Z"
		}
		first := fmt.Sprintf("%s%d", bank, aliases[2])
		if memory > 0 {
			first = "(SI)"
		}
		fmt.Fprintf(&source, `TEXT %s(SB),4,$0-48
MOVQ out+0(FP),AX
MOVQ a+8(FP),BX
MOVQ b+16(FP),CX
MOVQ c+24(FP),SI
MOVQ k+32(FP),DX
VMOVDQU64 (SI),Z0
VMOVDQU64 (CX),Z1
VMOVDQU64 (BX),Z2
KMOVQ DX,K3
STC
%s%s $%d,%s,%s%d%s,%s%d
VMOVDQU64 Z2,(AX)
SETCS 64(AX)
RET
`, name, op, suffix, immediate, first, bank, aliases[1], mask, bank, aliases[0])
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1}, {Offset: 24, Type: Ptr, Index: 3, Field: -1},
				{Offset: 32, Type: I64, Index: 4, Field: -1},
			}}}
		fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", name)
		fmt.Fprintf(&cases, "{%s,%d,%d,%d,%d,%d,{%d,%d,%d}},\n", name, width, bits/8, immediate, maskMode, memory, aliases[0], aliases[1], aliases[2])
	}
	for _, spec := range []struct {
		op   string
		bits int
	}{{"VPTERNLOGD", 32}, {"VPTERNLOGQ", 64}} {
		for width, bank := range map[int]string{16: "X", 32: "Y", 64: "Z"} {
			for immediate := 0; immediate < 256; immediate++ {
				add(spec.op, bank, width, spec.bits, immediate, 0, 0, [3]int{2, 1, 0})
			}
			for _, aliases := range [][3]int{{2, 1, 0}, {2, 2, 0}, {2, 1, 2}, {2, 1, 1}, {2, 2, 2}} {
				for mask := 0; mask <= 2; mask++ {
					for memory := 0; memory <= 2; memory++ {
						for _, immediate := range []int{0, 255, 150, 202} {
							add(spec.op, bank, width, spec.bits, immediate, mask, memory, aliases)
						}
					}
				}
			}
		}
	}
	goAssemblerOracleOutput(t, "amd64", source.String(), "", true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	const helper = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>
struct test {
    void (*run)(uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,uint64_t);
    unsigned width,lane,immediate,mask,memory,aliases[3];
};
`
	driver := helper + declarations.String() + "static const struct test cases[]={\n" + cases.String() + `};
int main(void) {
    const uint64_t masks[]={0,UINT64_MAX,1,0xaaaa,0x5555,UINT64_C(1)<<63};
    uint32_t saved=_mm_getcsr();
    for(unsigned test=0;test<sizeof(cases)/sizeof(cases[0]);test++)
    for(unsigned sample=0;sample<12;sample++) {
        const struct test *c=cases+test;
        uint8_t inputs[3][66],before[3][66],output[67];
        for(unsigned r=0;r<3;r++) for(unsigned i=0;i<66;i++)
            inputs[r][i]=(uint8_t)(i*(r*23+13)+sample*(r*19+51));
        memcpy(before,inputs,sizeof(inputs));
        memset(output,0xa7,sizeof(output));
        uint64_t mask=masks[sample%6];
        uint32_t csr=0x1f80|(sample&3)<<13|(sample&63);
        _mm_setcsr(csr);
        c->run(output+1,inputs[2]+1,inputs[1]+1,inputs[0]+1,mask);
        uint32_t after=_mm_getcsr();
        _mm_setcsr(saved);
        if(after!=csr || output[0]!=0xa7 || output[66]!=0xa7 || output[65]!=1 ||
           memcmp(inputs,before,sizeof(inputs))) return 1;
        for(unsigned i=0;i<64;i++) {
            unsigned want=0;
            if(i<c->width) {
                if(c->mask && !(mask>>(i/c->lane)&1)) {
                    want=c->mask==2?0:inputs[c->aliases[0]][i+1];
                } else {
                    unsigned a=inputs[c->aliases[0]][i+1];
                    unsigned b=inputs[c->aliases[1]][i+1];
                    unsigned third=c->memory?inputs[0][1+(c->memory==2?i%c->lane:i)]:inputs[c->aliases[2]][i+1];
                    for(unsigned bit=0;bit<8;bit++) {
                        unsigned index=((a>>bit&1)<<2)|((b>>bit&1)<<1)|(third>>bit&1);
                        want|=(c->immediate>>index&1)<<bit;
                    }
                }
            }
            if(output[i+1]!=want) {
                fprintf(stderr,"case=%u sample=%u byte=%u got=%x want=%x\n",test,sample,i,output[i+1],want);
                return 2;
            }
        }
    }
    return 0;
}
`
	for _, optimize := range []bool{false, true} {
		text := ir
		if optimize {
			text = x86MulDivRoundOptimize(t, text)
		}
		t.Run(fmt.Sprint("IR_O2=", optimize), func(t *testing.T) {
			compileAndRunRuntimeTestForTarget(t, llc, clang, "ternary-complete", triple, text, driver, prefix)
		})
	}
	t.Logf("%d kernels x12 values/masks, all64 alias bytes, carry/MXCSR/input canaries, all256 truth tables; portable LLVM, not original native AVX512 execution", count)
}
