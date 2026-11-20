package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Polynomial long multiplication is independent of the production selectors,
// descriptors and LLVM intrinsic. Both input qwords and both output qwords are
// observed, including the otherwise ignored immediate bits.
const x86CLMULIndependentC = `#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>
static void product(uint64_t a,uint64_t b,uint64_t *out) {
    uint64_t lo=0,hi=0;
    for(unsigned bit=0;bit<64;bit++) {
        if((b>>bit)&1) {
            lo^=a<<bit;
            if(bit) hi^=a>>(64-bit);
        }
    }
    out[0]=lo; out[1]=hi;
}
static const uint64_t edges[]={0,1,UINT64_MAX,UINT64_C(0x8000000000000000),
    UINT64_C(0x123456789abcdef0),UINT64_C(0xfedcba9876543210),
    UINT64_C(0x1111111111111111),UINT64_C(0xaaaaaaaaaaaaaaaa)};
struct Buffer {_Alignas(64) uint8_t before[64],value[80],after[64];};
typedef void (*Program)(uint8_t*,const uint8_t*,const uint8_t*);
static int check(Program program,const char *name,unsigned width,int legacy,int selector,int alias) {
    for(unsigned sample=0;sample<73;sample++) {
        struct Buffer a,b,out;
        memset(&a,0xa7,sizeof(a)); memset(&b,0xb9,sizeof(b)); memset(&out,0xc3,sizeof(out));
        for(unsigned word=0;word<8;word++) {
            uint64_t av=edges[(sample+word)%8],bv=edges[(sample/8+word*3)%8];
            if(sample>=64) {av^=(uint64_t)sample*713781;bv^=(uint64_t)sample*391531;}
            memcpy(a.value+word*8,&av,8); memcpy(b.value+word*8,&bv,8);
        }
        struct Buffer originalA=a,originalB=b,want=out;
        for(unsigned lane=0;lane<width;lane+=16) {
            uint64_t av,bv,pair[2];
            memcpy(&av,(alias==3?b.value:a.value)+lane+((selector>>4)&1)*8,8);
            memcpy(&bv,b.value+lane+(selector&1)*8,8);
            product(bv,av,pair); memcpy(want.value+lane,pair,16);
        }
        memcpy(want.value+width,legacy?b.value+width:(uint8_t[64]){0},64-width);
        want.value[64]=1; want.value[65]=0;
        unsigned saved=_mm_getcsr(),profile=0x1f80|((sample%4)<<13)|(sample%64);
        memcpy(want.value+68,&profile,4); _mm_setcsr(profile);
        program(out.value,a.value,b.value); unsigned after=_mm_getcsr(); _mm_setcsr(saved);
        if(after!=profile||memcmp(&a,&originalA,sizeof(a))||memcmp(&b,&originalB,sizeof(b))||memcmp(&out,&want,sizeof(out))) {
            for(unsigned i=0;i<sizeof(out);i++) if(((uint8_t*)&out)[i]!=((uint8_t*)&want)[i])
                fprintf(stderr,"%s sample=%u byte=%u got=%x want=%x\n",name,sample,i,((uint8_t*)&out)[i],((uint8_t*)&want)[i]);
            return 1;
        }
    }
    return 0;
}
`

func TestCrossLinuxRuntimeMatrixX86CLMULCompleteBytes(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	var source, declarations, checks strings.Builder
	sigs := map[string]FuncSig{}
	count := 0
	for _, kind := range []string{"legacy", "X", "Y", "Z"} {
		legacy := kind == "legacy"
		bank, width := kind, 16
		if legacy {
			bank = "X"
		} else if bank == "Y" {
			width = 32
		} else if bank == "Z" {
			width = 64
		}
		for _, selector := range []int{0, 1, 16, 17, 238, 255} {
			for _, alias := range []int{0, 1, 2, 3, 4} {
				if legacy && (alias == 1 || alias == 2) {
					continue
				}
				name := fmt.Sprint("clmulbytes", count)
				count++
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-24\nMOVQ out+0(FP),AX\nMOVQ a+8(FP),BX\nMOVQ b+16(FP),CX\n", name)
				source.WriteString("VMOVUPS (BX),Z0\nVMOVUPS (CX),Z1\nVMOVUPS (CX),Z2\nCMPQ AX,AX\nSTC\n")
				first, second, destination := bank+"0", bank+"1", bank+"2"
				if alias == 1 {
					destination = first
				} else if alias == 2 {
					destination = second
				} else if alias == 3 {
					first = second
				} else if alias == 4 {
					first = "(BX)"
				}
				if legacy {
					destination = "X1"
					fmt.Fprintf(&source, "PCLMULQDQ $%d,%s,%s\n", selector, first, destination)
				} else {
					fmt.Fprintf(&source, "VPCLMULQDQ $%d,%s,%s,%s\n", selector, first, second, destination)
				}
				fmt.Fprintf(&source, "VMOVUPS Z%s,(AX)\nSETCS 64(AX)\nSETNE 65(AX)\nSTMXCSR 68(AX)\nRET\n", destination[1:])
				sigs[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
					Frame: FrameLayout{Params: []FrameSlot{
						{Offset: 0, Type: Ptr, Index: 0, Field: -1},
						{Offset: 8, Type: Ptr, Index: 1, Field: -1},
						{Offset: 16, Type: Ptr, Index: 2, Field: -1},
					}}}
				fmt.Fprintf(&declarations, "extern void %s(uint8_t*,const uint8_t*,const uint8_t*);\n", name)
				fmt.Fprintf(&checks, "if(check(%s,%q,%d,%d,%d,%d)) return 1;\n", name, kind+fmt.Sprint(selector, "/", alias), width, x86FloatAddSubBoolInt(legacy), selector, alias)
			}
		}
	}
	if count != 108 {
		t.Fatal("complete independent runtime denominator changed", count)
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
	oracle := x86CLMULIndependentC + declarations.String() + "int main(void) {\n" + checks.String() + "return 0;\n}\n"
	for _, optimized := range []bool{false, true} {
		t.Run(fmt.Sprintf("IR_O2=%t", optimized), func(t *testing.T) {
			text := ir
			if optimized {
				text = x86MulDivRoundOptimize(t, text)
			}
			compileAndRunRuntimeTestForTarget(t, llc, clang, "clmul-complete-bytes", triple, text, oracle, prefix)
		})
	}
	t.Log("108 kernels x 73 inputs, full aliases/flags/MXCSR/canaries; portable LLVM wide semantics, not native AVX512 execution")
}

func TestCrossLinuxRuntimeMatrixX86CLMULOriginalGo(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var functions, checks strings.Builder
	count := 0
	for _, immediate := range []int{0, 1, 16, 17, 238, 255} {
		for _, alias := range []int{0, 3, 4} {
			source := "X0"
			if alias == 3 {
				source = "X1"
			} else if alias == 4 {
				source = "(AX)"
			}
			row := fmt.Sprintf("PCLMULQDQ $%d,%s,X1", immediate, source)
			code := x86OrderingHintGoBytes(t, "amd64", "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			if len(code) != 7 || code[len(code)-1] != 0xc3 {
				t.Fatal("actual Go object differs from one legacy instruction plus RET", row, code)
			}
			var bytes []string
			for _, value := range code[:len(code)-1] {
				bytes = append(bytes, fmt.Sprintf("0x%02x", value))
			}
			name := fmt.Sprint("original", count)
			count++
			assembly := "movdqu (%%rax), %%xmm0\n\tmovdqu (%%rsi), %%xmm1\n\tcmpq %%rax, %%rax\n\tstc\n\t.byte " + strings.Join(bytes, ",") +
				"\n\tmovdqu %%xmm1, (%%rdi)\n\tsetc 64(%%rdi)\n\tsetne 65(%%rdi)\n\tstmxcsr 68(%%rdi)"
			fmt.Fprintf(&functions, `static void %s(uint8_t *out,const uint8_t *a,const uint8_t *b) {
    memcpy(out+16,b+16,48);
    __asm__ volatile(%q::"a"(a),"S"(b),"D"(out):"xmm0","xmm1","cc","memory");
}
`, name, assembly)
			fmt.Fprintf(&checks, "if(check(%s,%q,16,1,%d,%d)) return 1;\n", name, row, immediate, alias)
		}
	}
	oracle := x86CLMULIndependentC + functions.String() + "int main(void) {\n" + checks.String() + "return 0;\n}\n"
	execution.compileAndRunLLVM(t, "clmul-original-go", "define void @unused() { ret void }\n", oracle, "-O2")
	t.Log("18 actual original Go legacy encodings x 73 numerical/FLAGS/MXCSR samples; native X results, not original wide-register execution")
}
