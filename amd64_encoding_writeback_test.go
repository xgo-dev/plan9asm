package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86EncodingWritebackCase struct {
	instruction        string
	width, scalarBytes int
	legacy             bool
	portable, avx2     bool
	gather             int // 1: VEX vector mask; 2: EVEX predicate mask.
}

// One observation per writer path, plus independent legacy and wider controls.
// Arithmetic and fault oracles stay with each family; this matrix observes
// physical upper bytes, scalar passthrough, aliases and unrelated state only.
var x86EncodingWritebackCases = []x86EncodingWritebackCase{
	{"VRANGEPS $0,X1,X2,X@", 16, 0, false, true, false, 0},
	{"VRANGESS $0,X1,X2,X@", 16, 4, false, true, false, 0},
	{"VGETMANTPS $0,X1,X@", 16, 0, false, false, false, 0},
	{"VGETMANTSD $0,X1,X2,X@", 16, 8, false, false, false, 0},
	{"VADDSUBPS X1,X2,X@", 16, 0, false, true, true, 0},
	{"ADDSUBPS X1,X@", 16, 0, true, true, true, 0},
	{"VADDPS X1,X2,X@", 16, 0, false, true, true, 0},
	{"VADDSD X1,X2,X@", 16, 8, false, true, true, 0},
	{"VADDPS X1,X2,K1,X@", 16, 0, false, true, false, 0},
	{"VADDPS.Z X1,X2,K1,X@", 16, 0, false, true, false, 0},
	{"VADDSD X1,X2,K1,X@", 16, 8, false, true, false, 0},
	{"VADDSD.Z X1,X2,K1,X@", 16, 8, false, true, false, 0},
	{"VGATHERDPS X2,(AX)(X1*4),X@", 16, 0, false, true, true, 1},
	{"VGATHERDPS (AX)(X1*4),K1,X@", 16, 0, false, true, false, 2},
	{"VPMOVDB Z1,X@", 16, 0, false, true, false, 0},
	{"VPMOVDW Z1,Y@", 32, 0, false, true, false, 0},
	{"VGETEXPPS X1,X@", 16, 0, false, false, false, 0},
	{"VGETEXPSS X1,X2,X@", 16, 4, false, false, false, 0},
	{"VRCP14PS X1,X@", 16, 0, false, false, false, 0},
	{"VRCP14SS X1,X2,X@", 16, 4, false, false, false, 0},
	{"VRCPPS X1,X@", 16, 0, false, false, true, 0},
	{"RCPPS X1,X@", 16, 0, true, false, true, 0},
	{"VRCP28SS X1,X2,X@", 16, 4, false, false, false, 0},
	{"VEXP2PS Z1,Z@", 64, 0, false, false, false, 0},
	{"VRNDSCALEPS $0,X1,X@", 16, 0, false, false, false, 0},
	{"VREDUCESD $0,X1,X2,X@", 16, 8, false, false, false, 0},
	{"VROUNDPS $0,X1,X@", 16, 0, false, true, true, 0},
	{"ROUNDPS $0,X1,X@", 16, 0, true, true, true, 0},
	{"VROUNDSS $0,X1,X2,X@", 16, 4, false, true, true, 0},
	{"ROUNDSS $0,X1,X@", 16, 4, true, true, true, 0},
	{"VSCALEFPS X1,X2,X@", 16, 0, false, false, false, 0},
	{"VSCALEFSS X1,X2,X@", 16, 4, false, false, false, 0},
	{"VFIXUPIMMPS $0,X1,X2,X@", 16, 0, false, false, false, 0},
	{"VFIXUPIMMSD $0,X1,X2,X@", 16, 8, false, false, false, 0},
	{"VSHUFI32X4 $0,Y1,Y2,Y@", 32, 0, false, true, false, 0},
	{"VPERMD Y1,Y2,Y@", 32, 0, false, true, true, 0},
	{"VRANGEPS $0,X1,X2,K1,X@", 16, 0, false, true, false, 0},
	{"VRANGEPS.Z $0,X1,X2,K1,X@", 16, 0, false, true, false, 0},
	{"VFIXUPIMMSD $0,X1,X2,K1,X@", 16, 8, false, false, false, 0},
	{"VFIXUPIMMSD.Z $0,X1,X2,K1,X@", 16, 8, false, false, false, 0},
}

func x86EncodingWritebackProgram(t *testing.T, mode string) (string, string, string) {
	t.Helper()
	physical, bank := 64, "Z"
	if mode == "avx2" {
		physical, bank = 32, "Y"
	}
	var source, declarations, prototypes, rows strings.Builder
	count := 0
	for _, row := range x86EncodingWritebackCases {
		if mode == "portable" && !row.portable || mode == "avx2" && !row.avx2 {
			continue
		}
		aliases := []int{0, 1}
		if row.gather != 0 {
			aliases = []int{0, 3} // A gather destination must not alias its VSIB index or mask.
		}
		for _, destination := range aliases {
			instruction := strings.ReplaceAll(row.instruction, "@", fmt.Sprint(destination))
			name := fmt.Sprint("Writer", count)
			fmt.Fprintf(&declarations, "func %s(out *[260]byte,state *[256]byte,p *[64]byte,mask uint64)\n", name)
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-32\nMOVQ out+0(FP),DI\nMOVQ state+8(FP),SI\nMOVQ p+16(FP),AX\n", name)
			for register := 0; register < 4; register++ {
				fmt.Fprintf(&source, "VMOVUPS %d(SI),%s%d\n", register*64, bank, register)
			}
			if strings.Contains(instruction, "K1") {
				source.WriteString("KMOVQ mask+24(FP),K1\n")
			}
			source.WriteString("MOVL $5,R8\nCMPL R8,$3\n")
			source.WriteString(instruction + "\n")
			for register := 0; register < 4; register++ {
				fmt.Fprintf(&source, "VMOVUPS %s%d,%d(DI)\n", bank, register, register*64)
			}
			source.WriteString("SETCS 256(DI)\nSETOS 257(DI)\nRET\n")
			fmt.Fprintf(&prototypes, "extern void InstructionFormat%d(uint8_t*,const uint8_t*,const uint8_t*,uint64_t);\n", count)
			fmt.Fprintf(&rows, "{InstructionFormat%d,%q,%d,%d,%d,%d,%t,%d},\n",
				count, instruction, physical, row.width, row.scalarBytes, destination, row.legacy, row.gather)
			count++
		}
	}
	if len(x86EncodingWritebackCases) != 40 || count == 0 {
		t.Fatal("encoding writer path inventory changed", len(x86EncodingWritebackCases), mode, count)
	}
	want := map[string]int{"all": 80, "portable": 44, "avx2": 24}[mode]
	if count != want {
		t.Fatal("execution counterpart lost its exact original row partition", mode, count, want)
	}
	t.Logf("%s: %d original functions; native-only/MXCSR/ER rows remain in the full 80-function object inventory", mode, count)
	driver := strings.NewReplacer("PROTOTYPES", prototypes.String(), "ROWS", rows.String()).Replace(x86EncodingWritebackDriver)
	return source.String(), declarations.String(), driver
}

func x86EncodingWritebackIR(t *testing.T, mode, triple string) (string, string) {
	t.Helper()
	source, declarations, driver := x86EncodingWritebackProgram(t, mode)
	x86LEAActualTargetGoObject(t, "amd64", "x86_64-unknown-linux-gnu", source)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "writer", "package writer\n"+declarations)
	resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "amd64", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The complete initialized instruction emitter is isolated from public
	// source-effect registration. Do not count this as public API acceptance.
	return x86ScalarFormatObjectUnit(t, file, sigs, "amd64", triple, 0), driver
}

func TestX86EncodingWritebackCompleteEmitterObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, _ := x86EncodingWritebackIR(t, "all", triple)
			for _, level := range []string{"-O0", "-O2"} {
				input := ir
				if level == "-O2" {
					input = x86MulDivRoundOptimize(t, ir)
				}
				x86PackedStringCompileObject(t, llc, triple, input, level)
			}
		})
	}
}

func x86EncodingWritebackRuntime(t *testing.T, execution x86FloatCompareExecution, mode string) {
	t.Helper()
	ir, driver := x86EncodingWritebackIR(t, mode, execution.triple)
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			input := ir
			if level == "-O2" {
				input = x86MulDivRoundOptimize(t, ir)
			}
			execution.compileAndRunLLVM(t, "encoding-writeback", input, driver, level)
		})
	}
}

const x86EncodingWritebackDriver = `
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
PROTOTYPES
struct row {
    void (*run)(uint8_t*,const uint8_t*,const uint8_t*,uint64_t);
    const char *name;
    unsigned physical,width,scalar,destination;
    bool legacy;
    unsigned gather;
};
static const struct row rows[]={ROWS};
int main(void) {
    const uint64_t masks[]={0,1,5,UINT64_MAX};
    unsigned failures=0;
    for(unsigned r=0;r<sizeof(rows)/sizeof(rows[0]);r++) {
        const struct row *row=&rows[r];
        for(unsigned sample=0;sample<4;sample++) {
            uint8_t state[256],before[256],output[262],memory[64];
            for(unsigned bank=0;bank<4;bank++) for(unsigned lane=0;lane<16;lane++) {
                uint32_t bits=UINT32_C(0x3fc00000)+bank*UINT32_C(0x100000)+lane*256+sample*65536;
                memcpy(state+bank*64+lane*4,&bits,4);
            }
            if(row->gather) memset(state+64,0,64);
            if(row->gather==1) memset(state+128,255,64);
            memcpy(before,state,256);
            memset(memory,0x37,64);
            memset(output,0xa7,sizeof(output));
            row->run(output+1,state,memory,masks[sample]);
            if(memcmp(state,before,256)||output[0]!=0xa7||output[259]!=0xa7||
               output[260]!=0xa7||output[261]!=0xa7||output[257]||output[258])return 1;
            for(unsigned byte=0;byte<64;byte++)if(memory[byte]!=0x37)return 1;
            for(unsigned byte=0;byte<256;byte++) {
                unsigned bank=byte/64,lane=byte%64;
                unsigned expected=before[byte];
                if(lane>=row->physical)expected=0xa7;
                else if(bank==row->destination) {
                    if(lane>=row->width)expected=row->legacy?before[byte]:0;
                    else if(row->scalar && lane>=row->scalar && lane<16)
                        expected=before[(row->legacy?row->destination:2)*64+lane];
                    else continue; /* Per-family oracles own the arithmetic result. */
                } else if(row->gather==1 && bank==2)expected=0;
                if(output[byte+1]!=expected) {
                    fprintf(stderr,"%s sample=%u bank=%u byte=%u got=%x want=%x\n",
                            row->name,sample,bank,lane,output[byte+1],expected);
                    failures++;
                    break;
                }
            }
        }
    }
    fprintf(stderr,"encoding writeback rows=%zu failed samples=%u\n",sizeof(rows)/sizeof(rows[0]),failures);
    return failures?1:0;
}
`
