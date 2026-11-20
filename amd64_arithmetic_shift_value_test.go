package plan9asm

import (
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func x86ArithmeticShiftValueRows(arch string) []struct{ op, bank, mode string } {
	var rows []struct{ op, bank, mode string }
	for _, name := range x86ArithmeticShiftTestNames() {
		for _, bank := range []string{"X", "Y", "Z"} {
			if name[0] != 'V' && bank != "X" {
				continue
			}
			modes := []string{"plain"}
			if arch == "amd64" && name[0] == 'V' {
				modes = append(modes, "merge", "zero")
			}
			for _, mode := range modes {
				rows = append(rows, struct{ op, bank, mode string }{name, bank, mode})
			}
		}
	}
	return rows
}

func x86ArithmeticShiftValueProgram(arch string) (string, string, string, string) {
	return x86FixedBinaryValueRuntimeProgram(arch, false, "ArithmeticShift", x86ArithmeticShiftValueRows,
		func(op string) (int, int) {
			perLane := 0
			if strings.Contains(op, "RAV") {
				perLane = 1
			}
			return x86ArithmeticShiftTestBits(op), perLane
		})
}

func TestX86ArithmeticShiftPortableBaselineTargetIR(t *testing.T) {
	source, declarations, _, _ := x86ArithmeticShiftValueProgram("amd64")
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"} {
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", triple, api)
			if err != nil {
				t.Fatal(api, err)
			}
			if regexp.MustCompile(`"target-features"="[^"]*\+avx`).MatchString(ir) {
				t.Errorf("portable numerical oracle retains native ISA requirements: %s/%s", triple, api)
			}
		}
	}
}

func TestX86ArithmeticShiftInitializedFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	if len(x86ArithmeticShiftValueRows("amd64")) != 56 || len(x86ArithmeticShiftValueRows("386")) != 20 {
		t.Fatal("complete arithmetic opcode/width denominator changed")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations, _, _ := x86ArithmeticShiftValueProgram(target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, target.triple, ir, level)
				}
			}
		})
	}
}

// Portable LLVM numerical execution is not original AVX/AVX512 execution.
// Counts include each boundary and high unsigned bits; the reference builds
// individual output bits without signed C shifts or the production emitter.
func TestX86ArithmeticShiftPortableValuesAndCanaries(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc and clang required")
	}
	arch, cWord := "amd64", "uint64_t"
	if strconv.IntSize == 32 {
		arch, cWord = "386", "uint32_t"
	}
	source, declarations, prototypes, rows := x86ArithmeticShiftValueProgram(arch)
	driver := "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n" + prototypes +
		"typedef " + cWord + " shift_word;\n" + `
struct kernel {void (*fn)(uint8_t*,uint8_t*,uint8_t*,shift_word);unsigned width,bits,mode,legacy,per_lane;};
static const struct kernel kernels[]={
` + rows + `};
int main(void) {
    const uint64_t counts[]={0,1,7,8,15,16,31,32,63,64,127,255,256,UINT64_C(0x100000000),UINT64_MAX};
    const shift_word masks[]={0,1,(shift_word)0xa55a9c63f00fc33cULL,(shift_word)-1};
    for(unsigned k=0;k<sizeof(kernels)/sizeof(kernels[0]);k++) {
        const struct kernel *p=&kernels[k];
        for(unsigned sample=0;sample<33;sample++)for(unsigned c=0;c<sizeof(counts)/sizeof(counts[0]);c++)
                for(unsigned m=0;m<sizeof(masks)/sizeof(masks[0]);m++) {
            uint8_t a[67],b[67],a_before[67],b_before[67],out[67],want[64];
            memset(a,0xa7,sizeof(a));memset(b,0x91,sizeof(b));memset(out,0xc3,sizeof(out));
            for(unsigned i=0;i<64;i++)b[i+1]=(i*73+sample*29)^(sample>>1);
            unsigned count_bytes=p->per_lane?p->bits/8:8;
            for(unsigned lane=0;lane<64/count_bytes;lane++)for(unsigned byte=0;byte<count_bytes;byte++)
                a[1+lane*count_bytes+byte]=counts[(c+lane)%15]>>(byte*8);
            memcpy(a_before,a,67);memcpy(b_before,b,67);memcpy(want,b+1,64);
            if(!p->legacy)memset(want+p->width,0,64-p->width);
            for(unsigned lane=0;lane<p->width/(p->bits/8);lane++) {
                if(p->mode && !(masks[m]>>lane&1)) {
                    if(p->mode==2)memset(want+lane*(p->bits/8),0,p->bits/8);
                    continue;
                }
                unsigned at=p->per_lane?lane*count_bytes:0;
                uint64_t shift=0;
                for(unsigned byte=0;byte<count_bytes;byte++)shift|=(uint64_t)a[1+at+byte]<<(byte*8);
                if(shift>=p->bits)shift=p->bits-1;
                for(unsigned bit=0;bit<p->bits;bit++) {
                    unsigned from=bit+(unsigned)shift;
                    if(from>=p->bits)from=p->bits-1;
                    unsigned input=lane*p->bits+from,output=lane*p->bits+bit;
                    unsigned value=(b[1+input/8]>>(input%8))&1;
                    want[output/8]=(want[output/8]&~(1u<<(output%8)))|(value<<(output%8));
                }
            }
            p->fn(a+1,b+1,out+1,masks[m]);
            if(memcmp(out+1,want,64)||out[65]!=1||out[0]!=0xc3||out[66]!=0xc3||
                    memcmp(a,a_before,67)||memcmp(b,b_before,67)) {
                fprintf(stderr,"arithmetic shift row=%u sample=%u count=%u width=%u bits=%u\n",k,sample,c,p->width,p->bits);
                return 1;
            }
        }
    }
    return 0;
}
`
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
			if err != nil {
				t.Fatal(api, err)
			}
			if regexp.MustCompile(`"target-features"="[^"]*\+avx`).MatchString(ir) {
				t.Fatal("portable arithmetic oracle requires native AVX/AVX512 hardware")
			}
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				for _, level := range []int{0, 2} {
					compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "arithmetic-shift-values", triple, text, driver, nil, level)
				}
			}
		})
	}
	t.Log("complete opcode/width kernels and Go-valid merge/zero masks; full 64-byte aliases, CF, input/output canaries and unsigned saturating counts; portable LLVM only")
}
