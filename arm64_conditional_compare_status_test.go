package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

type arm64ConditionalTestCase struct {
	bits, condition, nzcv, left, right int
	signaling, raw, dead, complete     bool
}

func arm64ConditionalStatusCases() []arm64ConditionalTestCase {
	var cases []arm64ConditionalTestCase
	for _, bits := range []int{16, 32, 64} {
		for _, signaling := range []bool{false, true} {
			for _, dead := range []bool{false, true} {
				cases = append(cases, arm64ConditionalTestCase{bits, 1, 10, 0, 31, signaling, true, dead, true})
			}
			if bits != 16 {
				cases = append(cases, arm64ConditionalTestCase{bits, 1, 10, 0, 31, signaling, false, false, true})
			}
		}
	}
	for condition := 0; condition < 16; condition++ {
		cases = append(cases, arm64ConditionalTestCase{32, condition, condition, 31, 0, false, false, false, false})
	}
	for flags := 0; flags < 16; flags++ {
		cases = append(cases, arm64ConditionalTestCase{64, 1, flags, 0, 31, true, false, false, false})
	}
	for bank := 0; bank < 32; bank++ {
		cases = append(cases, arm64ConditionalTestCase{16, 1, 10, bank, bank, true, true, false, false})
	}
	return cases
}

func (row arm64ConditionalTestCase) instruction() string {
	if row.raw {
		return fmt.Sprintf("WORD $%#08x", arm64ConditionalTestWord(row.bits, row.condition, row.nzcv, row.left, row.right, row.signaling))
	}
	op := "FCCMP"
	if row.signaling {
		op += "E"
	}
	if row.bits == 32 {
		op += "S"
	} else {
		op += "D"
	}
	return fmt.Sprintf("%s %s,F%d,F%d,$%d", op, arm64ConditionalTestConditions[row.condition], row.right, row.left, row.nzcv)
}

func arm64ConditionalStatusSource(cases []arm64ConditionalTestCase) (string, string) {
	var source, declarations strings.Builder
	declarations.WriteString("package compare\n")
	for index, row := range cases {
		name := fmt.Sprintf("compareConditionalStatus%d", index)
		fmt.Fprintf(&declarations, "func %s(*[68]uint64,*[69]uint64)\n", name)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-16\nMOVD in+0(FP),R0\nMOVD out+8(FP),R1\n", name)
		for bank := 0; bank < 32; bank++ {
			fmt.Fprintf(&source, "VLD1.P 16(R0),[V%d.B16]\n", bank)
		}
		source.WriteString("MRS FPCR,R10\nMRS FPSR,R11\nMOVD (R0),R2\nMSR R2,FPCR\nMOVD 8(R0),R2\nMSR R2,FPSR\nMOVD 16(R0),R2\nMOVD 24(R0),R3\nCMP R3,R2\n")
		source.WriteString(row.instruction() + "\n")
		if row.dead {
			source.WriteString("CMP R0,R0\n")
		}
		source.WriteString("CSET MI,R2\nCSET EQ,R3\nCSET CS,R4\nCSET VS,R5\nLSL $3,R2,R2\nLSL $2,R3,R3\nLSL $1,R4,R4\nORR R3,R2,R2\nORR R4,R2,R2\nORR R5,R2,R2\nMRS FPSR,R3\nMRS FPCR,R4\n")
		for bank := 0; bank < 32; bank++ {
			fmt.Fprintf(&source, "VST1.P [V%d.B16],16(R1)\n", bank)
		}
		source.WriteString("MOVD R2,(R1)\nMOVD R3,8(R1)\nMOVD R4,16(R1)\nMSR R10,FPCR\nMSR R11,FPSR\nRET\n")
	}
	return source.String(), declarations.String()
}

// Integer condition reference independent of both lowerer and its condValue.
func arm64ConditionalTestTrue(condition int, flags uint64) bool {
	n, z, c, v := flags&8 != 0, flags&4 != 0, flags&2 != 0, flags&1 != 0
	base := [...]bool{z, c, n, v, c && !z, n == v, n == v && !z, true}[condition/2]
	if condition&1 != 0 && condition != 15 {
		return !base
	}
	return base
}

func arm64ConditionalStatusPrograms(cases []arm64ConditionalTestCase, declarations string) (string, string) {
	var original, driver strings.Builder
	original.WriteString(strings.Replace(declarations, "package compare", "package main\nimport \"fmt\"", 1))
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for index := range cases {
		fmt.Fprintf(&driver, "extern void compareConditionalStatus%d(uint64_t*,uint64_t*);\n", index)
	}
	original.WriteString("var functions=[]func(*[68]uint64,*[69]uint64){\n")
	driver.WriteString("static void (*functions[])(uint64_t*,uint64_t*)={\n")
	for index := range cases {
		fmt.Fprintf(&original, "compareConditionalStatus%d,\n", index)
		fmt.Fprintf(&driver, "compareConditionalStatus%d,\n", index)
	}
	original.WriteString("}\nvar forms=[]struct{bits,left,right,mode,condition,nzcv int; signaling,dead,complete bool}{\n")
	driver.WriteString("};\nstatic const struct{int bits,left,right,mode,condition,nzcv,signaling,dead,complete;} forms[]={\n")
	for _, row := range cases {
		mode, signaling, dead, complete := 0, 0, 0, 0
		if row.left == row.right {
			mode = 1
		}
		if row.signaling {
			signaling = 1
		}
		if row.dead {
			dead = 1
		}
		if row.complete {
			complete = 1
		}
		fmt.Fprintf(&original, "{%d,%d,%d,%d,%d,%d,%t,%t,%t},\n", row.bits, row.left, row.right, mode, row.condition, row.nzcv, row.signaling, row.dead, row.complete)
		fmt.Fprintf(&driver, "{%d,%d,%d,%d,%d,%d,%d,%d,%d},\n", row.bits, row.left, row.right, mode, row.condition, row.nzcv, signaling, dead, complete)
	}
	original.WriteString("}\nvar truth=[16][4]bool{\n")
	driver.WriteString("};\nstatic const int truth[16][4]={\n")
	for condition := 0; condition < 16; condition++ {
		original.WriteString("{")
		driver.WriteString("{")
		for _, flags := range []uint64{6, 8, 2, 3} {
			valid := arm64ConditionalTestTrue(condition, flags)
			fmt.Fprintf(&original, "%t,", valid)
			if valid {
				driver.WriteString("1,")
			} else {
				driver.WriteString("0,")
			}
		}
		original.WriteString("},\n")
		driver.WriteString("},\n")
	}
	original.WriteString("}\nvar samples=[]struct{bits,mode int; a,b,control,flags,quiet,signaling uint64; edge bool}{\n")
	driver.WriteString("};\nstatic const struct{int bits,mode;uint64_t a,b,control,flags,quiet,signaling;int edge;} samples[]={\n")
	for _, bits := range []int{16, 32, 64} {
		for mode := 0; mode < 2; mode++ {
			for first, left := range arm64CompareValues(bits) {
				for second, right := range arm64CompareValues(bits) {
					if mode == 1 && first != second {
						continue
					}
					for rounding := 0; rounding < 4; rounding++ {
						for controls := 0; controls < 4; controls++ {
							control := uint64(rounding)<<22 | uint64(controls&1)<<24 | uint64(controls>>1)<<25
							if bits == 16 && controls&1 != 0 {
								control |= 1 << 19
							}
							flags, quiet := arm64CompareExpected(bits, left, right, control, false)
							_, signaling := arm64CompareExpected(bits, left, right, control, true)
							edge := second == 0 || mode == 1
							fmt.Fprintf(&original, "{%d,%d,%#x,%#x,%#x,%d,%d,%d,%t},\n", bits, mode, left, right, control, flags, quiet, signaling, edge)
							edgeValue := 0
							if edge {
								edgeValue = 1
							}
							fmt.Fprintf(&driver, "{%d,%d,%#xULL,%#xULL,%#xULL,%d,%d,%d,%d},\n", bits, mode, left, right, control, flags, quiet, signaling, edgeValue)
						}
					}
				}
			}
		}
	}
	original.WriteString(`}
func main() {
    seeds:=[][2]uint64{{0,0},{0,1},{1,0},{0x8000000000000000,0x7fffffffffffffff}}
    count:=0
    for function,form:=range forms {
        for _,sample:=range samples {
            if sample.bits!=form.bits || sample.mode!=form.mode || !form.complete && !sample.edge {continue}
            for seed,values:=range seeds {
                for _,preset:=range []uint64{0,0x08000012} {
                    var input [68]uint64
                    for i:=0;i<64;i++ {input[i]=0x123456789abcdef0+uint64(i)*0x0102030405060708}
                    mask:=^uint64(0)
                    if form.bits<64 {mask=(uint64(1)<<form.bits)-1}
                    input[2*form.left]=input[2*form.left]&^mask|sample.a
                    if form.mode==0 {input[2*form.right]=input[2*form.right]&^mask|sample.b}
                    input[64],input[65],input[66],input[67]=sample.control,preset,values[0],values[1]
                    var output,want [69]uint64
                    copy(want[:64],input[:64])
                    want[64],want[65],want[66]=uint64(form.nzcv),preset,sample.control
                    if truth[form.condition][seed] {
                        want[64]=sample.flags
                        if form.signaling {want[65]|=sample.signaling} else {want[65]|=sample.quiet}
                    }
                    if form.dead {want[64]=6}
                    output[67],output[68]=0x123456789abcdef0,0xfedcba9876543210
                    want[67],want[68]=output[67],output[68]
                    functions[function](&input,&output)
                    if output!=want {panic(fmt.Sprintf("function %d seed %d sample %+v got %x want %x",function,seed,sample,output,want))}
                    count++
                }
            }
        }
    }
    fmt.Println("ARM64_COMPARE_ORIGINAL_PASS conditional state",count)
}
`)
	driver.WriteString(`};
int main(void) {
    const uint64_t seeds[4][2]={{0,0},{0,1},{1,0},{UINT64_C(0x8000000000000000),UINT64_C(0x7fffffffffffffff)}};
    unsigned count=0;
    for(unsigned function=0;function<sizeof(forms)/sizeof(forms[0]);function++) {
        for(unsigned index=0;index<sizeof(samples)/sizeof(samples[0]);index++) {
            if(samples[index].bits!=forms[function].bits || samples[index].mode!=forms[function].mode || (!forms[function].complete && !samples[index].edge)) continue;
            for(unsigned seed=0;seed<4;seed++) {
                for(unsigned preset=0;preset<2;preset++) {
                    uint64_t input[68]={0},output[69]={0},want[69]={0};
                    for(unsigned i=0;i<64;i++) input[i]=UINT64_C(0x123456789abcdef0)+(uint64_t)i*UINT64_C(0x0102030405060708);
                    uint64_t mask=UINT64_MAX;
                    if(forms[function].bits<64) mask=(UINT64_C(1)<<forms[function].bits)-1;
                    unsigned left=2*forms[function].left,right=2*forms[function].right;
                    input[left]=(input[left]&~mask)|samples[index].a;
                    if(forms[function].mode==0) input[right]=(input[right]&~mask)|samples[index].b;
                    input[64]=samples[index].control;input[65]=preset?0x08000012:0;input[66]=seeds[seed][0];input[67]=seeds[seed][1];
                    for(unsigned i=0;i<64;i++) want[i]=input[i];
                    want[64]=forms[function].nzcv;want[65]=input[65];want[66]=input[64];
                    if(truth[forms[function].condition][seed]) {
                        want[64]=samples[index].flags;
                        want[65]|=forms[function].signaling?samples[index].signaling:samples[index].quiet;
                    }
                    if(forms[function].dead) want[64]=6;
                    output[67]=want[67]=UINT64_C(0x123456789abcdef0);
                    output[68]=want[68]=UINT64_C(0xfedcba9876543210);
                    functions[function](input,output);
                    for(unsigned word=0;word<69;word++) {
                        if(output[word]!=want[word]) {
                            fprintf(stderr,"function %u sample %u seed %u word %u got %llx want %llx\n",function,index,seed,word,(unsigned long long)output[word],(unsigned long long)want[word]);
                            return 1;
                        }
                    }
                    count++;
                }
            }
        }
    }
    printf("ARM64_CONDITIONAL_TRANSLATED_PASS %u\n",count);
    return 0;
}
`)
	return original.String(), driver.String()
}

func arm64ConditionalStatusRuntime(t *testing.T, triple, goos string, compiler, runner []string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	cases := arm64ConditionalStatusCases()
	if len(cases) != 80 {
		t.Fatal("complete conditional status partition changed", len(cases))
	}
	visited := 0
	for start := 0; start < len(cases); start += 40 {
		end := start + 40
		if end > len(cases) {
			end = len(cases)
		}
		t.Run(fmt.Sprintf("batch%d", start/40), func(t *testing.T) {
			source, declarations := arm64ConditionalStatusSource(cases[start:end])
			original, driver := arm64ConditionalStatusPrograms(cases[start:end], declarations)
			arm64ScalarCompareActualGo(t, source, original, goos, runner)
			irs := arm64CompareMatrixIRs(t, source, declarations, triple)
			for api, ir := range irs {
				for _, variant := range []struct{ name, ir string }{{"none", ir}, {"O2", armFloatEffectOptimizedIR(t, ir)}} {
					for _, level := range []int{0, 2} {
						t.Run(fmt.Sprintf("api%d/IR_%s/backend_O%d", api, variant.name, level), func(t *testing.T) {
							compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "conditional_state", triple, variant.ir, driver, runner, level)
						})
					}
				}
			}
		})
		visited += end - start
	}
	if visited != len(cases) {
		t.Fatal("status partition is not exhaustive")
	}
}

func TestARM64ConditionalCompareWholeStateNativeRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("Darwin host counterpart; required Linux/QEMU owner executes the same whole-state fixture")
	}
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	arm64ConditionalStatusRuntime(t, "aarch64-apple-darwin", "darwin", []string{clang}, nil)
}
