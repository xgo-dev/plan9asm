package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Integer-only IEEE reference: no host float operation or production helper.
// Arm FPCompare unpacks both operands using FPCR, signals sNaNs (all NaNs
// for FCMPE), and writes 0011/1000/0110/0010 for unordered/less/equal/greater.
func arm64CompareExpected(bits int, left, right, control uint64, signaling bool) (flags, status uint64) {
	fractionBits, exponentBits := uint(23), uint(8)
	if bits == 64 {
		fractionBits, exponentBits = 52, 11
	} else if bits == 16 {
		fractionBits, exponentBits = 10, 5
	}
	fraction := uint64(1)<<fractionBits - 1
	exponent := (uint64(1)<<exponentBits - 1) << fractionBits
	sign := uint64(1) << uint(bits-1)
	left &= sign | exponent | fraction
	right &= sign | exponent | fraction
	nan := false
	for _, operand := range []*uint64{&left, &right} {
		value := *operand
		if value&exponent == exponent && value&fraction != 0 {
			nan = true
			if signaling || value&(uint64(1)<<(fractionBits-1)) == 0 {
				status |= 1
			}
		}
		flush := control&(1<<24) != 0
		if bits == 16 {
			flush = control&(1<<19) != 0
		}
		if flush && value&exponent == 0 && value&fraction != 0 {
			*operand = value & sign
			if bits != 16 {
				status |= 1 << 7
			}
		}
	}
	if nan {
		return 3, status
	}
	if left == right || left&^sign == 0 && right&^sign == 0 {
		return 6, status
	}
	less := left < right
	if (left^right)&sign != 0 {
		less = left&sign != 0
	} else if left&sign != 0 {
		less = left > right
	}
	if less {
		return 8, status
	}
	return 2, status
}

func arm64CompareValues(bits int) []uint64 {
	if bits == 16 {
		return []uint64{0, 0x8000, 0x3c00, 0xbc00, 0x7c00, 0xfc00, 0x7e01, 0xfe01, 0x7c01, 0xfc01, 1, 0x8001, 0x3ff, 0x400, 0x7bff, 0xfbff}
	}
	if bits == 32 {
		return []uint64{0, 0x80000000, 0x3f800000, 0xbf800000, 0x7f800000, 0xff800000, 0x7fc00001, 0xffc00001, 0x7f800001, 0xff800001, 1, 0x80000001, 0x007fffff, 0x00800000, 0x7f7fffff, 0xff7fffff}
	}
	return []uint64{0, 0x8000000000000000, 0x3ff0000000000000, 0xbff0000000000000, 0x7ff0000000000000, 0xfff0000000000000, 0x7ff8000000000001, 0xfff8000000000001, 0x7ff0000000000001, 0xfff0000000000001, 1, 0x8000000000000001, 0x000fffffffffffff, 0x0010000000000000, 0x7fefffffffffffff, 0xffefffffffffffff}
}

func arm64CompareStatusPrograms(cases []arm64CompareCase) (string, string, int) {
	var original, driver strings.Builder
	original.WriteString("package main\nimport \"fmt\"\n")
	driver.WriteString("#include <stdint.h>\n#include <stdio.h>\n")
	for index := range cases {
		fmt.Fprintf(&original, "func compareMatrix%d(*[66]uint64,*[69]uint64)\n", index)
		fmt.Fprintf(&driver, "extern void compareMatrix%d(uint64_t*,uint64_t*);\n", index)
	}
	original.WriteString("var functions = [...]func(*[66]uint64,*[69]uint64){\n")
	driver.WriteString("static void (*functions[])(uint64_t*,uint64_t*)={\n")
	for index := range cases {
		fmt.Fprintf(&original, "compareMatrix%d,\n", index)
		fmt.Fprintf(&driver, "compareMatrix%d,\n", index)
	}
	original.WriteString("}\nvar forms = []struct { bits,left,right,mode int; signaling,dead bool }{\n")
	driver.WriteString("};\nstatic const struct { int bits,left,right,mode,signaling,dead; } forms[]={\n")
	for _, row := range cases {
		mode, signaling, dead := 0, 0, 0
		if row.left == row.right {
			mode = 1
		}
		if row.zero {
			mode = 2
		}
		if strings.Contains(row.op, "E") {
			signaling = 1
		}
		if row.dead {
			dead = 1
		}
		fmt.Fprintf(&original, "{%d,%d,%d,%d,%t,%t},\n", row.bits, row.left, row.right, mode, signaling != 0, row.dead)
		fmt.Fprintf(&driver, "{%d,%d,%d,%d,%d,%d},\n", row.bits, row.left, row.right, mode, signaling, dead)
	}
	original.WriteString("}\nvar samples = []struct { bits,mode int; a,b,control,flags,quiet,signaling uint64 }{\n")
	driver.WriteString("};\nstatic const struct { int bits,mode; uint64_t a,b,control,flags,quiet,signaling; } samples[]={\n")
	seen := make(map[int]bool)
	count := 0
	for _, row := range cases {
		if seen[row.bits] {
			continue
		}
		seen[row.bits] = true
		for mode := 0; mode < 3; mode++ {
			for _, left := range arm64CompareValues(row.bits) {
				for rightIndex, value := range arm64CompareValues(row.bits) {
					right := value
					if mode != 0 && rightIndex != 0 {
						continue
					}
					if mode == 1 {
						right = left
					} else if mode == 2 {
						right = 0
					}
					for rounding := 0; rounding < 4; rounding++ {
						for controls := 0; controls < 4; controls++ {
							control := uint64(rounding)<<22 | uint64(controls&1)<<24 | uint64(controls>>1)<<25
							if row.bits == 16 && controls&1 != 0 {
								control |= 1 << 19
							}
							flags, quiet := arm64CompareExpected(row.bits, left, right, control, false)
							_, signaling := arm64CompareExpected(row.bits, left, right, control, true)
							fmt.Fprintf(&original, "{%d,%d,%#x,%#x,%#x,%#x,%#x,%#x},\n", row.bits, mode, left, right, control, flags, quiet, signaling)
							fmt.Fprintf(&driver, "{%d,%d,%#xULL,%#xULL,%#xULL,%#xULL,%#xULL,%#xULL},\n", row.bits, mode, left, right, control, flags, quiet, signaling)
							count++
						}
					}
				}
			}
		}
	}
	original.WriteString(`}
func main() {
    count:=0
    for function,form:=range forms {
        for _,sample:=range samples {
            if sample.bits!=form.bits || sample.mode!=form.mode { continue }
            var input [66]uint64
            for i:=0;i<64;i++ { input[i]=0x123456789abcdef0+uint64(i)*0x0102030405060708 }
            mask:=^uint64(0)
            if form.bits<64 { mask=(uint64(1)<<form.bits)-1 }
            input[2*form.left]=input[2*form.left]&^mask|sample.a
            if form.mode==0 { input[2*form.right]=input[2*form.right]&^mask|sample.b }
            input[64],input[65]=sample.control,0x08000002
            var output,want [69]uint64
            copy(want[:64],input[:64])
            want[64],want[65],want[66]=sample.flags,input[65]|sample.quiet,input[64]
            if form.signaling { want[65]=input[65]|sample.signaling }
            if form.dead { want[64]=6 }
            output[67],output[68]=0x123456789abcdef0,0xfedcba9876543210
            want[67],want[68]=output[67],output[68]
            functions[function](&input,&output)
            if output!=want { panic(fmt.Sprintf("function %d sample %+v got %x want %x",function,sample,output,want)) }
            count++
        }
    }
    fmt.Println("ARM64_COMPARE_ORIGINAL_PASS",count)
}
`)
	driver.WriteString(`};
int main(void) {
    unsigned count=0;
    for(unsigned function=0;function<sizeof(forms)/sizeof(forms[0]);function++) {
        for(unsigned index=0;index<sizeof(samples)/sizeof(samples[0]);index++) {
            if(samples[index].bits!=forms[function].bits || samples[index].mode!=forms[function].mode) continue;
            uint64_t input[66]={0},output[69]={0},want[69]={0};
            for(unsigned i=0;i<64;i++) input[i]=0x123456789abcdef0ULL+(uint64_t)i*0x0102030405060708ULL;
            uint64_t mask=UINT64_MAX;
            if(forms[function].bits<64) mask=(UINT64_C(1)<<forms[function].bits)-1;
            unsigned left=2*forms[function].left,right=2*forms[function].right;
            input[left]=(input[left]&~mask)|samples[index].a;
            if(forms[function].mode==0) input[right]=(input[right]&~mask)|samples[index].b;
            input[64]=samples[index].control;input[65]=0x08000002;
            for(unsigned i=0;i<64;i++) want[i]=input[i];
            want[64]=forms[function].dead?6:samples[index].flags;
            want[65]=input[65]|(forms[function].signaling?samples[index].signaling:samples[index].quiet);
            want[66]=input[64];
            output[67]=want[67]=0x123456789abcdef0ULL;
            output[68]=want[68]=0xfedcba9876543210ULL;
            functions[function](input,output);
            for(unsigned word=0;word<69;word++) {
                if(output[word]!=want[word]) {
                    fprintf(stderr,"function %u sample %u word %u got %llx want %llx\n",function,index,word,(unsigned long long)output[word],(unsigned long long)want[word]);
                    return 1;
                }
            }
            count++;
        }
    }
    printf("ARM64_COMPARE_TRANSLATED_PASS %u\n",count);
    return 0;
}
`)
	return original.String(), driver.String(), count
}

func arm64CompareStatusRuntime(t *testing.T, triple, goos string, compiler, runner []string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	cases := arm64CompareCases([]int{0, 15, 31}, false)
	raw := arm64CompareCases([]int{31}, true)
	cases = append(cases, raw...)
	for _, row := range raw {
		if row.bits == 32 {
			row.bits = 16
			cases = append(cases, row)
		}
	}
	source, declarations := arm64CompareMatrixSource(cases)
	original, driver, samples := arm64CompareStatusPrograms(cases)
	arm64ScalarCompareActualGo(t, source, original, goos, runner)
	// The three API object gate is separate. Runtime exercises the typed Go
	// consumer and both IR/backend optimization axes on the same original file.
	ir := arm64CompareMatrixIRs(t, source, declarations, triple)[2]
	for _, variant := range []struct{ name, ir string }{{"none", ir}, {"O2", armFloatEffectOptimizedIR(t, ir)}} {
		for _, level := range []int{0, 2} {
			t.Run(fmt.Sprintf("IR_%s/backend_O%d", variant.name, level), func(t *testing.T) {
				compileAndRunRuntimeTestWithCompiler(t, llc, compiler, "compare_status", triple, variant.ir, driver, runner, level)
			})
		}
	}
	t.Logf("%d named/raw/live/dead/zero/alias/bank kernels; %d integer IEEE/FPCR reference samples; entire 32-V bank, NZCV, FPSR, FPCR and output canaries", len(cases), samples)
}

func TestARM64ScalarCompareWholeStateRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("Darwin host counterpart; required Linux/QEMU matrix runs the same complete oracle")
	}
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang not found")
	}
	arm64CompareStatusRuntime(t, "aarch64-apple-darwin", "darwin", []string{clang}, nil)
}
