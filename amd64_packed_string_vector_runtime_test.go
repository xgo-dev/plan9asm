//go:build unix

package plan9asm

import (
	"crypto/sha256"
	"debug/elf"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

func x86PackedStringVectorCOracle(cases []x86PackedStringVectorCase) string {
	var functions, registrations strings.Builder
	for index, row := range cases {
		name := fmt.Sprintf("stringvector%d", index)
		fmt.Fprintf(&functions, "extern void %s(uint8_t *,const uint8_t *);\n", name)
		// Native legacy SSE supplies an independent low-mask/index and flags
		// oracle. VEX upper-zeroing is checked separately against the ISA rule;
		// this portable test never claims execution of a native VEX instruction.
		fmt.Fprintf(&functions, `static void reference%d(const uint8_t *left,const uint8_t *right,uint8_t *mask,uint64_t *flags,uint64_t *index) {
    uint64_t a=5,d=9,c=73,f;
    __asm__ volatile(
        "movdqu (%%[left]),%%%%xmm1\n\t"
        "movdqu (%%[right]),%%%%xmm2\n\t"
        "%s $%d,%%%%xmm2,%%%%xmm1\n\t"
        "pushfq\n\t"
        "popq %%[flags]\n\t"
        "movdqu %%%%xmm0,(%%[mask])\n\t"
        : "+a"(a),"+d"(d),"+c"(c),[flags]"=&r"(f)
        : [left]"r"(left),[right]"r"(right),[mask]"r"(mask)
        : "xmm0","xmm1","xmm2","cc","memory");
    *flags=f&UINT64_C(0x8d5);
    *index=c;
}

`, index, strings.ToLower(strings.TrimPrefix(row.op, "V")), row.imm)
		fmt.Fprintf(&registrations, "{%s,reference%d,%d,%d,%d,%d,%q},\n", name, index,
			row.source, row.dst, x86FloatAddSubBoolInt(strings.HasSuffix(row.op, "M")),
			x86FloatAddSubBoolInt(strings.HasPrefix(row.op, "V")), row.op)
	}
	return `#include <stdint.h>
#include <stdio.h>
#include <string.h>
` + functions.String() + `
struct program {
    void (*run)(uint8_t *,const uint8_t *);
    void (*reference)(const uint8_t *,const uint8_t *,uint8_t *,uint64_t *,uint64_t *);
    int source,destination,mask,vector;
    const char *name;
};
static const struct program programs[]={
` + registrations.String() + `};

int main(void) {
    unsigned observations=0;
    for (unsigned program=0;program<sizeof(programs)/sizeof(programs[0]);++program) {
        const struct program *p=&programs[program];
        for (unsigned round=0;round<4;++round) {
            uint8_t input[194],original[194],output[362],mask[16];
            uint64_t flags,index,gotFlags,gotIndex;
            for (unsigned i=0;i<sizeof(input);++i) {
                input[i]=(uint8_t)(i*73+round*19+1);
            }
            input[1+3]=0;
            input[1+64+7]=0;
            input[1+128+11]=0;
            memcpy(original,input,sizeof(input));
            memset(output,0xc3,sizeof(output));
            uint32_t saved,before=UINT32_C(0x1f80)|(round<<13)|round,after;
            __asm__ volatile("stmxcsr %0":"=m"(saved));
            __asm__ volatile("ldmxcsr %0"::"m"(before));
            p->reference(input+1+p->destination*64,input+1+p->source*64,mask,&flags,&index);
            p->run(output+1,input+1);
            __asm__ volatile("stmxcsr %0":"=m"(after));
            __asm__ volatile("ldmxcsr %0"::"m"(saved));
            memcpy(&gotFlags,output+1+336,8);
            memcpy(&gotIndex,output+1+352,8);
            uint8_t lahf=(uint8_t)((flags&UINT64_C(0xd5))|2);
            if (gotFlags!=flags || output[1+344]!=lahf || gotIndex!=index ||
                after!=before || output[0]!=0xc3 || output[361]!=0xc3 || memcmp(input,original,sizeof(input))) {
                fprintf(stderr,"%s/%u flags/index/input/canary mismatch\n",p->name,program);
                return 1;
            }
            const unsigned widths[]={16,32,64},offsets[]={0,16,48};
            for (unsigned reg=0;reg<3;++reg) {
                for (unsigned view=0;view<3;++view) {
                    for (unsigned byte=0;byte<widths[view];++byte) {
                        uint8_t want=input[1+reg*64+byte];
                        if (p->mask && reg==0) {
                            if (byte<16) {
                                want=mask[byte];
                            } else if (p->vector) {
                                want=0;
                            }
                        }
                        uint8_t got=output[1+reg*112+offsets[view]+byte];
                        if (got!=want) {
                            fprintf(stderr,"%s/%u round=%u bank=%u width=%u byte=%u got=%u want=%u\n",
                                p->name,program,round,reg,widths[view],byte,got,want);
                            return 1;
                        }
                    }
                }
            }
            ++observations;
        }
    }
    printf("portable packed-string byte observations %u failures 0\n",observations);
    return 0;
}
`
}

func TestX86PackedStringImplicitVectorByteOracle(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	execution.compiler = append(execution.compiler, "-mno-red-zone")
	cases := x86PackedStringVectorCases()
	declarations, source := x86PackedStringVectorFixture(cases, "amd64")
	ir := x86CPUQueryIRFromDeclaration(t, source, declarations, "amd64", execution.triple, "Go")
	// Only the execution target-feature request changes: all source operations
	// and LLVM byte arithmetic stay intact. This makes the wide virtual bank
	// oracle executable using SSE4.2, without asserting native AVX/AVX512.
	features := regexp.MustCompile(`"target-features"="([^"]*)"`)
	ir = features.ReplaceAllStringFunc(ir, func(attribute string) string {
		values := features.FindStringSubmatch(attribute)[1]
		for _, value := range strings.Split(values, ",") {
			switch value {
			case "+avx", "+avx512f", "+avx512vl", "+sse4.2":
			default:
				t.Fatalf("unreviewed portable feature request: %q", value)
			}
		}
		return `"target-features"="+sse4.2"`
	})
	if strings.Contains(ir, `"target-features"="+avx`) {
		t.Fatal("portable oracle retained an unreviewed native AVX feature request")
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			input := ir
			if level == "-O2" {
				input = x86UndefinedTrapOptimizedIR(t, input)
			}
			output := execution.compileAndRunLLVM(t, "packed-string-vector-bytes", input, x86PackedStringVectorCOracle(cases), level)
			want := fmt.Sprintf("portable packed-string byte observations %d failures 0\n", len(cases)*4)
			if string(output) != want {
				t.Fatalf("incomplete byte oracle: %s", output)
			}
		})
	}
}

func x86PackedStringNativeYFixture() ([]x86PackedStringVectorCase, string, string) {
	var cases []x86PackedStringVectorCase
	for _, row := range x86PackedStringVectorCases() {
		if row.imm == 8 {
			cases = append(cases, row)
		}
	}
	declarations, source := x86PackedStringVectorFixture(cases, "amd64")
	// Actual native AVX has 32-byte banks. Z-bank execution is a distinct
	// AVX512 requirement and is not silently inferred from this counterpart.
	for reg := 0; reg < 3; reg++ {
		source = strings.ReplaceAll(source, fmt.Sprintf("VMOVUPS %d(SI),Z%d\n", reg*64, reg),
			fmt.Sprintf("VMOVUPS %d(SI),Y%d\n", reg*64, reg))
		source = strings.ReplaceAll(source, fmt.Sprintf("VMOVUPS Z%d,%d(DI)\n", reg, reg*112+48), "")
	}
	return cases, declarations, source
}

func x86PackedStringNativeGoDriver(cases []x86PackedStringVectorCase) string {
	var registrations strings.Builder
	for index, row := range cases {
		fmt.Fprintf(&registrations, "{stringvector%d,%d,%d,%t,%t,%t,%q},\n", index, row.source, row.dst,
			strings.HasSuffix(row.op, "M"), strings.HasPrefix(row.op, "V"),
			strings.Contains(row.op, "ESTR"), row.op)
	}
	return `package main

import (
    "encoding/binary"
    "fmt"
    "os"
    "unsafe"
)

type program struct {
    run func(*[360]byte,*[192]byte)
    source,destination int
    mask,vector,explicit bool
    name string
}

var programs=[]program{
` + registrations.String() + `}

func fail(name string,round int,detail string) {
    fmt.Fprintf(os.Stderr,"%s round=%d %s\n",name,round,detail)
    os.Exit(1)
}

func main() {
    observations:=0
    for _,p:=range programs {
        for round:=0;round<4;round++ {
            input:=[194]byte{}
            output:=[362]byte{}
            for i:=range input {
                input[i]=byte(i*73+round*19+1)
            }
            input[1+3]=0
            input[1+64+7]=0
            input[1+128+11]=0
            original:=input
            for i:=range output {
                output[i]=0xc3
            }
            p.run((*[360]byte)(unsafe.Pointer(&output[1])),(*[192]byte)(unsafe.Pointer(&input[1])))
            if input!=original || output[0]!=0xc3 || output[361]!=0xc3 {
                fail(p.name,round,"input/canary mismatch")
            }
            left:=input[1+p.destination*64:1+p.destination*64+16]
            right:=input[1+p.source*64:1+p.source*64+16]
            la,lb:=5,9
            if !p.explicit {
                la,lb=16,16
                for i:=0;i<16;i++ {
                    if left[i]==0 && la==16 {
                        la=i
                    }
                    if right[i]==0 && lb==16 {
                        lb=i
                    }
                }
            }
            var result uint16
            for i:=0;i<16;i++ {
                if i>=la && i>=lb || i<la && i<lb && left[i]==right[i] {
                    result|=1<<uint(i)
                }
            }
            flags:=uint64(0)
            if result!=0 {
                flags|=1
            }
            if lb<16 {
                flags|=0x40
            }
            if la<16 {
                flags|=0x80
            }
            if result&1!=0 {
                flags|=0x800
            }
            index:=uint64(73)
            if !p.mask {
                index=16
                for i:=0;i<16;i++ {
                    if result&(1<<uint(i))!=0 {
                        index=uint64(i)
                        break
                    }
                }
            }
            gotFlags:=binary.LittleEndian.Uint64(output[337:345])&0x8d5
            gotIndex:=binary.LittleEndian.Uint64(output[353:361])
            if gotFlags!=flags || gotIndex!=index || output[345]!=byte(flags&0xd5)|2 {
                fail(p.name,round,"six flags/LAHF/index mismatch")
            }
            widths,offsets:=[]int{16,32},[]int{0,16}
            for reg:=0;reg<3;reg++ {
                for view,width:=range widths {
                    for b:=0;b<width;b++ {
                        want:=input[1+reg*64+b]
                        if p.mask && reg==0 {
                            if b<16 {
                                want=0
                                if b<2 {
                                    want=byte(result>>uint(b*8))
                                }
                            } else if p.vector {
                                want=0
                            }
                        }
                        if got:=output[1+reg*112+offsets[view]+b];got!=want {
                            fail(p.name,round,fmt.Sprintf("bank=%d width=%d byte=%d got=%d want=%d",reg,width,b,got,want))
                        }
                    }
                }
            }
            observations++
        }
    }
    fmt.Printf("original native AVX packed-string observations %d failures 0\n",observations)
}
`
}

func TestX86PackedStringNativeAVXCounterpartOriginalObject(t *testing.T) {
	cases, declarations, source := x86PackedStringNativeYFixture()
	execution := x86FloatCompareExecution{triple: "x86_64-unknown-linux-gnu"}
	executable := x86DefinedStatusBuildOriginal(t, execution, declarations, source, x86PackedStringNativeGoDriver(cases))
	object, err := elf.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	if object.Class != elf.ELFCLASS64 || object.Machine != elf.EM_X86_64 || object.Data != elf.ELFDATA2LSB {
		t.Fatal("native AVX counterpart is not an actual Linux/amd64 ELF")
	}
	bytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual original Go Linux/amd64 ELF bytes=%d sha=%x; compile-only, native execution remains required", len(bytes), sha256.Sum256(bytes))
}
