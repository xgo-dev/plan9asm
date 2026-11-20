package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestCrossLinuxRuntimeMatrixX86MOVNTIOriginalFlagsAndFaults(t *testing.T) {
	execution := x86FloatCompareExecutionTools(t)
	var assembly, declarations, prototypes, checks, goChecks strings.Builder
	declarations.WriteString("package oracle\n")
	count := 0
	for _, row := range []struct {
		suffix string
		bytes  int
	}{{"L", 4}, {"Q", 8}} {
		for _, offset := range []int{0, 1} {
			name := fmt.Sprintf("Store%s%d", row.suffix, offset)
			fmt.Fprintf(&declarations, "func %s(out *byte,value uint64)\n", name)
			fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$0-16\n"+
				"MOVQ out+0(FP),DX\nMOVQ value+8(FP),AX\n"+
				"MOVL $0x7fffffff,R8\nADDL $1,R8\nSTC\nMOVL $%d,CX\n"+
				"MOVNTI%s AX,(DX)(CX*1)\nSFENCE\n"+
				"SETCS 24(DX)\nSETOS 25(DX)\nSETEQ 26(DX)\nSETMI 27(DX)\nRET\n",
				name, offset, row.suffix)
			fmt.Fprintf(&prototypes, "extern void %s(uint8_t *,uint64_t);\n", name)
			fmt.Fprintf(&checks, "if (check_value(%s,%d,%d,value)) return 1; count++;\n", name, row.bytes, offset)
			fmt.Fprintf(&goChecks, "check(t,%s,%d,%d,value); count++\n", name, row.bytes, offset)
			count++
		}
		fmt.Fprintf(&declarations, "func Dead%s(out *byte)\n", row.suffix)
		fmt.Fprintf(&assembly, "TEXT ·Dead%s(SB),4,$0-8\nMOVQ out+0(FP),DX\nMOVQ $42,AX\n"+
			"MOVNTI%s AX,(DX)\nMOVNTI%s AX,(DX)\nSFENCE\nRET\n", row.suffix, row.suffix, row.suffix)
	}
	if count != 4 {
		t.Fatal("complete scalar non-temporal value/canary directory changed", count)
	}
	goAssemblerOracleOutput(t, "amd64", assembly.String(), "", true)
	ir := x86NarrowOracleIR(t, assembly.String(), declarations.String(), execution.triple)
	for _, pipeline := range []struct{ name, level, ir string }{
		{"backend_O0", "-O0", ir},
		{"backend_O2", "-O2", ir},
		{"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			if strings.Count(pipeline.ir, `asm sideeffect "movnti`) != 8 || strings.Contains(pipeline.ir, "!nontemporal") {
				t.Fatal("original/dead native stores became optional cache metadata")
			}
			output := execution.compileAndRunLLVM(t, "movnti-values-flags", pipeline.ir,
				fmt.Sprintf(x86MOVNTIValuesC, prototypes.String(), checks.String()), pipeline.level)
			if string(output) != "MOVNTI values/FLAGS/canary outcomes 32 failures 0\n" {
				t.Fatal("independent exact native value/FLAGS/canary observations", string(output))
			}
			executable := execution.compileLLVM(t, "movnti-dead-faults", pipeline.ir, x86MOVNTIFaultsC, pipeline.level)
			for row := 0; row < 2; row++ {
				for probe := 0; probe < 4; probe++ {
					want := x86ObserveMemoryFault(t, execution, executable, row, probe, 1)
					if probe == 2 {
						if want != "return" {
							t.Fatal("complete accessible original native MOVNTI store faulted", row, want)
						}
					} else if want != "segv" && want != "bus" {
						t.Fatal("NULL, partial-page or readonly original native store did not fault", row, probe, want)
					}
					if got := x86ObserveMemoryFault(t, execution, executable, row, probe, 0); got != want {
						t.Fatal("dead MOVNTI lost exact native fault behavior", row, probe, got, want)
					}
				}
			}
			t.Log("32 value/FLAGS/full-buffer outcomes; both widths retain dead NULL, partial-page, complete-page and readonly native writes")
		})
	}
	x86WordMultiplyRunOriginalGo(t, execution, declarations.String(), assembly.String(),
		fmt.Sprintf(x86MOVNTIOriginalGo, goChecks.String()))
}

const x86MOVNTIValuesC = `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
%s
static int check_value(void (*run)(uint8_t *,uint64_t),unsigned bytes,unsigned offset,uint64_t value) {
    uint8_t actual[48], expected[48];
    memset(actual,0xc3,sizeof(actual));
    memset(expected,0xc3,sizeof(expected));
    for (unsigned i=0;i<bytes;i++) expected[1+offset+i]=(uint8_t)(value>>(i*8));
    expected[25]=1;
    expected[26]=1;
    expected[27]=0;
    expected[28]=1;
    run(actual+1,value);
    if (memcmp(actual,expected,sizeof(actual))) {
        fprintf(stderr,"MOVNTI value/FLAGS/canary mismatch bytes=%%u offset=%%u value=%%llx\n",bytes,offset,(unsigned long long)value);
        return 1;
    }
    return 0;
}
int main(void) {
    const uint64_t values[]={0,1,UINT64_MAX,UINT64_C(0x8000000000000000),
        UINT64_C(0x1122334455667788),UINT64_C(0x8877665544332211),
        UINT64_C(0xaaaaaaaa55555555),UINT64_C(0x00000000ffffffff)};
    unsigned count=0;
    for (unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++) {
        uint64_t value=values[i];
        %s
    }
    if (count!=32) return 1;
    printf("MOVNTI values/FLAGS/canary outcomes %%u failures 0\n",count);
    return 0;
}
`

const x86MOVNTIOriginalGo = `package oracle
import "testing"
func check(t *testing.T,run func(*byte,uint64),bytes,offset int,value uint64) {
    t.Helper()
    var actual,expected [48]byte
    for i:=range actual {actual[i]=0xc3; expected[i]=0xc3}
    for i:=0;i<bytes;i++ {expected[1+offset+i]=byte(value>>uint(i*8))}
    expected[25],expected[26],expected[27],expected[28]=1,1,0,1
    run(&actual[1],value)
    if actual!=expected {t.Fatalf("original MOVNTI bytes=%%d offset=%%d value=%%x got=%%x want=%%x",bytes,offset,value,actual,expected)}
}
func TestOriginal(t *testing.T) {
    values:=[]uint64{0,1,^uint64(0),0x8000000000000000,0x1122334455667788,
        0x8877665544332211,0xaaaaaaaa55555555,0x00000000ffffffff}
    count:=0
    for _,value:=range values {
        %s
    }
    if count!=32 {t.Fatal(count)}
    t.Log("original Go MOVNTI values/FLAGS/canary outcomes 32 failures 0")
}
`

const x86MOVNTIFaultsC = x86MemoryFaultSupportC + `
extern void DeadL(uint8_t *);
extern void DeadQ(uint8_t *);
int main(int argc,char **argv) {
    if (argc!=4) return 80;
    unsigned row,probe,original;
    char tail;
    if (sscanf(argv[1],"%u%c",&row,&tail)!=1 ||
            sscanf(argv[2],"%u%c",&probe,&tail)!=1 ||
            sscanf(argv[3],"%u%c",&original,&tail)!=1 || row>1 || probe>3 || original>1) return 80;
    if (memory_fault_setup(0)) return 81;
    unsigned bytes=row?8:4;
    uint8_t *input=probe==0?NULL:guard+page-bytes+(probe==1?1:0);
    if (probe==3) {
#ifdef _WIN32
        DWORD old;
        if (!VirtualProtect(guard,page,PAGE_READONLY,&old)) return 82;
#else
        if (mprotect(guard,page,PROT_READ)) return 82;
#endif
    }
    printf("memory enter %u %u %u\n",row,probe,original);
    if (fflush(stdout)) return 83;
    if (original) {
        if (row) __asm__ volatile("movnti %1,(%0); movnti %1,(%0); sfence"::"r"(input),"r"((uint64_t)42):"memory");
        else __asm__ volatile("movnti %1,(%0); movnti %1,(%0); sfence"::"r"(input),"r"((uint32_t)42):"memory");
    } else if (row) DeadQ(input);
    else DeadL(input);
    if (free_guard()) return 84;
    puts("memory complete");
    return fflush(stdout)?85:0;
}
`
