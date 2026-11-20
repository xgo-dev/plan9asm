//go:build linux && amd64

package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// These original complete Go bytes run through an explicit AX/BX C adapter,
// not an authenticated SDK entry or a native Go caller. Capture RFLAGS before
// the adapter's cleanup changes it; keep its original stack/GP canaries.
func x86NumericalLEAOriginalAdapter(t *testing.T, index int, source string) string {
	t.Helper()
	adapter := amd64RegisterBoolOriginalAdapter(t, "x86_64-unknown-linux-gnu", index, source)
	first, rest, found := strings.Cut(adapter, "\n")
	if !found || !strings.HasPrefix(first, "__asm__(") || !strings.HasSuffix(first, ");") {
		t.Fatal("original adapter must retain its exact assembly writer")
	}
	assembly, err := strconv.Unquote(strings.TrimSuffix(strings.TrimPrefix(first, "__asm__("), ");"))
	if err != nil {
		t.Fatal(err)
	}
	call := fmt.Sprintf("callq OriginalBody%d\n", index)
	observation := "movq %r15,48(%r12)\n"
	if strings.Count(assembly, call) != 1 || strings.Count(assembly, observation) != 1 {
		t.Fatal("original adapter lost its unique call/observation boundary")
	}
	assembly = strings.Replace(assembly, call, call+"pushfq\npopq %r11\n", 1)
	assembly = strings.Replace(assembly, observation, observation+"movq %r11,56(%r12)\n", 1)
	return fmt.Sprintf("__asm__(%q);\n%s", assembly, rest)
}

func TestCrossLinuxRuntimeMatrixX86NumericalLEAOriginalBytesAndLLVM(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("required native Linux AMD64 LEA owner needs LLVM22 llc/clang")
	}
	execution := x86FloatCompareExecution{llc: llc, triple: "x86_64-unknown-linux-gnu",
		compiler: []string{clang, "-target", "x86_64-unknown-linux-gnu"}}
	rows := x86NumericalLEARows("amd64")
	for start := 0; start < len(rows); start += 32 {
		end := start + 32
		if end > len(rows) {
			end = len(rows)
		}
		t.Run(fmt.Sprintf("%d-%d", start, end), func(t *testing.T) {
			batch := rows[start:end]
			source, declarations := x86NumericalLEASources("amd64", batch, true)
			var originals, prototypes, checks, status, statusDeclarations strings.Builder
			for index, row := range batch {
				original := fmt.Sprintf("TEXT ·NumericalLEA%d<ABIInternal>(SB),4,$0-0\n%sRET\n", index, row.body("amd64", true))
				originals.WriteString(x86NumericalLEAOriginalAdapter(t, index, original))
				fmt.Fprintf(&prototypes, "extern uint64_t NumericalLEA%d(uint64_t,uint64_t);\nextern uint64_t Status%d(uint64_t,uint64_t);\n", index, index)
				// LAHF is a pre-existing scalar lowering diagnostic, not a new
				// must-defined/canonical permission. The paired numerical result
				// above independently requires the complete typed LEA proof.
				fmt.Fprintf(&status, "TEXT ·Status%d<ABIInternal>(SB),4,$0-0\n%sSETOS DL\nLAHF\nMOVBLZX AH,AX\nMOVBLZX DL,DX\nSHLQ $8,DX\nORQ DX,AX\nRET\n", index, row.body("amd64", false))
				fmt.Fprintf(&statusDeclarations, "func Status%d(x,y uint64) uint64\n", index)
				initial := "UINT64_C(0x1122334455667788)"
				if row.destination == "AX" {
					initial = "a"
				} else if row.destination == "BX" {
					initial = "b"
				}
				result := row.effective
				if row.width == "W" {
					result = "((" + initial + ")&~UINT64_C(65535))|(uint16_t)(" + result + ")"
				} else if row.width == "L" {
					result = "(uint32_t)(" + result + ")"
				}
				fmt.Fprintf(&checks, `{
    uint64_t observed[8]={0},raw=Original%d(a,b,observed),want=%s;
    uint64_t got=NumericalLEA%d(a,b),bits=flags(a,b),packed=(bits&255)|2|((bits>>11&1)<<8);
    uint64_t llvmFlags=Status%d(a,b);
    if(raw!=want||got!=want||(observed[7]&0x8d5)!=bits||llvmFlags!=packed||!canaries(observed)){
        fprintf(stderr,"row=%d a=%%llx b=%%llx raw=%%llx LLVM=%%llx want=%%llx nativeFlags=%%llx LLVMflags=%%llx expectedFlags=%%llx\n",
            (unsigned long long)a,(unsigned long long)b,(unsigned long long)raw,(unsigned long long)got,
            (unsigned long long)want,(unsigned long long)(observed[7]&0x8d5),(unsigned long long)llvmFlags,(unsigned long long)bits);
        return 1;
    }
}
`, index, result, index, index, start+index)
			}
			driver := `#include <stdint.h>
#include <stdio.h>
` + originals.String() + prototypes.String() + `
static int canaries(const uint64_t *p){
    return p[0]==UINT64_C(0x5a5a5a5a5a5a5a5a)&&p[1]==p[0]&&
        p[2]==UINT64_C(0x6b6b6b6b6b6b6b6b)&&p[3]==p[2]&&
        p[4]==UINT64_C(0x123456789abcdef0)&&p[5]==UINT64_C(0xfedcba9876543210)&&p[6]==UINT64_C(0x876543210fedcba9);
}
static uint64_t flags(uint64_t a,uint64_t b){
    uint64_t r=a-b;unsigned parity=(uint8_t)r;
    parity^=parity>>4;parity^=parity>>2;parity^=parity>>1;
    return (a<b)|((uint64_t)((parity&1)==0)<<2)|(((a^b^r)>>4&1)<<4)|
        ((uint64_t)(r==0)<<6)|((r>>63)<<7)|((((a^b)&(a^r))>>63)<<11);
}
int main(void){
    const uint64_t values[]={0,1,63,64,65,65535,65536,UINT64_C(2147483647),UINT64_C(2147483648),
        UINT64_C(4294967295),UINT64_C(4294967296),UINT64_C(1)<<63,UINT64_C(0x1122334455667788),UINT64_MAX};
    for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);i++)for(unsigned j=0;j<sizeof(values)/sizeof(values[0]);j++){
        uint64_t a=values[i],b=values[j];
` + checks.String() + `
    }
    puts("complete original Go numerical LEA bytes vs LLVM; W/L/Q, all effective-address axes, aliases, all six unchanged FLAGS and stack/GP canaries");
    return 0;
}
`
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source+status.String(), declarations+statusDeclarations.String(), "amd64", execution.triple, api)
				if err != nil {
					t.Fatal(api, err)
				}
				for _, optimized := range []bool{false, true} {
					input, level := ir, "-O0"
					if optimized {
						input, level = x86MulDivRoundOptimize(t, input), "-O2"
					}
					t.Log(api, level, execution.compileAndRunLLVM(t, "numerical-lea", input, driver, level))
				}
			}
		})
	}
}
