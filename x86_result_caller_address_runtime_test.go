package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type x86CallerAddressRuntimeRow struct {
	body, address, test string
	bits, condition     int
}

func x86CallerAddressRuntimeRows() []x86CallerAddressRuntimeRow {
	var rows []x86CallerAddressRuntimeRow
	for _, width := range []struct {
		name string
		bits int
	}{{"B", 8}, {"W", 16}, {"L", 32}, {"Q", 64}} {
		for condition, op := range amd64RegisterBoolConditions {
			rows = append(rows, x86CallerAddressRuntimeRow{
				body:    "MOVQ AX,DX\nLEAQ 16(DX),AX\nTEST" + width.name + " BX,AX\n" + op + " AX",
				address: "a+16", test: "v&b", bits: width.bits, condition: condition,
			})
		}
	}
	for _, alias := range []string{"MOVQ", "MOVD", "MOVDQ2Q"} {
		rows = append(rows, x86CallerAddressRuntimeRow{
			body:    alias + " AX,AX\nADDQ $16,AX\nTESTW $0xff0,AX\nJE yes\nMOVB $0,AX\nJMP done\nyes:\nMOVB $1,AX\ndone:",
			address: "a+16", test: "v&UINT64_C(0xff0)", bits: 16, condition: 2,
		})
	}
	return append(rows,
		x86CallerAddressRuntimeRow{"TESTB BH,AH\nSETEQ AX", "a", "(v>>8)&(b>>8)", 8, 2},
		x86CallerAddressRuntimeRow{"LEAQ (AX)(BX*8),AX\nTESTQ $-1,AX\nSETMI AX", "a+8*b", "v", 64, 9},
		x86CallerAddressRuntimeRow{"SUBQ $16,AX\nTESTQ BX,AX\nSETEQ AX", "a-16", "v&b", 64, 2},
		x86CallerAddressRuntimeRow{"ADDQ BX,AX\nTESTQ $-1,AX\nSETMI AX", "a+b", "v", 64, 9},
	)
}

func TestX86ResultCallerAddressThreeTargetOriginalAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	var source, declarations strings.Builder
	for index, row := range x86CallerAddressRuntimeRows() {
		name := fmt.Sprintf("Address%d", index)
		source.WriteString(strings.ReplaceAll(x86CallerAddressRegisterSource(row.body), "·view", "·"+name))
		fmt.Fprintf(&declarations, "func %s(p *byte,n uint64) bool\n", name)
	}
	requireAMD64RegisterResultGoObject(t, source.String())
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		for _, api := range []string{"text", "module", "Go"} {
			ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", triple, api)
			if err != nil {
				t.Fatal(triple, api, err)
			}
			for _, optimized := range []bool{false, true} {
				input := ir
				if optimized {
					input = x86MulDivRoundOptimize(t, input)
				}
				x86ResultInitializationObject(t, llc, triple, input, "caller-address")
			}
		}
	}
}

func TestCrossLinuxRuntimeMatrixX86CallerAddressInstructionBytesAndLLVM(t *testing.T) {
	x86CallerAddressRuntime(t, x86CallerAddressRuntimeRows())
}

func x86CallerAddressRuntime(t *testing.T, rows []x86CallerAddressRuntimeRow) {
	t.Helper()
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	var source, declarations, originals, wrappers, prototypes, checks strings.Builder
	for index, row := range rows {
		name := fmt.Sprintf("Address%d", index)
		original := strings.ReplaceAll(x86CallerAddressRegisterSource(row.body), "·view", "·"+name)
		source.WriteString(original)
		fmt.Fprintf(&declarations, "func %s(p *byte,n uint64) bool\n", name)
		// Reuse the independently declared original-byte AX/BX adapter and
		// raw-u64/stack/GP canaries, not an SDK/native Go caller certificate.
		originals.WriteString(amd64RegisterBoolOriginalAdapter(t, execution.triple, index, original))
		fmt.Fprintf(&wrappers, "\ndefine i32 @Probe%d(ptr %%p,i64 %%n) {\n %%v=call i1 @%s(ptr %%p,i64 %%n)\n %%r=zext i1 %%v to i32\n ret i32 %%r\n}\n", index, name)
		fmt.Fprintf(&prototypes, "extern uint32_t Probe%d(void*,uint64_t);\n", index)
		fmt.Fprintf(&checks, "{uint64_t v=%s,r=%s,observed[7]={0},raw=Original%d(a,b,observed);unsigned wanted=predicate(r,%d,%d);uint32_t got=Probe%d(p,b);\n"+
			"if(raw!=((v&~UINT64_C(255))|wanted)||(raw&255)>1||got!=wanted||!canaries(observed)){fprintf(stderr,\"row=%d offset=%%u mask=%%llx raw=%%llx LLVM=%%u expected=%%u\\n\",offset,(unsigned long long)b,(unsigned long long)raw,got,wanted);return 1;}}\n", row.address, row.test, index, row.bits, row.condition, index, index)
	}
	driver := `#include <stdint.h>
#include <stdio.h>
` + originals.String() + prototypes.String() + `
static int canaries(const uint64_t *p) {
    return p[0]==UINT64_C(0x5a5a5a5a5a5a5a5a)&&p[1]==p[0]&&
        p[2]==UINT64_C(0x6b6b6b6b6b6b6b6b)&&p[3]==p[2]&&
        p[4]==UINT64_C(0x123456789abcdef0)&&p[5]==UINT64_C(0xfedcba9876543210)&&p[6]==UINT64_C(0x876543210fedcba9);
}
static unsigned predicate(uint64_t r,unsigned bits,unsigned condition) {
    if(bits<64)r&=(UINT64_C(1)<<bits)-1;
    unsigned zf=r==0,sf=(r>>(bits-1))&1;
    uint8_t parity=r;parity^=parity>>4;parity^=parity>>2;parity^=parity>>1;
    unsigned pf=(parity&1)==0;
    /* TEST fixes CF/OF to zero, defines Z/S/P, and leaves AF undefined. */
    unsigned want[]={1,0,zf,!sf,!zf&&!sf,!zf,zf||sf,zf,sf,sf,!zf,1,0,!pf,!sf,pf};
    return want[condition];
}
int main(void) {
    unsigned char arena[8192+32];
    for(unsigned i=0;i<sizeof arena;i++)arena[i]=(unsigned char)(i*37+11);
    const uint64_t masks[]={0,1,15,UINT64_C(0xff0),UINT64_C(0x8000),UINT64_C(0x80000000),UINT64_C(0x8000000000000000),UINT64_MAX};
    for(unsigned offset=0;offset<4096;offset+=17)for(unsigned sample=0;sample<8;sample++){
        void *p=&arena[offset];uint64_t a=(uintptr_t)p,b=masks[sample];
` + checks.String() + `
    }
    for(unsigned i=0;i<sizeof arena;i++)if(arena[i]!=(unsigned char)(i*37+11))return 2;
    puts("actual same caller pointer; complete original encoder bytes and LLVM TEST/address predicates; raw upper bytes, stack/GP and whole arena canaries; explicit i1-to-i32 only");
    return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), "amd64", execution.triple, api)
		if err != nil {
			t.Fatal(api, err)
		}
		for _, optimized := range []bool{false, true} {
			input, level := ir+wrappers.String(), "-O0"
			if optimized {
				input, level = x86MulDivRoundOptimize(t, input), "-O2"
			}
			t.Logf("%s/%s: %s", api, level, execution.compileAndRunLLVM(t, "caller-address", input, driver, level))
		}
	}
}

func TestCrossLinuxRuntimeMatrixGoX86CallerAddressABI0Representation(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	assembly := `TEXT ·Address(SB),4,$0-20
MOVQ p+0(FP),AX
ADDQ $16,AX
TESTW $0xff0,AX
SETEQ DX
MOVBLZX DX,DX
MOVL DX,ret+16(FP)
RET
TEXT ·Observe(SB),4,$32-40
MOVQ p+0(FP),AX
MOVQ AX,0(SP)
MOVQ n+8(FP),AX
MOVQ AX,8(SP)
MOVQ $0x5a5a5a5a5a5a5a5a,AX
MOVQ AX,16(SP)
MOVQ $0x6b6b6b6b6b6b6b6b,AX
MOVQ AX,24(SP)
CALL ·Address(SB)
MOVQ 16(SP),AX
MOVQ AX,raw+16(FP)
MOVQ 24(SP),AX
MOVQ AX,adjacent+24(FP)
MOVQ 0(SP),AX
MOVQ AX,input+32(FP)
RET
`
	declarations := "func Address(p *byte,n uintptr) uint32\nfunc Observe(p *byte,n uintptr)(raw,adjacent,input uintptr)\n"
	oracle := `package framefixture
import("testing";"unsafe")
func TestOriginal(t *testing.T){
    var arena [8192]byte;for i:=range arena{arena[i]=byte(i*37+11)}
    seen:=uint8(0)
    for offset:=0;offset<4096;offset++{
        p:=&arena[offset];address:=uintptr(unsafe.Pointer(p));want:=uintptr(0)
        if (address+16)&0xff0==0{want=1};seen|=1<<want
        if Address(p,0)!=uint32(want){t.Fatalf("actual ABI0 pointer caller offset %d",offset)}
        raw,adjacent,input:=Observe(p,0)
        if raw!=0x5a5a5a5a00000000|want||adjacent!=0x6b6b6b6b6b6b6b6b||input!=address{t.Fatalf("raw result/stack/input canaries offset %d: %x %x %x",offset,raw,adjacent,input)}
    }
    if seen!=3{t.Fatal("page predicate lacks both real-address outcomes")}
    for i,value:=range arena{if value!=byte(i*37+11){t.Fatal("address-only source changed caller memory")}}
}
`
	fixedLocalPackedRunOriginal(t, execution, assembly, declarations, oracle, true)
}
