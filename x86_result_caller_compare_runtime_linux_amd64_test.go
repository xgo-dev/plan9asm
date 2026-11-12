//go:build linux && amd64

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// Linux AMD64 owns both required actual execution axes. Other hosts retain
// source/encoder/object coverage, not a fabricated runtime pass or tool skip.
func x86CallerCompareNativeTools(t *testing.T) x86FloatCompareExecution {
	t.Helper()
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 native Linux AMD64 tools required")
	}
	return x86FloatCompareExecution{llc: llc, triple: "x86_64-unknown-linux-gnu",
		compiler: []string{clang, "-target", "x86_64-unknown-linux-gnu"}}
}

func TestCrossLinuxRuntimeMatrixX86CallerAddressCMPInstructionBytesAndLLVM(t *testing.T) {
	execution := x86CallerCompareNativeTools(t)
	source, declarations := x86CallerCompareSources()
	var originals, wrappers, prototypes, checks strings.Builder
	for index, row := range x86CallerCompareRows() {
		name := fmt.Sprintf("Compare%d", index)
		original := strings.ReplaceAll(x86CallerAddressRegisterSource(row.body), "·view", "·"+name)
		originals.WriteString(amd64RegisterBoolOriginalAdapter(t, execution.triple, index, original))
		fmt.Fprintf(&wrappers, "\ndefine i32 @Probe%d(ptr %%p,ptr %%q) {\n %%v=call i1 @%s(ptr %%p,ptr %%q)\n %%r=zext i1 %%v to i32\n ret i32 %%r\n}\n", index, name)
		fmt.Fprintf(&prototypes, "extern uint32_t Probe%d(void*,void*);\n", index)
		right := row.right
		if row.bits == 64 && right != "a" && right != "b" && right != "b>>8" {
			right = "(uint64_t)(int64_t)(int32_t)(uint32_t)(" + right + ")"
		}
		fmt.Fprintf(&checks, "{uint64_t observed[7]={0},raw=Original%d(a,b,observed);unsigned want=predicate(%s,%s,%d,%d);uint32_t got=Probe%d(p,q);\n"+
			"if(raw!=(((%s)&~UINT64_C(255))|want)||(raw&255)>1||got!=want||!canaries(observed)){fprintf(stderr,\"row=%d offset=%%u other=%%u raw=%%llx LLVM=%%u expected=%%u\\n\",offset,other,(unsigned long long)raw,got,want);return 1;}}\n",
			index, row.left, right, row.bits, row.condition, index, row.rawBase, index)
	}
	driver := `#include <stdint.h>
#include <stdio.h>
` + originals.String() + prototypes.String() + `
static int canaries(const uint64_t *p) {
    return p[0]==UINT64_C(0x5a5a5a5a5a5a5a5a)&&p[1]==p[0]&&
        p[2]==UINT64_C(0x6b6b6b6b6b6b6b6b)&&p[3]==p[2]&&
        p[4]==UINT64_C(0x123456789abcdef0)&&p[5]==UINT64_C(0xfedcba9876543210)&&p[6]==UINT64_C(0x876543210fedcba9);
}
static unsigned predicate(uint64_t a,uint64_t b,unsigned bits,unsigned condition) {
    uint64_t mask=bits==64?UINT64_MAX:(UINT64_C(1)<<bits)-1;
    a&=mask;b&=mask;uint64_t r=(a-b)&mask;
    unsigned cf=a<b,zf=r==0,sf=(r>>(bits-1))&1,of=(((a^b)&(a^r))>>(bits-1))&1;
    uint8_t parity=r;parity^=parity>>4;parity^=parity>>2;parity^=parity>>1;
    unsigned pf=(parity&1)==0;
    unsigned want[]={!cf,cf,zf,sf==of,!zf&&sf==of,!cf&&!zf,zf||sf!=of,cf||zf,sf!=of,sf,!zf,!of,of,!pf,!sf,pf};
    return want[condition];
}
int main(void) {
    unsigned char arena[8192+32];
    for(unsigned i=0;i<sizeof arena;i++)arena[i]=(unsigned char)(i*37+11);
    const unsigned deltas[]={0,1,127,128,255,256,4095,8191};
    for(unsigned offset=0;offset<4096;offset+=17)for(unsigned sample=0;sample<8;sample++){
        unsigned other=(offset+deltas[sample])&8191;
        void *p=&arena[offset],*q=&arena[other];uint64_t a=(uintptr_t)p,b=(uintptr_t)q;
` + checks.String() + `
    }
    for(unsigned i=0;i<sizeof arena;i++)if(arena[i]!=(unsigned char)(i*37+11))return 2;
    puts("actual caller pointers; complete original Go CMP bytes vs LLVM three APIs/O0/O2; physical aliases/immediates/all SETcc; raw upper-byte, stack/GP and arena canaries");
    return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", execution.triple, api)
		if err != nil {
			t.Fatal(api, err)
		}
		for _, optimized := range []bool{false, true} {
			input, level := ir+wrappers.String(), "-O0"
			if optimized {
				input, level = x86MulDivRoundOptimize(t, input), "-O2"
			}
			t.Log(api, level, execution.compileAndRunLLVM(t, "caller-address-cmp", input, driver, level))
		}
	}
}

func TestCrossLinuxRuntimeMatrixGoX86CallerAddressCMPABI0Representation(t *testing.T) {
	execution := x86CallerCompareNativeTools(t)
	var assembly, declarations, checks strings.Builder
	for _, width := range []struct {
		name string
		bits int
	}{{"B", 8}, {"W", 16}, {"L", 32}, {"Q", 64}} {
		fmt.Fprintf(&assembly, "TEXT ·Compare%s(SB),4,$0-17\nMOVQ p+0(FP),AX\nMOVQ q+8(FP),BX\nCMP%s AX,BX\nSETEQ DX\nMOVB DX,ret+16(FP)\nRET\n", width.name, width.name)
		fmt.Fprintf(&assembly, "TEXT ·Observe%s(SB),4,$32-48\nMOVQ p+0(FP),AX\nMOVQ AX,0(SP)\nMOVQ q+8(FP),AX\nMOVQ AX,8(SP)\nMOVQ $0x5a5a5a5a5a5a5a5a,AX\nMOVQ AX,16(SP)\nMOVQ $0x6b6b6b6b6b6b6b6b,AX\nMOVQ AX,24(SP)\nCALL ·Compare%s(SB)\nMOVQ 16(SP),AX\nMOVQ AX,raw+16(FP)\nMOVQ 24(SP),AX\nMOVQ AX,adjacent+24(FP)\nMOVQ 0(SP),AX\nMOVQ AX,inputP+32(FP)\nMOVQ 8(SP),AX\nMOVQ AX,inputQ+40(FP)\nRET\n", width.name, width.name)
		fmt.Fprintf(&declarations, "func Compare%s(p,q *byte) bool\nfunc Observe%s(p,q *byte)(raw,adjacent,inputP,inputQ uintptr)\n", width.name, width.name)
		fmt.Fprintf(&checks, "{bits:=uint(%d);mask:=uint64(^uint64(0));if bits<64{mask=uint64(1)<<bits-1};want:=uintptr(0);if uint64(a)&mask==uint64(b)&mask{want=1};if Compare%s(p,q)!=(want==1){t.Fatal(\"actual Go ABI0 CMP %s\",offset,other)};raw,adjacent,inputP,inputQ:=Observe%s(p,q);if raw!=0x5a5a5a5a5a5a5a00|want||adjacent!=0x6b6b6b6b6b6b6b6b||inputP!=a||inputQ!=b{t.Fatalf(\"%s raw bool byte/stack/input canaries: %%x %%x %%x %%x\",raw,adjacent,inputP,inputQ)}}\n", width.bits, width.name, width.name, width.name, width.name)
	}
	oracle := `package framefixture
import("testing";"unsafe")
func TestOriginal(t *testing.T){
    var arena [8192]byte;for i:=range arena{arena[i]=byte(i*37+11)}
    for offset:=0;offset<4096;offset+=17{for _,delta:=range []int{0,1,127,128,255,256,4095,8191}{
        other:=(offset+delta)&8191;p,q:=&arena[offset],&arena[other];a,b:=uintptr(unsafe.Pointer(p)),uintptr(unsafe.Pointer(q))
` + checks.String() + `
    }}
    for i,value:=range arena{if value!=byte(i*37+11){t.Fatal("address-only CMP source changed caller memory")}}
}
`
	fixedLocalPackedRunOriginal(t, execution, assembly.String(), declarations.String(), oracle, true)
}
