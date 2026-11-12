package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

var amd64RegisterBoolConditions = strings.Fields("SETCC SETCS SETEQ SETGE SETGT SETHI SETLE SETLS SETLT SETMI SETNE SETOC SETOS SETPC SETPL SETPS")

// This encoder fixture needs Go's explicit standalone runtime assembler
// permission for an ABIInternal selector. It is NOT a captured SDK source or
// an authenticated native Go caller. The complete original function bytes are
// executed below through an independently declared AX/BX adapter.
func amd64RegisterBoolOriginalBytes(t *testing.T, source string) []byte {
	t.Helper()
	dir := t.TempDir()
	input, object := filepath.Join(dir, "original.s"), filepath.Join(dir, "original.o")
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	args := append(arm64ClosureGoAsmArgs(t), "-S", "-o", object, input)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "go", args...)
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "GOTOOLCHAIN=local", "GOFLAGS=")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if failure := goAssemblerOracleOutcome(input, object, output, err, ctx.Err(), true, "amd64"); failure != nil {
		t.Fatalf("complete original Go ABIInternal encoder fixture: %v\n%s", failure, output)
	}
	size := -1
	var code []byte
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if strings.Contains(line, " STEXT ") {
			if size != -1 {
				t.Fatal("encoder fixture must retain exactly one complete function")
			}
			for _, field := range fields {
				if strings.HasPrefix(field, "size=") {
					size, err = strconv.Atoi(strings.TrimPrefix(field, "size="))
					if err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		if len(fields) >= 1 && fields[0] == "rel" {
			t.Fatal("standalone byte execution cannot invent an external relocation", line)
		}
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "0x") || len(fields[1]) != 2 {
			continue
		}
		offset, err := strconv.ParseUint(fields[0][2:], 16, 32)
		if err != nil || int(offset) != len(code) {
			t.Fatal("incomplete/noncontiguous original function bytes", line)
		}
		for index, field := range fields[1:] {
			if index == 16 || len(field) != 2 {
				break
			}
			value, err := strconv.ParseUint(field, 16, 8)
			if err != nil {
				break
			}
			code = append(code, byte(value))
		}
	}
	if size <= 0 || len(code) != size {
		t.Fatalf("original function byte extent: got %d, actual STEXT size %d", len(code), size)
	}
	return code
}

func amd64RegisterBoolOriginalAdapter(t *testing.T, triple string, index int, source string) string {
	t.Helper()
	var encoded []string
	for _, value := range amd64RegisterBoolOriginalBytes(t, source) {
		encoded = append(encoded, fmt.Sprintf("0x%02x", value))
	}
	prefix, inputA, inputB, observations := "", "%rdi", "%rsi", "%rdx"
	if strings.Contains(triple, "darwin") {
		prefix = "_"
	}
	if strings.Contains(triple, "windows") {
		inputA, inputB, observations = "%rcx", "%rdx", "%r8"
	}
	core, adapter := fmt.Sprintf("%sOriginalBody%d", prefix, index), fmt.Sprintf("%sOriginal%d", prefix, index)
	// C preserves RBX/R12-R15; the fixture uses only AX/BX/CX/DX. Observe
	// untouched stack words and independent GP canaries, not unspecified AX
	// upper bytes interpreted as a bool or a physical Go entry guarantee.
	text := ".text\n" + core + ":\n.byte " + strings.Join(encoded, ",") + "\n.globl " + adapter + "\n" + adapter + ":\n" +
		"pushq %rbx\npushq %r12\npushq %r13\npushq %r14\npushq %r15\nsubq $32,%rsp\n" +
		"movq " + observations + ",%r12\nmovq " + inputA + ",%rax\nmovq " + inputB + ",%rbx\n" +
		"movabsq $0x123456789abcdef0,%r13\nmovabsq $0xfedcba9876543210,%r14\nmovabsq $0x876543210fedcba9,%r15\n" +
		"movabsq $0x5a5a5a5a5a5a5a5a,%r10\nmovq %r10,0(%rsp)\nmovq %r10,8(%rsp)\n" +
		"movabsq $0x6b6b6b6b6b6b6b6b,%r10\nmovq %r10,16(%rsp)\nmovq %r10,24(%rsp)\ncallq " + core + "\n" +
		"movq 0(%rsp),%r10\nmovq %r10,0(%r12)\nmovq 8(%rsp),%r10\nmovq %r10,8(%r12)\n" +
		"movq 16(%rsp),%r10\nmovq %r10,16(%r12)\nmovq 24(%rsp),%r10\nmovq %r10,24(%r12)\n" +
		"movq %r13,32(%r12)\nmovq %r14,40(%r12)\nmovq %r15,48(%r12)\n" +
		"addq $32,%rsp\npopq %r15\npopq %r14\npopq %r13\npopq %r12\npopq %rbx\nretq\n"
	return fmt.Sprintf("__asm__(%q);\nextern uint64_t Original%d(uint64_t,uint64_t,uint64_t*);\n", text, index)
}

func TestAMD64RegisterBoolThreeTargetOriginalAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	var bodies []string
	for _, op := range amd64RegisterBoolConditions {
		bodies = append(bodies, "CMPQ AX,BX\n"+op+" AX")
	}
	for op := range amd64ScalarExtensionMoveSpecs {
		bodies = append(bodies, "MOVQ $257,CX\n"+string(op)+" CX,AX")
	}
	for op := range x86ConditionalMoveSpecs {
		bodies = append(bodies, "CMPQ AX,BX\nMOVQ $1,CX\nMOVQ $0,AX\n"+string(op)+" CX,AX")
	}
	for _, alias := range []string{"MOVQ", "MOVD", "MOVDQ2Q"} {
		bodies = append(bodies, alias+" $257,AX")
	}
	var source, declarations strings.Builder
	for index, body := range bodies {
		name := fmt.Sprintf("Bool%d", index)
		source.WriteString(strings.ReplaceAll(amd64RegisterBoolSource(body), "·view", "·"+name))
		fmt.Fprintf(&declarations, "func %s(a,b uint64) bool\n", name)
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
				x86ResultInitializationObject(t, llc, triple, input, "register-bool")
			}
		}
	}
	t.Log("all16 SETcc, all14 extensions, all48 CMOV rows and all3 MOVQ source spellings; full originals, three APIs/targets and O0/O2 objects")
}

func TestCrossLinuxRuntimeMatrixAMD64RegisterCanonicalBoolInstructionBytes(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	var source, declarations, originals, wrappers, prototypes, checks strings.Builder
	type fixture struct{ body, expected string }
	var rows []fixture
	for index, op := range amd64RegisterBoolConditions {
		rows = append(rows, fixture{"CMPQ AX,BX\n" + op + " AX", fmt.Sprintf("(a&~UINT64_C(255))|want[%d]", index)})
	}
	rows = append(rows, []fixture{
		{"MOVB $0,AX", "a&~UINT64_C(255)"}, {"MOVB $1,AX", "(a&~UINT64_C(255))|1"},
		{"MOVW $257,AX", "(a&~UINT64_C(65535))|257"}, {"MOVL $257,AX", "257"},
		{"MOVQ $257,AX", "257"}, {"MOVD $257,AX", "257"}, {"MOVDQ2Q $257,AX", "257"},
		{"XORQ AX,AX", "0"}, {"ANDQ $1,AX", "a&1"}, {"ANDB $1,AX", "(a&~UINT64_C(255))|(a&1)"},
		{"CMPQ AX,BX\nSETNE BX\nMOVB BX,AX", "(a&~UINT64_C(255))|want[10]"},
		{"CMPQ AX,BX\nSETEQ BX\nMOVBQZX BX,AX", "want[2]"},
		{"MOVB $1,CH\nMOVB CH,AL", "(a&~UINT64_C(255))|1"},
		{"MOVW $257,CX\nMOVB CH,AL", "(a&~UINT64_C(255))|1"},
		{"MOVB $0,CX\nMOVB $1,DX\nORB DX,CX\nMOVB CX,AX", "(a&~UINT64_C(255))|1"},
		{"MOVB $2,AX\nANDB $1,AX", "a&~UINT64_C(255)"},
	}...)
	for index, row := range rows {
		name := fmt.Sprintf("Bool%d", index)
		original := strings.ReplaceAll(amd64RegisterBoolSource(row.body), "·view", "·"+name)
		source.WriteString(original)
		fmt.Fprintf(&declarations, "func %s(a,b uint64) bool\n", name)
		originals.WriteString(amd64RegisterBoolOriginalAdapter(t, execution.triple, index, original))
		fmt.Fprintf(&wrappers, "\ndefine i32 @Probe%d(i64 %%a,i64 %%b) {\n %%v=call i1 @%s(i64 %%a,i64 %%b)\n %%r=zext i1 %%v to i32\n ret i32 %%r\n}\n", index, name)
		fmt.Fprintf(&prototypes, "extern uint32_t Probe%d(uint64_t,uint64_t);\n", index)
		fmt.Fprintf(&checks, "{uint64_t observed[7]={0},raw=Original%d(a,b,observed),expected=%s;uint32_t logical=Probe%d(a,b);\n"+
			"if(raw!=expected || (raw&255)>1 || logical!=(raw&255) || !canaries(observed)){fprintf(stderr,\"row=%d a=%%llx b=%%llx raw=%%llx expected=%%llx LLVM=%%u\\n\",(unsigned long long)a,(unsigned long long)b,(unsigned long long)raw,(unsigned long long)expected,logical);return 1;}}\n", index, row.expected, index, index)
	}
	// Noncanonical bytes are genuinely executed only by the raw observer.
	// They must remain Context for every logical translator API, not be
	// compared after lossy truncation to i1 (2->0, 3->1).
	for offset, value := range []int{2, 3, 255} {
		index := len(rows) + offset
		original := amd64RegisterBoolSource(fmt.Sprintf("MOVB $%d,AX", value))
		originals.WriteString(amd64RegisterBoolOriginalAdapter(t, execution.triple, index, original))
		fmt.Fprintf(&checks, "{uint64_t observed[7]={0},raw=Original%d(a,b,observed);if(raw!=((a&~UINT64_C(255))|%d) || !canaries(observed))return 2;}\n", index, value)
	}
	driver := `#include <stdint.h>
#include <stdio.h>
` + originals.String() + prototypes.String() + `
static int canaries(const uint64_t *p) {
    return p[0]==UINT64_C(0x5a5a5a5a5a5a5a5a)&&p[1]==p[0]&&
        p[2]==UINT64_C(0x6b6b6b6b6b6b6b6b)&&p[3]==p[2]&&
        p[4]==UINT64_C(0x123456789abcdef0)&&p[5]==UINT64_C(0xfedcba9876543210)&&
        p[6]==UINT64_C(0x876543210fedcba9);
}
int main(void) {
    const uint64_t inputs[]={0,1,2,3,UINT64_C(0x8000000000000000),UINT64_C(0x7fffffffffffffff),UINT64_MAX};
    unsigned seen[16]={0};
    for(unsigned sample=0;sample<7;sample++) for(uint64_t b=0;b<4;b++) {
        uint64_t a=inputs[sample],r=a-b;
        unsigned cf=a<b,zf=r==0,sf=r>>63,of=((a^b)&(a^r))>>63;
        uint8_t parity=r;parity^=parity>>4;parity^=parity>>2;parity^=parity>>1;
        unsigned pf=(parity&1)==0;
        unsigned want[]={!cf,cf,zf,sf==of,!zf&&sf==of,!cf&&!zf,zf||sf!=of,cf||zf,sf!=of,sf,!zf,!of,of,!pf,!sf,pf};
        for(unsigned i=0;i<16;i++)seen[i]|=1U<<want[i];
` + checks.String() + `
    }
    for(unsigned i=0;i<16;i++) if(seen[i]!=3)return 3;
    puts("complete Go encoder bytes/AX-BX adapter; canonical low byte, raw upper bytes and stack/GP canaries; LLVM i1-to-i32 only");
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
			t.Logf("%s/%s: %s", api, level, execution.compileAndRunLLVM(t, "register-canonical-bool", input, driver, level))
		}
	}
	t.Log("32 canonical functions x 28 inputs x 3 APIs x O0/O2; all16 conditions both outcomes; three noncanonical raw-byte controls. Not a native Go caller/C _Bool ABI certificate.")
}

func TestCrossLinuxRuntimeMatrixGoAMD64CanonicalBoolByteRepresentation(t *testing.T) {
	execution := x86FloatCompareRuntimeTools(t, x86FloatCompareSSE)
	var assembly, declarations, rows strings.Builder
	for index, op := range amd64RegisterBoolConditions {
		fmt.Fprintf(&assembly, "TEXT ·Bool%d(SB),4,$0-17\nMOVQ a+0(FP),AX\nMOVQ b+8(FP),BX\nCMPQ AX,BX\n%s CX\nMOVB CX,ret+16(FP)\nRET\n", index, op)
		fmt.Fprintf(&declarations, "func Bool%d(a,b uint64) bool\n", index)
		fmt.Fprintf(&rows, "{Bool%d,Observe%d},\n", index, index)
	}
	for index, value := range []int{2, 3, 255} {
		fmt.Fprintf(&assembly, "TEXT ·Bool%d(SB),4,$0-17\nMOVB $%d,ret+16(FP)\nRET\n", 16+index, value)
		fmt.Fprintf(&declarations, "func Bool%d(a,b uint64) bool\n", 16+index)
	}
	for index := 0; index < 19; index++ {
		fmt.Fprintf(&declarations, "func Observe%d(a,b uint64)(raw,adjacent,input uint64)\n", index)
		fmt.Fprintf(&assembly, `TEXT ·Observe%d(SB),4,$32-40
MOVQ a+0(FP),AX
MOVQ AX,0(SP)
MOVQ b+8(FP),AX
MOVQ AX,8(SP)
MOVQ $0x5a5a5a5a5a5a5a5a,AX
MOVQ AX,16(SP)
MOVQ $0x6b6b6b6b6b6b6b6b,AX
MOVQ AX,24(SP)
CALL ·Bool%d(SB)
MOVQ 16(SP),AX
MOVQ AX,raw+16(FP)
MOVQ 24(SP),AX
MOVQ AX,adjacent+24(FP)
MOVQ 0(SP),AX
MOVQ AX,input+32(FP)
RET
`, index, index)
	}
	oracle := `package framefixture
import "testing"
func TestOriginal(t *testing.T) {
    rows:=[]struct{call func(uint64,uint64)bool;observe func(uint64,uint64)(uint64,uint64,uint64)}{
` + rows.String() + `}
    inputs:=[]uint64{0,1,2,3,1<<63,(1<<63)-1,^uint64(0)}
    seen:=[16]uint8{}
    for _,a:=range inputs {for b:=uint64(0);b<4;b++ {
        r:=a-b;cf,zf,sf:=a<b,r==0,r>>63!=0;of:=((a^b)&(a^r))>>63!=0
        parity:=byte(r);parity^=parity>>4;parity^=parity>>2;parity^=parity>>1;pf:=parity&1==0
        want:=[]bool{!cf,cf,zf,sf==of,!zf&&sf==of,!cf&&!zf,zf||sf!=of,cf||zf,sf!=of,sf,!zf,!of,of,!pf,!sf,pf}
        for i,row:=range rows {
            expected:=uint64(0);if want[i]{expected=1}
            if row.call(a,b)!=want[i]{t.Fatalf("canonical Go bool caller row %d",i)}
            raw,adjacent,input:=row.observe(a,b)
            if raw!=0x5a5a5a5a5a5a5a00|expected||adjacent!=0x6b6b6b6b6b6b6b6b||input!=a{t.Fatalf("raw bool byte/canaries row %d: %x %x %x",i,raw,adjacent,input)}
            seen[i]|=1<<expected
        }
        for i,observe:=range []func(uint64,uint64)(uint64,uint64,uint64){Observe16,Observe17,Observe18}{
            raw,adjacent,input:=observe(a,b);value:=[]uint64{2,3,255}[i]
            if raw!=0x5a5a5a5a5a5a5a00|value||adjacent!=0x6b6b6b6b6b6b6b6b||input!=a{t.Fatal("noncanonical raw byte was normalized")}
        }
    }}
    for i,outcomes:=range seen{if outcomes!=3{t.Fatalf("SETcc row %d lacks both outcomes",i)}}
}
`
	fixedLocalPackedRunOriginal(t, execution, assembly.String(), declarations.String(), oracle, true)
	t.Logf("actual %s/amd64 owned Go ABI0 bool caller/return-byte representation; all16 SETcc outcomes and 2/3/255 raw-byte controls. Separate from ABIInternal caller authorization.", runtime.GOOS)
}
