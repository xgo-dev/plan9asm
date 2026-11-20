package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86PhysicalSPRequirePublicContext(t *testing.T, source, declarations, arch, triple string) {
	t.Helper()
	for _, api := range []string{"text", "module", "Go"} {
		if ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("private physical-SP mathematics acquired an unproved public entry/frame/return", api, err)
		}
	}
}

// Test-only direct emission. Neither this helper nor a native C call into its
// LLVM output certifies the original physical Go entry, stack or RET. SP/BP
// here are virtual integer slots and never replace LLVM's real return stack.
func x86PhysicalSPPrivateEmitter(t *testing.T, source string, signatures map[string]FuncSig, arch, triple string) string {
	t.Helper()
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	return x86ScalarFormatObjectUnit(t, file, signatures, arch, triple, 0)
}

func x86PhysicalSPRunPrivateMath(t *testing.T, execution x86FloatCompareExecution, name, ir, driver string) {
	t.Helper()
	for _, pipeline := range []struct{ name, level, ir string }{
		{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir},
		{"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
	} {
		t.Run(pipeline.name, func(t *testing.T) {
			execution.compileAndRunLLVM(t, name, pipeline.ir, driver, pipeline.level)
		})
	}
}

func TestX86PhysicalSPOriginalPrivateEmitterMath(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	leave, leaveC := x86LeaveOriginalFixture(t)
	unary, unaryC := x86UnaryOriginalFixture(t)
	for _, fixture := range []struct {
		name, source, driver string
		signature            FuncSig
	}{
		{"implicitlegacysemantics", leave, leaveC, FuncSig{Name: "implicitlegacysemantics", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: Ptr, Index: 1, Field: -1}}}}},
		{"unaryaliases", unary, unaryC, FuncSig{Name: "unaryaliases", Args: []LLVMType{Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			ir := x86PhysicalSPPrivateEmitter(t, fixture.source,
				map[string]FuncSig{fixture.name: fixture.signature}, "amd64", execution.triple)
			// Only the C symbol is adapted. Every original source instruction,
			// input value and C check above remains hash-bound and unchanged.
			driver := "#define " + fixture.name + " InstructionFormat0\n" + fixture.driver
			x86PhysicalSPRunPrivateMath(t, execution, "original-private-sp-math", ir, driver)
		})
	}
	t.Log("original LEAVE/XLAT and all 78 Ymb aliases execute only the private virtual-SP emitter mathematics; not original Go/native ABI execution")
}

func x86LeavePrivateWidthProgram(arch string) (string, map[string]FuncSig) {
	word, move, wide := 8, "MOVQ", "Q"
	if arch == "386" {
		word, move, wide = 4, "MOVL", "L"
	}
	var source strings.Builder
	signatures := make(map[string]FuncSig)
	for index, suffix := range []string{"W", wide} {
		name := fmt.Sprint("LeaveWidth", index)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s out+0(FP),DI\n%s data+%d(FP),BP\n"+
			"MOVL $0x7fffffff,DX\nADDL $1,DX\nSTC\nLEAVE%s\n%s BP,0(DI)\n%s SP,%d(DI)\n"+
			"MOVL $0,AX\nLAHF\nMOVB AH,%d(DI)\nSETOS %d(DI)\nRET\n",
			name, 2*word, move, move, word, suffix, move, move, word, 2*word, 2*word+1)
		signatures[name] = FuncSig{Name: name, Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: int64(word), Type: Ptr, Index: 1, Field: -1}}}}
	}
	return source.String(), signatures
}

func TestX86LeaveCompleteWidthsPrivateObjectsAndPublicContext(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete private LEAVE objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, signatures := x86LeavePrivateWidthProgram(target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				if ir, err := x86ScalarFPBitViewAPI(t, source, "func LeaveWidth0(out,data *byte)\nfunc LeaveWidth1(out,data *byte)", target.arch, target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("private LEAVE mathematics acquired an original physical return/frame role", api, err)
				}
			}
			ir := x86PhysicalSPPrivateEmitter(t, source, signatures, target.arch, target.triple)
			for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
				compileLLVMToObject(t, llc, target.triple, "private-leave-widths.ll", "private-leave-widths.o", text)
			}
		})
	}
}

// Mode32 is executed separately on an actual IA32 Linux counterpart. Merely
// truncating a 64-bit host C pointer would not establish its four-byte model.
func x86LeavePrivateWidthC(word int) string {
	typ := "uint64_t"
	if word == 4 {
		typ = "uint32_t"
	}
	return fmt.Sprintf(`
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef %s word;
extern void InstructionFormat0(uint8_t *,const uint8_t *);
extern void InstructionFormat1(uint8_t *,const uint8_t *);
static word read_word(const uint8_t *p,unsigned bytes) {
    word value=0;
    for(unsigned i=0;i<bytes;i++) value|=(word)p[i]<<(8*i);
    return value;
}

int main(void) {
    const uint64_t patterns[]={0,1,UINT64_C(0x8000000000008000),UINT64_MAX};
    void (*calls[])(uint8_t *,const uint8_t *)={InstructionFormat0,InstructionFormat1};
    unsigned outcomes=0;
    for(unsigned row=0;row<2;row++)
        for(unsigned sample=0;sample<4;sample++)
            for(unsigned offset=0;offset<16;offset++) {
                uint8_t data[32],before[32],out[32],want[32];
                memset(data,0xa7,sizeof(data));
                memcpy(data+offset,&patterns[sample],sizeof(word));
                memcpy(before,data,sizeof(data));
                memset(out,0xc3,sizeof(out));
                memset(want,0xc3,sizeof(want));

                unsigned bytes=row?sizeof(word):2;
                word base=(word)(uintptr_t)(data+offset);
                word mask=bytes==sizeof(word)?(word)-1:UINT16_MAX;
                word bp=(base&~mask)|(read_word(data+offset,bytes)&mask);
                word sp=base+bytes;
                memcpy(want,&bp,sizeof(word));
                memcpy(want+sizeof(word),&sp,sizeof(word));
                want[2*sizeof(word)]=0x97;
                want[2*sizeof(word)+1]=1;

                calls[row](out,data+offset);
                if(memcmp(out,want,sizeof(out))||memcmp(data,before,sizeof(data))) return 1;
                outcomes++;
            }
    if(outcomes!=128) return 2;
    puts("PRIVATE_LEAVE_128_WIDTH_VALUES_FLAGS_CANARIES_PASS");
    return 0;
}
`, typ)
}

func TestX86LeaveAMD64PrivateWidthValuesAndFlagsPortable(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	source, signatures := x86LeavePrivateWidthProgram("amd64")
	ir := x86PhysicalSPPrivateEmitter(t, source, signatures, "amd64", execution.triple)
	x86PhysicalSPRunPrivateMath(t, execution, "private-leave-amd64-values", ir, x86LeavePrivateWidthC(8))
	t.Log("two AMD64 widths use virtual SP/BP mathematics; original Go/native stack ABI is not executed")
}
