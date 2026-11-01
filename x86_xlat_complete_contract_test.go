package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func x86XLATProgram(arch string) (string, string) {
	word, move, push, pop, typ := 8, "MOVQ", "PUSHFQ", "POPQ", "uint64"
	if arch == "386" {
		word, move, push, pop, typ = 4, "MOVL", "PUSHFL", "POPL", "uint32"
	}
	var source strings.Builder
	for _, name := range []string{"XLATValue", "XLATFlags", "XLATDead"} {
		result := word
		if name == "XLATFlags" {
			result = 4
		} else if name == "XLATDead" {
			result = 0
		}
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s table+0(FP),BX\n%s input+%d(FP),AX\n",
			name, 2*word+result, move, move, word)
		if name == "XLATFlags" {
			source.WriteString("MOVL $0x7fffffff,DX\nADDL $1,DX\nSTC\n")
		}
		source.WriteString("XLAT\n")
		if name == "XLATValue" {
			fmt.Fprintf(&source, "%s AX,ret+%d(FP)\n", move, 2*word)
		} else if name == "XLATFlags" {
			fmt.Fprintf(&source, "%s\n%s CX\nANDL $0x8d5,CX\nMOVL CX,ret+%d(FP)\n", push, pop, 2*word)
		}
		source.WriteString("RET\n")
	}
	// No full AX definition: XLAT needs exactly AL for its unsigned index.
	fmt.Fprintf(&source, "TEXT ·XLATLowOnly(SB),4,$0-%d\n%s table+0(FP),BX\nMOVB $255,AL\nXLAT\nRET\n", word, move)
	declarations := fmt.Sprintf("func XLATValue(table *byte,input %s) %s\nfunc XLATFlags(table *byte,input %s) uint32\n"+
		"func XLATDead(table *byte,input %s)\nfunc XLATLowOnly(table *byte)\n", typ, typ, typ, typ)
	return source.String(), declarations
}

func TestX86XLATCompleteGoGrammarAndImplicitTypedInputs(t *testing.T) {
	table, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []string{"{AXLAT, ynone, Px, opBytes{0xd7}}", "var ynone = []ytab{\n\t{Zlit, 1, argList{}},\n}"} {
		if !strings.Contains(string(table), row) {
			t.Fatal("independent complete Go XLAT encoder/zero-operand row changed", row)
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		instruction := x86ScalarLaneInstruction(t, "XLAT")
		effect, known, err := x86TypedInstructionByteEffect(instruction.Op, instruction, arch)
		if !known || err != nil || !effect.requiresResultProof || effect.flagsRead|effect.flagsDefined|effect.flagsKilled != 0 {
			t.Fatal("XLAT lost its complete implicit AL/address/native-byte input contract", arch, effect, known, err)
		}
		al, base := false, false
		for _, operand := range effect.operands {
			al = al || operand.index == -1 && operand.operand.Kind == OpReg && operand.operand.Reg == AL &&
				operand.width == 1 && operand.read && operand.write
			base = base || operand.index == -1 && operand.operand.Kind == OpReg && operand.operand.Reg == BX &&
				operand.width == x86ResultPointerWord(arch) && operand.read && !operand.write
		}
		if !al || !base {
			t.Fatal("XLAT consumed full AX, lost AL's write or hid the implicit base", arch, effect)
		}
		for _, source := range []string{"XLAT AX", "XLAT (BX)", "XLAT.P", "XLAT.Z"} {
			instruction := x86ScalarLaneInstruction(t, source)
			if _, known, err := x86TypedInstructionByteEffect(instruction.Op, instruction, arch); !known || err == nil {
				t.Fatal("XLAT accepted a non-Go operand or suffix", source, known, err)
			}
		}
	}
}

func TestX86XLATInitializedPublicObjectsAndActualInputRevocations(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete initialized XLAT objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := x86XLATProgram(target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("legitimate initialized XLAT lost its public result/native access", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						if strings.Count(text, "load volatile i8,") != 4 {
							t.Fatal("XLAT did not retain one exact m8 read per original opcode, including Void/dead", text)
						}
						compileLLVMToObject(t, llc, target.triple, "xlat-initialized.ll", "xlat-initialized.o", text)
					}
				})
			}
			move := "MOVQ"
			if target.arch == "386" {
				move = "MOVL"
			}
			for _, mutation := range []struct{ name, before, after string }{
				{"missing AL", "MOVB $255,AL\n", ""},
				{"NUM is not pointer", move + " table+0(FP),BX\n", move + " $1,BX\n"},
				{"index is not whole AX", "MOVB $255,AL\n", "MOVB $255,AH\n"},
			} {
				changed := strings.ReplaceAll(source, mutation.before, mutation.after)
				for _, api := range []string{"text", "module", "Go"} {
					if ir, err := x86ScalarFPBitViewAPI(t, changed, declarations, target.arch, target.triple, api); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("dead XLAT invented an unsigned AL input or native table base", mutation.name, api, err)
					}
				}
			}
		})
	}
}

func TestX86XLATStandaloneDoesNotGrantNativeOrPhysicalAddressRights(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		instruction := x86ScalarLaneInstruction(t, "XLAT")
		state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
		state.gp[0], state.pointerGP[3], state.callerAddressGP[3] = 1, true, true
		before := state.clone()
		if x86ResultTransfer(instruction, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
			t.Fatal("standalone XLAT query invented a numerical native read or changed its caller", arch)
		}
		for _, restriction := range []func(*Instr){
			func(ins *Instr) { ins.x86Encoded = true },
			func(ins *Instr) { ins.x86SourceRaw = &x86SourceRawInstruction{op: ins.Op} },
			func(ins *Instr) { ins.x86AddressBits = 32 },
			func(ins *Instr) { ins.x86SegmentPrefix = 0x64 },
		} {
			changed, state := instruction, before.clone()
			restriction(&changed)
			if x86ResultTransfer(changed, &state, nil, 0, arch) || !reflect.DeepEqual(state, before) {
				t.Fatal("XLAT imported an unbound physical address/source contract", arch)
			}
		}
	}
}

func TestX86XLATAll256UnsignedIndicesUpperBytesAndFlagsPortable(t *testing.T) {
	execution, arch, typ := x86ScalarCountHostExecution(t), "amd64", "uint64_t"
	if strconv.IntSize == 32 {
		arch, typ = "386", "uint32_t"
	}
	source, declarations := x86XLATProgram(arch)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, execution.triple, api)
			if err != nil {
				t.Fatal("initialized XLAT failed before the independent complete unsigned-index oracle", err)
			}
			x86PhysicalSPRunPrivateMath(t, execution, "xlat-public-values", ir, fmt.Sprintf(x86XLATValueC, typ))
		})
	}
}

const x86XLATValueC = `
#include <stdint.h>
#include <string.h>
typedef %s word;
extern word XLATValue(const uint8_t *,word);
extern uint32_t XLATFlags(const uint8_t *,word);
extern void XLATDead(const uint8_t *,word),XLATLowOnly(const uint8_t *);

int main(void) {
    uint8_t table[256],before[256];
    for(unsigned i=0;i<256;i++) table[i]=(uint8_t)(i*73+19);
    memcpy(before,table,sizeof(table));
    const uint64_t uppers[]={0,UINT64_C(0x1122334455667700),UINT64_C(0x8000000080000000),UINT64_MAX&~UINT64_C(255)};
    for(unsigned high=0;high<4;high++)
        for(unsigned low=0;low<256;low++) {
            word input=(word)(uppers[high]|low);
            word want=(input&~(word)255)|table[low];
            if(XLATValue(table,input)!=want || XLATFlags(table,input)!=0x895) return 1;
            XLATDead(table,input);
            if(memcmp(table,before,sizeof(table))) return 2;
        }
    XLATLowOnly(table);
    return memcmp(table,before,sizeof(table))?3:0;
}
`

func TestX86XLATDeadNativeByteAccessFaults(t *testing.T) {
	execution, arch, typ := x86ScalarCountHostExecution(t), "amd64", "uint64_t"
	if strconv.IntSize == 32 {
		arch, typ = "386", "uint32_t"
	}
	source, declarations := x86XLATProgram(arch)
	driver := x86MemoryFaultDriver(fmt.Sprintf(`
extern void XLATDead(const uint8_t *,%s);
static int run_dead(const uint8_t *p) {
    XLATDead((const uint8_t *)((uintptr_t)p-255),255);
    return 0;
}
`, typ), "{run_dead,1,0},")
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, execution.triple, api)
			if err != nil {
				t.Fatal("dead XLAT failed before its independent exact-byte fault observer", err)
			}
			for _, pipeline := range []struct{ name, level, ir string }{
				{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir},
				{"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
			} {
				t.Run(pipeline.name, func(t *testing.T) {
					executable := execution.compileLLVM(t, "xlat-dead-faults", pipeline.ir, driver, pipeline.level)
					x86CheckMemoryFaultMatrix(t, execution, executable, 1)
				})
			}
		})
	}
}
