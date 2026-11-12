package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func x86NativeLEAAddressBitsProgram(arch string) (string, string) {
	word, move, old := 8, "MOVQ", "0x1122334455667788"
	if arch == "386" {
		word, move, old = 4, "MOVL", "0x55667788"
	}
	var operations string
	for index, width := range []string{"W", "L", map[string]string{"amd64": "Q", "386": "L"}[arch]} {
		operations += fmt.Sprintf("%s $%s,AX\nLEA%s -7(SI)(DX*8),AX\n%s AX,%d(DI)\n", move, old, width, move, index*word)
	}
	source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s out+0(FP),DI\n%s base+%d(FP),SI\n"+
		"MOVL index+%d(FP),DX\nMOVL $0x7fffffff,R8\nADDL $1,R8\nSTC\n%s"+
		"SETCS %d(DI)\nSETOS %d(DI)\nSETEQ %d(DI)\nSETMI %d(DI)\nRET\n",
		2*word+4, move, move, word, 2*word, operations, 3*word, 3*word+1, 3*word+2, 3*word+3)
	if arch == "386" {
		// The scratch is an ordinary physical GP in both source modes.
		source = strings.ReplaceAll(source, "R8", "BX")
	}
	return source, "func Value(out *[40]byte,base *byte,index uint32)\n"
}

func TestX86NativeLEAAddressBitsCompleteWidthsAndTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("native LEA address-bit objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		source, declaration := x86NativeLEAAddressBitsProgram(target.arch)
		x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
				if err != nil || ir == "" {
					t.Fatal("initialized original LEA address observations rejected", err)
				}
				for _, pipeline := range []struct{ input, level string }{
					{ir, "-O0"}, {ir, "-O2"}, {x86DwordProductIROptimize(t, ir), "-O2"},
				} {
					x86PackedStringCompileObject(t, llc, target.triple, pipeline.input, pipeline.level)
				}
			})
		}
	}
}

func TestX86NativeLEAAddressBitsPortableValuesAndStatus(t *testing.T) {
	llc, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 llc/clang required")
	}
	const driver = `#include <stdint.h>
#include <string.h>
extern void Value(uint8_t *,const uint8_t *,uint32_t);
int main(void) {
    uint8_t storage[8]={0};
    const uintptr_t bases[]={(uintptr_t)storage,0,UINTPTR_MAX-3,UINT32_MAX-3};
    const uint32_t indexes[]={0,1,UINT32_MAX};
    for (unsigned b=0;b<4;b++) for (unsigned i=0;i<3;i++) {
        uint8_t out[40]; memset(out,0xa5,sizeof(out));
        Value(out,(const uint8_t*)bases[b],indexes[i]);
        uintptr_t address=bases[b]+(uintptr_t)indexes[i]*8-7;
        uintptr_t actual[3]; memcpy(actual,out,sizeof(actual));
        uintptr_t old=sizeof(uintptr_t)==8 ? UINT64_C(0x1122334455667788) : UINT32_C(0x55667788);
        uintptr_t want16=(old&~(uintptr_t)0xffff)|(address&0xffff);
        if (actual[0]!=want16 || actual[1]!=(uint32_t)address || actual[2]!=address) return 1;
        unsigned flags=3*sizeof(uintptr_t);
        if (out[flags]!=1 || out[flags+1]!=1 || out[flags+2]!=0 || out[flags+3]!=1) return 2;
        for (unsigned j=flags+4;j<sizeof(out);j++) if (out[j]!=0xa5) return 3;
    }
    return 0;
}
`
	source, declaration := x86NativeLEAAddressBitsProgram("amd64")
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", triple, api)
			if err != nil || ir == "" {
				t.Fatal("complete native-address LEA program rejected before portable value execution", err)
			}
			for _, pipeline := range []struct {
				input string
				level int
			}{
				{ir, 0}, {ir, 2}, {x86DwordProductIROptimize(t, ir), 2},
			} {
				compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "lea-address-bits", triple, pipeline.input, driver, nil, pipeline.level)
			}
		})
	}
}

func TestX86NativeLEAAddressBitsDoNotInventNumericalOrPointerFacts(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, move := int64(8), "MOVQ"
		if arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, width := range x86NumericalLEAWidths(arch) {
			t.Run(arch+"/"+width, func(t *testing.T) {
				instruction := x86ScalarLaneInstruction(t, "LEA"+width+" -7(SI)(DX*8),AX")
				initial := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionBackward}
				initial.gp[0], initial.gp[2] = 0xff, 0xff
				initial.pointerGP[6], initial.callerAddressGP[6] = true, true
				initial.pointerGP[7], initial.callerAddressGP[7] = true, true
				if x86LEAWidth(instruction.Op, arch) >= word {
					state := initial.clone()
					accepted, known := x86ResultNativeLEAAddressBitsStep(instruction, &state, nil, arch, true)
					if accepted || known || !reflect.DeepEqual(state, initial) {
						t.Fatal("narrow observation intercepted the existing complete pointer consumer")
					}
					return
				}
				for _, control := range []string{"complete", "no-leaf", "unknown-base", "unknown-index"} {
					state := initial.clone()
					if control == "unknown-base" {
						state.pointerGP[6], state.callerAddressGP[6] = false, false
					}
					if control == "unknown-index" {
						state.gp[2] = 0
					}
					before := state.clone()
					accepted, known := x86ResultNativeLEAAddressBitsStep(instruction, &state, nil, arch, control != "no-leaf")
					if !known || accepted != (control == "complete") {
						t.Fatal("native address observation invented a missing source or leaf scope", control, accepted, known)
					}
					if !accepted {
						if !reflect.DeepEqual(state, before) {
							t.Fatal("rejected address observation partially mutated state", control)
						}
						continue
					}
					if x86ResultRead(Operand{Kind: OpReg, Reg: AX}, word, &state, nil, arch) ||
						state.pointerGP[0] || state.callerAddressGP[0] || state.flags != before.flags || state.direction != before.direction {
						t.Fatal("LEA address bits became numerical, pointer or status permissions")
					}
					store := x86ScalarLaneInstruction(t, move+" AX,(DI)")
					for _, leaf := range []bool{false, true} {
						copy := state.clone()
						accepted, known := x86LoweredScalarNativeStoreWithAddressBits(store, &copy, nil, arch, leaf)
						if !known || accepted != leaf || !reflect.DeepEqual(copy, state) {
							t.Fatal("exact observation supplied a new byte or escaped its native leaf scope", leaf)
						}
					}
					empty := state.clone()
					empty.nativeLEAAddressBits = x86NativeLEAAddressBits{}
					if merged := state.intersect(empty); merged.nativeLEAAddressBits.bytes != 0 {
						t.Fatal("join retained a missing address observation")
					}
				}
			})
		}
	}
}

func TestX86NativeLEAAddressBitsCannotSurviveAConflictingWrite(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		move, triple := "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, triple = "MOVL", "i386-unknown-linux-gnu"
		}
		source, declaration := x86NativeLEAAddressBitsProgram(arch)
		for _, change := range []struct {
			instruction string
			complete    bool
		}{{"MOVB $0,AL", false}, {"MOVW $0,AX", true}, {"MOVB 1(SI),AL", false}} {
			modified := strings.Replace(source, move+" AX,0(DI)", change.instruction+"\n"+move+" AX,0(DI)", 1)
			if modified == source {
				t.Fatal("address observation control did not modify its original producer")
			}
			x86LEAActualTargetGoObject(t, arch, triple, modified)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(arch+"/"+change.instruction+"/"+api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, modified, declaration, arch, triple, api)
					if change.complete {
						if err != nil || ir == "" {
							t.Fatal("independent complete numerical overwrite lost its own bytes", err)
						}
					} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("an intervening partial write reused stale address-derived bytes", err)
					}
				})
			}
		}
	}
}

func TestX86NativeLEANarrowObserverDoesNotStealFullPointerContinuation(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, move, lea, triple := 8, "MOVQ", "LEAQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, move, lea, triple = 4, "MOVL", "LEAL", "i386-unknown-linux-gnu"
		}
		source := fmt.Sprintf("TEXT ·Value(SB),4,$0-%d\n%s out+0(FP),DI\n%s input+%d(FP),SI\n"+
			"MOVL $3,DX\n%s 1(SI)(DX*2),BX\nMOVB (BX),AX\nMOVB AX,(DI)\nRET\n", 2*word, move, move, word, lea)
		x86LEAActualTargetGoObject(t, arch, triple, source)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func Value(out,input *byte)\n", arch, triple, api)
				if err != nil || ir == "" {
					t.Fatal("narrow address observation stole the existing complete pointer continuation", err)
				}
			})
		}
	}
}
