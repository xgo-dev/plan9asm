package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86CommutedPointerAddRegisters(arch string) []Reg {
	registers := []Reg{AX, CX, DX, BX, SI, DI}
	if arch == "386" {
		return append(registers, BP)
	}
	return append(registers, "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
}

func TestX86IncomingPointerCommutedAddRegistersAndRoles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, suffix := x86ResultPointerWord(arch), "Q"
		if arch == "386" {
			suffix = "L"
		}
		var original strings.Builder
		for _, source := range x86CommutedPointerAddRegisters(arch) {
			for _, destination := range x86CommutedPointerAddRegisters(arch) {
				fmt.Fprintf(&original, "ADD%s %s,%s\n", suffix, source, destination)
			}
		}
		requireX86GoAssemblerResult(t, arch, "TEXT ·Value(SB),4,$0-0\n"+original.String()+"RET\n", true)
		for _, source := range x86CommutedPointerAddRegisters(arch) {
			for _, destination := range x86CommutedPointerAddRegisters(arch) {
				if source == destination {
					continue // A pointer cannot simultaneously supply the NUM operand.
				}
				for _, commuted := range []bool{false, true} {
					for _, caller := range []bool{false, true} {
						name := fmt.Sprintf("%s/%s-%s/commuted%t/caller%t", arch, source, destination, commuted, caller)
						t.Run(name, func(t *testing.T) {
							ins := x86ScalarLaneInstruction(t, "ADD"+suffix+" "+string(source)+","+string(destination))
							first, _, _ := x86ResultGP(source, word, arch)
							last, mask, _ := x86ResultGP(destination, word, arch)
							pointer, number := last, first
							if commuted {
								pointer, number = first, last
							}
							state := x86ResultState{direction: x86ResultDirectionBackward}
							state.gp[number] = mask
							state.canonicalGP[number] = 1
							state.pointerGP[pointer], state.callerAddressGP[pointer] = true, caller
							if caller {
								state.callerAddressOrigin[pointer] = 1
							}
							before, want := state.clone(), state.clone()
							want.pointerGP[last], want.gp[last] = true, 0
							want.canonicalGP[last] = 0
							want.callerAddressGP[last], want.callerAddressOrigin[last] = caller, want.callerAddressOrigin[pointer]
							want.flags = x86ByteFlagsAll
							if !x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) {
								t.Fatal("full-word pointer/NUM addition rejected", ins.Raw)
							}
							state.callerAddressGP = x86ResultCallerAddressesAfterTransfer(ins, before.callerAddressGP, state.callerAddressGP, nil, arch)
							state.callerAddressOrigin = x86ResultCallerOriginsAfter(ins, before.callerAddressOrigin, state.callerAddressGP, map[int64]bool{0: true}, arch)
							if !reflect.DeepEqual(state, want) {
								t.Fatal("addition changed NUM, source, caller origin, flags or DF outside its typed footprint", state, want)
							}
						})
					}
				}
			}
		}
	}
}

func x86CommutedPointerAddBodies(arch string) []struct{ name, body string } {
	word, suffix := x86ResultPointerWord(arch), "Q"
	if arch == "386" {
		suffix = "L"
	}
	load := fmt.Sprintf("MOV%s p+0(FP),SI\nMOV%s n+%d(FP),DX\n", suffix, suffix, word)
	rows := []struct{ name, body string }{
		{"commuted register", load + "ADD" + suffix + " SI,DX\n"},
		{"commuted parameter", fmt.Sprintf("MOV%s n+%d(FP),DX\nADD%s p+0(FP),DX\n", suffix, word, suffix)},
		{"ordinary register", load + "ADD" + suffix + " DX,SI\nMOV" + suffix + " SI,DX\n"},
		{"ordinary parameter", "MOV" + suffix + " p+0(FP),DX\n" + fmt.Sprintf("ADD%s n+%d(FP),DX\n", suffix, word)},
		{"same origin join", load + "CMP" + suffix + " DX,$0\nJE alternate\nADD" + suffix + " SI,DX\nJMP joined\nalternate:\nLEA" + suffix + " (SI)(DX*1),DX\njoined:\n"},
	}
	for index := range rows {
		rows[index].body += fmt.Sprintf("SUB%s p+0(FP),DX\nMOV%s DX,ret+%d(FP)\nRET", suffix, suffix, 2*word)
	}
	return rows
}

func TestX86IncomingPointerCommutedAddWholeSource(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range x86CommutedPointerAddBodies(arch) {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value(p *byte,n uintptr) uintptr", row.body)
				requireX86GoAssemblerResult(t, arch, source, true)
				for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
					if err := check(file.Funcs[0], sig, arch); err != nil {
						t.Fatal("complete same-origin commuted address did not cancel", err)
					}
				}
			})
		}
	}
}

func TestX86IncomingPointerCommutedAddFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			assembly, declarations := x86CommutedPointerAddProgram(t, target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, assembly)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, assembly, declarations, target.arch, target.triple, api)
					if err != nil || strings.Count(ir, "define ") != 5 {
						t.Fatal("complete original pointer-add inventory rejected", err)
					}
					x86PackedStringCompileObject(t, llc, target.triple, ir, "-O0")
					x86PackedStringCompileObject(t, llc, target.triple, x86MulDivRoundOptimize(t, ir), "-O2")
				})
			}
		})
	}
}

func x86CommutedPointerAddProgram(t *testing.T, arch string) (string, string) {
	t.Helper()
	var assembly, declarations strings.Builder
	for index, row := range x86CommutedPointerAddBodies(arch) {
		_, _, _, source := x86ResultInitializationFixture(t, arch, "func Value(p *byte,n uintptr) uintptr", row.body)
		name := fmt.Sprintf("Value%d", index)
		assembly.WriteString(strings.Replace(source, "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(p *byte,n uintptr) uintptr\n", name)
	}
	return assembly.String(), declarations.String()
}

func TestX86IncomingPointerCommutedAddPortableExecution(t *testing.T) {
	execution := x86ScalarCountHostExecution(t)
	assembly, declarations := x86CommutedPointerAddProgram(t, "amd64")
	const driver = `#include <stdint.h>
extern uint64_t Value0(uint8_t*, uint64_t), Value1(uint8_t*, uint64_t);
extern uint64_t Value2(uint8_t*, uint64_t), Value3(uint8_t*, uint64_t);
extern uint64_t Value4(uint8_t*, uint64_t);
int main(void) {
    uint8_t storage[64] = {0};
    uint64_t (*functions[])(uint8_t*, uint64_t) = {Value0, Value1, Value2, Value3, Value4};
    const uint64_t offsets[] = {0, 1, 63, 64, 65, UINT64_MAX, UINT64_C(1)<<63};
    for (unsigned fn=0; fn<5; fn++)
        for (unsigned sample=0; sample<7; sample++)
            if (functions[fn](storage, offsets[sample]) != offsets[sample]) return 1;
    for (unsigned i=0; i<sizeof storage; i++) if (storage[i]) return 2;
    return 0;
}
`
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, assembly, declarations, "amd64", execution.triple, api)
			if err != nil {
				t.Fatal(err)
			}
			execution.compileAndRunLLVM(t, "commuted-pointer-add", ir, driver, "-O0")
			execution.compileAndRunLLVM(t, "commuted-pointer-add", x86MulDivRoundOptimize(t, ir), driver, "-O2")
		})
	}
}

func TestX86IncomingPointerCommutedAddBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, typ, suffix := x86ResultPointerWord(arch), "uint64", "Q"
		if arch == "386" {
			typ, suffix = "uint32", "L"
		}
		for _, row := range []struct{ name, body string }{
			{"two pointers", "MOV" + suffix + " SI,DX\nADD" + suffix + " SI,DX\n"},
			{"same pointer alias", "ADD" + suffix + " SI,SI\n"},
			{"partial add", "ADDW SI,DX\n"},
			{"reversed subtract", "SUB" + suffix + " SI,DX\n"},
			{"unknown offset", "ADD" + suffix + " SI,CX\n"},
			{"pointer as NUM", "ADD" + suffix + " SI,DX\nMOV" + suffix + " DX,ret+RESULT(FP)\nRET\n"},
			{"unproved pointee", "ADD" + suffix + " SI,DX\nMOVL (DX),AX\n"},
			{"partial pointer overwrite", "MOVW $0,SI\nADD" + suffix + " SI,DX\n"},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				body := fmt.Sprintf("MOV%s p+0(FP),SI\nMOV%s n+%d(FP),DX\n", suffix, suffix, word) + row.body
				body += fmt.Sprintf("MOV%s $0,ret+%d(FP)\nRET", suffix, 2*word)
				body = strings.ReplaceAll(body, "RESULT", fmt.Sprint(2*word))
				_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value(p *byte,n "+typ+") "+typ, body)
				requireX86GoAssemblerResult(t, arch, source, true)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("commuted addition granted another pointer or NUM contract", err)
				}
			})
		}
		for missing := int64(0); missing < word; missing++ {
			t.Run(fmt.Sprintf("%s/missing-offset-byte-%d", arch, missing), func(t *testing.T) {
				state := x86ResultState{pointerGP: [16]bool{6: true}, callerAddressGP: [16]bool{6: true}}
				state.gp[2] = uint8((1<<uint(word))-1) &^ (1 << uint(missing))
				before := state.clone()
				ins := x86ScalarLaneInstruction(t, "ADD"+suffix+" SI,DX")
				if x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(before, state) {
					t.Fatal("missing NUM input published an address or flags")
				}
			})
		}
		for _, row := range []struct {
			name   string
			mutate func(*Instr)
		}{
			{"encoded", func(ins *Instr) { ins.x86Encoded = true }},
			{"address override", func(ins *Instr) { ins.x86AddressBits = 32 }},
			{"segment", func(ins *Instr) { ins.x86SegmentPrefix = 0x64 }},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				state := x86ResultState{pointerGP: [16]bool{6: true}, callerAddressGP: [16]bool{6: true}, gp: [16]uint8{2: 0xff}}
				before := state.clone()
				ins := x86ScalarLaneInstruction(t, "ADD"+suffix+" SI,DX")
				row.mutate(&ins)
				if x86ScalarFPResultTransfer(ins, &state, nil, 0, arch) || !reflect.DeepEqual(before, state) {
					t.Fatal("named address addition borrowed an independent encoding contract")
				}
			})
		}
		t.Run(arch+"/different typed origin join", func(t *testing.T) {
			body := fmt.Sprintf("MOV%s p+0(FP),SI\nMOV%s n+%d(FP),DX\nCMP%s DX,$0\nJE alternate\n"+
				"ADD%s SI,DX\nJMP joined\nalternate:\nADD%s q+%d(FP),DX\njoined:\n"+
				"SUB%s p+0(FP),DX\nMOV%s DX,ret+%d(FP)\nRET", suffix, suffix, 2*word, suffix,
				suffix, suffix, word, suffix, suffix, 3*word)
			_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value(p,q *byte,n "+typ+") "+typ, body)
			requireX86GoAssemblerResult(t, arch, source, true)
			if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("different commuted pointer origins survived a must-join", err)
			}
		})
	}
}
