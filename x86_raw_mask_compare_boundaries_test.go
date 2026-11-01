package plan9asm

import (
	"errors"
	"reflect"
	"testing"
)

func TestX86RawMaskCompareMissingInputsCannotBorrowVoidOrBool(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, name := range []string{"VPCMPB", "VPCMPW", "VPCMPD", "VPCMPQ", "VPCMPUB", "VPCMPUW", "VPCMPUD", "VPCMPUQ"} {
			for _, operand := range []string{"X3", "(SI)"} {
				bytes := x86RawNumericalInstruction(t, "amd64", name+" $6,"+operand+",X4,K1,K2")
				source := "TEXT ·Value(SB),4,$0\n" + bytes + "RET\n"
				for _, declaration := range []string{"func Value()", "func Value(unused bool)"} {
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("raw compare acquired missing data/mask/native address through a dead result", target, name, operand, api, err)
						}
					}
				}
			}
		}
	}
}

func TestX86RawMaskCompareSelectorAndNativeAuthorityStayBound(t *testing.T) {
	bytes := x86RawNumericalInstruction(t, "amd64", "VPCMPUD.BCST $6,(SI),X4,K1,K2")
	for _, arch := range []string{"386", "amd64"} {
		file, err := Parse(ArchAMD64, "TEXT Value(SB),4,$0-0\n"+bytes+"RET\n")
		if err != nil {
			t.Fatal(err)
		}
		file, err = normalizeX86RawFile(file, arch)
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionEither}
		state.pointerGP[6], state.masks[1] = true, true
		state.writeVector(4, 64, ^uint64(0), false)
		before := state.clone()
		if accepted, known := x86ResultVectorCompareStepWithRead(ins, &state, nil, arch, false); !known || accepted || !reflect.DeepEqual(state, before) {
			t.Fatal("standalone compare query borrowed the paired native read", arch)
		}
		want := before.clone()
		want.masks[2] = true
		if accepted, known := x86LoweredImmediatePackedCompareStep(ins, &state, nil, arch); !known || !accepted || !reflect.DeepEqual(state, want) {
			t.Fatal("paired raw compare changed independent flags/pointer/vector facts", arch)
		}
		for _, mutate := range []func(*Instr){
			func(ins *Instr) { ins.Args[0].Imm = 7 },
			func(ins *Instr) { ins.Args[1].Mem.Base = DI },
			func(ins *Instr) { ins.Op = "VPCMPD.BCST" },
			func(ins *Instr) { ins.x86UnboundAddressOverride = true },
		} {
			changed := ins
			changed.Args = append([]Operand(nil), ins.Args...)
			mutate(&changed)
			state = before.clone()
			if accepted, known := x86LoweredImmediatePackedCompareStep(changed, &state, nil, arch); !known || accepted || !reflect.DeepEqual(state, before) {
				t.Fatal("changed raw selector/operand/encoding acquired a numerical continuation", arch, changed.Raw)
			}
		}
	}
}
