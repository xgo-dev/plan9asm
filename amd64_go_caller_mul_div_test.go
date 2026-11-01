package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestX86GoCallerFloatMulDivWholeFamilyByteEffects(t *testing.T) {
	for _, row := range x86FloatMulDivFormats("amd64") {
		if strings.Contains(row, "(AX)") {
			continue
		}
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		form, recognized, err := x86FloatMulDivProperties(ins, "amd64")
		if !recognized || err != nil || !x86CallerVectorMoveKnown(ins) {
			t.Fatalf("missing registered family effect %s: %v", row, err)
		}
		for _, missing := range []int{-1, form.first, form.second, form.destination, 4} {
			state := x86SourceStackState{
				vectors: map[Reg]uint64{"Z0": ^uint64(0), "Z1": ^uint64(0), "Z2": ^uint64(0)},
				masks:   map[Reg]bool{"K1": true},
			}
			if missing >= 0 && missing < len(ins.Args) && ins.Args[missing].Kind == OpReg {
				state.vectors[x86CallerVectorRoot(ins.Args[missing].Reg)] &^= 1
			}
			if missing == 4 {
				state.masks["K1"] = false
			}
			before, masksBefore := x86CloneCallerVectorState(state.vectors, state.masks)
			accepted := x86CallerVectorMoveStep(&ins, &state, nil)
			want := missing == -1 || missing == form.destination && !form.legacy && (form.mask < 0 || form.zeroing) || missing == 4 && form.mask < 0
			if accepted != want || !reflect.DeepEqual(state.masks, masksBefore) || !accepted && !reflect.DeepEqual(state.vectors, before) {
				t.Fatalf("%s missing %d: %t want %t, invented numerical/mask evidence", row, missing, accepted, want)
			}
		}
	}
}

func TestX86GoCallerFloatMulDivCannotInventValuesOrPermissions(t *testing.T) {
	for name, body := range map[string]string{
		"unknown source":       "VMULPS X0,X1,X2\nVMOVSS X2,(DX)",
		"division no identity": "VDIVPS X0,X0,X2\nVMOVSS X2,(DX)",
		"unknown merge":        "VMOVUPS (DI),X0\nVMOVUPS (SI),X1\nKMOVQ AX,K1\nVMULPS X0,X1,K1,X2\nVMOVSS X2,(DX)",
		"unknown mask":         "VMOVUPS (DI),X0\nVMOVUPS (SI),X1\nVDIVPS.Z X0,X1,K1,X2\nVMOVSS X2,(DX)",
		"pointer mask":         "VMOVUPS (DI),X0\nKMOVQ DI,K1\nVMULPS.Z X0,X0,K1,X2\nVMOVSS X2,(DX)",
		"physical stack":       "VMOVUPS (DI),X0\nVMULPS (SP),X0,X2\nVMOVSS X2,(DX)",
		"FP pointer":           "VMOVUPS (DI),X0\nVDIVPS a+0(FP),X0,X2\nVMOVSS X2,(DX)",
		"unknown memory":       "VMOVUPS (DI),X0\nVMULPS (R11),X0,X2\nVMOVSS X2,(DX)",
		"g read":               "VMOVUPS (DI),X0\nVDIVPS (R14),X0,X2\nVMOVSS X2,(DX)",
		"wide result":          "VMOVUPS (DI),X0\nVMULPS X0,X0,X2\nVMOVUPS X2,(DX)",
		"input write":          "VMOVUPS (DI),X0\nVDIVPS X0,X0,X2\nVMOVSS X2,(DI)",
		"unknown CFG join":     "CMPQ AX,$0\nJE joined\nVMOVUPS (DI),X0\njoined:\nVMULPS X0,X0,X2\nVMOVSS X2,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved MUL/DIV source passed: %v", err)
			}
		})
	}
}
