package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86GoCallerFMA3InitializedNumericalInputs(t *testing.T) {
	for _, body := range []string{
		"VMOVUPS (DI),X0\nVMOVUPS (SI),X1\nVFMADD231SS (DI),X0,X1\nVMOVSS X1,(DX)",
		"VMOVUPS (DI),Y0\nVMOVUPS (SI),Y1\nVFMADD132PS (DI),Y0,Y1\nVMOVSS X1,(DX)",
		"VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVFNMADD213PD.BCST (DI),Z0,Z1\nVMOVSS X1,(DX)",
		"VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nKMOVQ AX,K1\nVFMADDSUB231PS.Z Z0,Z0,K1,Z1\nVMOVSS X1,(DX)",
		"VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVFMSUBADD132PD.RD_SAE Z0,Z0,Z1\nVMOVSS X1,(DX)",
	} {
		t.Run(strings.ReplaceAll(body, "\n", ";"), func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestX86GoCallerFMA3CompleteFamilyRegisterEffects(t *testing.T) {
	for _, instruction := range x86FMA3NamedFormats("amd64") {
		if strings.Contains(instruction, "(AX)") {
			continue // Actual typed caller-memory/objects are checked separately.
		}
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+instruction+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		if !x86CallerVectorMoveKnown(ins) {
			t.Fatalf("complete named FMA3 format has no shared effect: %s", instruction)
		}
		form, _, err := amd64FMA3Properties(ins, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		for _, missing := range []int{-1, 0, 1, 2} {
			state := x86SourceStackState{vectors: map[Reg]uint64{
				"Z0": ^uint64(0), "Z1": ^uint64(0), "Z2": ^uint64(0),
			}, masks: map[Reg]bool{"K1": true}}
			if missing >= 0 {
				state.vectors[Reg(fmt.Sprintf("Z%d", missing))] &^= 1
			}
			before, masks := x86CloneCallerVectorState(state.vectors, state.masks)
			accepted := x86CallerFMA3Step(&ins, form, &state, nil)
			if accepted != (missing == -1) || !reflect.DeepEqual(state.masks, masks) ||
				!accepted && !reflect.DeepEqual(state.vectors, before) {
				t.Fatalf("%s missing input %d: invented numerical data or changed masks: %t/%v", instruction, missing, accepted, state.vectors)
			}
		}
	}
	for opcode, spec := range amd64FMA3Specs {
		if !spec.rawOnly {
			continue
		}
		ins := Instr{Op: opcode, x86Encoded: true, Args: []Operand{
			{Kind: OpReg, Reg: "X0"}, {Kind: OpReg, Reg: "X1"}, {Kind: OpReg, Reg: "X2"},
		}}
		if x86CallerVectorMoveKnown(ins) {
			t.Fatalf("raw-only FP16 acquired a Go-named caller contract: %s", opcode)
		}
	}
}

func TestX86GoCallerFMA3ScalarPreservesUnknownUpperXBytes(t *testing.T) {
	for _, instruction := range []string{
		"VFMADD132SS X0,X1,X2", "VFMSUB213SD.RD_SAE X0,X1,X2",
		"VFNMADD231SS.Z X0,X1,K1,X2", "VFNMSUB132SD.RU_SAE.Z X0,X1,K1,X2",
	} {
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+instruction+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		form, _, err := amd64FMA3Properties(ins, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		low := x86CallerVectorByteMask(int64(form.spec.laneBits / 8))
		for _, oldUpper := range []uint64{0, 0xff00, 0xff000, ^uint64(0)} {
			state := x86SourceStackState{vectors: map[Reg]uint64{
				"Z0": low, "Z1": low, "Z2": low | oldUpper,
			}, masks: map[Reg]bool{"K1": true}}
			if !x86CallerFMA3Step(&ins, form, &state, nil) {
				t.Fatalf("initialized low inputs incorrectly require unknown upper X data: %s", instruction)
			}
			var expected uint64
			for index := 0; index < 64; index++ {
				bit := uint64(1) << uint(index)
				if index >= 16 || index < form.spec.laneBits/8 || oldUpper&bit != 0 {
					expected |= bit
				}
			}
			if state.vectors["Z2"] != expected {
				t.Fatalf("%s changed byte %x initialization: got %x want %x", instruction, oldUpper, state.vectors["Z2"], expected)
			}
		}
	}
}

func TestX86GoCallerFMA3CannotInventNumericalInputs(t *testing.T) {
	for _, body := range []string{
		"VFMADD231SS (DI),X0,X1\nVMOVSS X1,(DX)",
		"VMOVSS (DI),X0\nVFMADD231SS X0,X0,X1\nVMOVSS X1,(DX)",
		"VMOVSS (DI),X0\nVFMADD231SS.Z X0,X0,K1,X0\nVMOVSS X0,(DX)",
		"VMOVSS (DI),X0\nKMOVQ DI,K1\nVFMADD231SS.Z X0,X0,K1,X0\nVMOVSS X0,(DX)",
		"VMOVUPS (DI),Y0\nVFMADD231PS (BX),Y0,Y0\nVMOVSS X0,(DX)",
		"VMOVUPS (DI),Y0\nVFMADD231PS a+0(FP),Y0,Y0\nVMOVSS X0,(DX)",
		"VMOVUPS (DI),Y0\nVFMADD231PS (CX),Y0,Y0\nVMOVSS X0,(DX)",
		"VMOVUPS (DI),Y0\nVFMADD231PS (R14),Y0,Y0\nVMOVSS X0,(DX)",
		"VMOVUPS (DI),Y0\nVFMADD231PS 0(SP),Y0,Y0\nVMOVSS X0,(DX)",
		"VMOVUPS (DI),Y0\nVFMADD231PS (DI),Y0,Y0\nVMOVUPS Y0,(DX)",
		"CMPQ AX,$0\nJE joined\nVMOVUPS (DI),Y0\njoined:\nVFMADD231PS (DI),Y0,Y0\nVMOVSS X0,(DX)",
	} {
		t.Run(strings.ReplaceAll(body, "\n", ";"), func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved FMA input acquired caller continuation: %v", err)
			}
		})
	}
}
