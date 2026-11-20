package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type x86ScalarMoveExpectedAxes struct {
	operands, suffix string
	memory, upper    int
	mask             int
	write, zero      bool
}

func TestAMD64ScalarVectorMoveGrammarCompleteGoFamilies(t *testing.T) {
	want := map[Op]amd64ScalarVectorMoveSpec{
		"MOVSS": {bits: 32, legacy: true}, "MOVSD": {bits: 64, legacy: true},
		"VMOVSS": {bits: 32}, "VMOVSD": {bits: 64},
		"VMOVSH": {bits: 16, rawOnly: true},
	}
	if !reflect.DeepEqual(amd64ScalarVectorMoveSpecs, want) {
		t.Fatalf("scalar move family differs from yxmov / _yvmovsd plus the distinct raw FP16 family: %+v", amd64ScalarVectorMoveSpecs)
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"MOVSS", "MOVSD", "VMOVSS", "VMOVSD"} {
			legacy := !strings.HasPrefix(op, "V")
			forms := []x86ScalarMoveExpectedAxes{
				{operands: "(AX),X1", memory: 0, upper: -1, mask: -1},
				{operands: "X1,(AX)", memory: 1, write: true, upper: -1, mask: -1},
			}
			if legacy {
				forms = append(forms, x86ScalarMoveExpectedAxes{operands: "X1,X7", memory: -1, upper: -1, mask: -1})
			} else {
				forms = append(forms,
					x86ScalarMoveExpectedAxes{operands: "X1,X2,X31", memory: -1, upper: 1, mask: -1},
					x86ScalarMoveExpectedAxes{operands: "(AX),K7,X31", memory: 0, upper: -1, mask: 1},
					x86ScalarMoveExpectedAxes{operands: "(AX),K7,X31", suffix: ".Z", memory: 0, upper: -1, mask: 1, zero: true},
					x86ScalarMoveExpectedAxes{operands: "X31,K7,(AX)", memory: 2, write: true, upper: -1, mask: 1})
				if arch == "amd64" {
					forms = append(forms,
						x86ScalarMoveExpectedAxes{operands: "X1,X2,K7,X31", memory: -1, upper: 1, mask: 2},
						x86ScalarMoveExpectedAxes{operands: "X1,X2,K7,X31", suffix: ".Z", memory: -1, upper: 1, mask: 2, zero: true})
				}
			}
			for _, expected := range forms {
				instruction := op + expected.suffix + " " + expected.operands
				source := "TEXT forms(SB),4,$0-0\n" + instruction + "\nRET\n"
				requireX86GoAssemblerResult(t, arch, source, true)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					t.Fatal(err)
				}
				form, recognized, err := amd64ScalarVectorMoveProperties(file.Funcs[0].Instrs[1], arch)
				if !recognized || err != nil || form.memory != expected.memory || form.memoryWrite != expected.write ||
					form.upper != expected.upper || form.mask != expected.mask || form.zeroing != expected.zero {
					t.Fatalf("%s %s grammar axes = %+v / %v", arch, instruction, form, err)
				}
			}
		}
	}
}

func TestAMD64ScalarVectorMoveGrammarRejectsInvalidGoAxes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, instruction := range []string{
			"MOVSS $1,X0", "MOVSD $0,X0", "MOVSS X16,X0", "MOVSD X0,X16",
			"MOVSS.Z (AX),X0", "MOVSD Y0,X0", "MOVSS (AX),(BX)",
			"VMOVSS X0,X1", "VMOVSD.Z (AX),X0", "VMOVSS.Z X0,K1,(AX)",
			"VMOVSD (AX),K0,X0", "VMOVSS X0,X1,K0,X2", "VMOVSD Y0,X1,X2",
			"VMOVSS X0,(AX),X1", "VMOVSD.BCST (AX),X0", "VMOVSD X0,K1,X1",
		} {
			t.Run(arch+"/"+instruction, func(t *testing.T) {
				source := "TEXT forms(SB),4,$0-0\n" + instruction + "\nRET\n"
				requireX86GoAssemblerResult(t, arch, source, false)
				file, err := Parse(ArchAMD64, source)
				if err != nil {
					return
				}
				if _, _, err := amd64ScalarVectorMoveProperties(file.Funcs[0].Instrs[1], arch); err == nil {
					t.Fatalf("grammar accepted invalid %s %s", arch, instruction)
				}
				triple := "x86_64-unknown-linux-gnu"
				if arch == "386" {
					triple = "i386-unknown-linux-gnu"
				}
				if _, err := Translate(file, Options{Goarch: arch, TargetTriple: triple,
					Sigs: map[string]FuncSig{"forms": {Name: "forms", Ret: Void}},
				}); err == nil {
					t.Fatalf("lowerer accepted invalid %s %s", arch, instruction)
				}
			})
		}
	}
	for _, arch := range []string{"amd64", "386"} {
		for _, instruction := range []string{"VMOVSH (AX),X0", "MOVSS X8,X0"} {
			if instruction == "MOVSS X8,X0" && arch == "amd64" {
				continue
			}
			source := fmt.Sprintf("TEXT forms(SB),4,$0-0\n%s\nRET\n", instruction)
			requireX86GoAssemblerResult(t, arch, source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := amd64ScalarVectorMoveProperties(file.Funcs[0].Instrs[1], arch); err == nil {
				t.Fatalf("named/architecture restriction omitted for %s %s", arch, instruction)
			}
		}
	}
}
