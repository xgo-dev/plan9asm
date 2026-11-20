package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86GoCallerFloatingCompareCompleteInitializedForms(t *testing.T) {
	for _, original := range x86FloatCompareGoForms("amd64") {
		t.Run(original, func(t *testing.T) {
			row := strings.NewReplacer("8(AX)", "8(DI)", "(AX)(CX*4)", "(DI)").Replace(original)
			file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			form, recognized, err := x86FloatCompareProperties(ins, "amd64")
			if !recognized || err != nil {
				t.Fatalf("independent source form not recognized: %v", err)
			}
			body := "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVMOVUPS (SI),Z20\nVMOVUPS (SI),Z21\nKMOVQ AX,K1\n" + row
			destination := ins.Args[form.destination].Reg
			if form.maskResult {
				body += "\nKMOVD " + string(destination) + ",(DX)"
			} else {
				index, _ := amd64VectorRegisterIndex(destination, form.byteWidth)
				body += fmt.Sprintf("\nVMOVSS X%d,(DX)", index)
			}
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestX86GoCallerFloatingCompareRegisterKnowledgeAndMasks(t *testing.T) {
	rows := x86FloatCompareGoForms("amd64")
	rows = append(rows, "VCMPPS $0,Z0,Z1,K1,K1", "VCMPSS $255,X0,X1,K1,K1")
	for _, row := range rows {
		if strings.Contains(row, "(AX)") {
			continue
		}
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		form, _, err := x86FloatCompareProperties(ins, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		width := form.byteWidth
		if form.scalar {
			width = form.bits / 8
		}
		required := x86CallerVectorByteMask(int64(width))
		first, second := x86CallerVectorRoot(ins.Args[form.first].Reg), x86CallerVectorRoot(ins.Args[form.second].Reg)
		for seed := 0; seed < 64; seed++ {
			upper := uint64(seed) * 0x391072d5e64b8a0f
			state := x86SourceStackState{
				vectors: map[Reg]uint64{first: required, second: required | upper},
				masks:   map[Reg]bool{"K1": true},
			}
			if !x86CallerVectorMoveKnown(ins) || !x86CallerVectorMoveStep(&ins, &state, nil) {
				t.Fatalf("complete registered compare effect rejected %s", row)
			}
			if form.maskResult {
				if !state.masks[ins.Args[form.destination].Reg] || state.vectors[first] != required || state.vectors[second] != required|upper {
					t.Fatalf("K-result changed input vectors or required old mask contents: %s", row)
				}
				continue
			}
			want := ^uint64(0)
			if form.legacy {
				want = required | upper
			} else if form.scalar {
				want = ^x86CallerVectorByteMask(16) | required | upper&(x86CallerVectorByteMask(16)&^required)
			}
			if got := state.vectors[x86CallerVectorRoot(ins.Args[form.destination].Reg)]; got != want {
				t.Fatalf("%s seed%d defined bytes=%#x want=%#x", row, seed, got, want)
			}
		}
		for _, missing := range []int{form.first, form.second, form.mask} {
			if missing < 0 {
				continue
			}
			state := x86SourceStackState{
				vectors: map[Reg]uint64{first: required, second: required},
				masks:   map[Reg]bool{"K1": true},
			}
			if missing == form.mask {
				state.masks[ins.Args[missing].Reg] = false
			} else {
				state.vectors[x86CallerVectorRoot(ins.Args[missing].Reg)] &^= 1
			}
			vectors, masks := x86CloneCallerVectorState(state.vectors, state.masks)
			if x86CallerVectorMoveStep(&ins, &state, nil) || !reflect.DeepEqual(state.vectors, vectors) || !reflect.DeepEqual(state.masks, masks) {
				t.Fatalf("%s missing role%d invented evidence or updated partial state", row, missing)
			}
		}
	}
}

func TestX86GoCallerFloatingCompareRejectsUnprovedInputAndEnvelope(t *testing.T) {
	for name, body := range map[string]string{
		"unknown source":        "CMPPS X0,X1,$0\nVMOVSS X1,(DX)",
		"unknown mask":          "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVCMPPS $0,Z0,Z1,K1,K2\nKMOVD K2,(DX)",
		"unknown old K is read": "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nVCMPPS $0,Z0,Z1,K1,K1\nKMOVD K1,(DX)",
		"pointer mask":          "VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\nKMOVQ DI,K1\nVCMPPS $0,Z0,Z1,K1,K2\nKMOVD K2,(DX)",
		"unknown base":          "VMOVUPS (SI),X1\nCMPPS (BX),X1,$0\nVMOVSS X1,(DX)",
		"native stack":          "VMOVUPS (SI),X1\nCMPPS (SP),X1,$0\nVMOVSS X1,(DX)",
		"pointer FP":            "VMOVUPS (SI),X1\nCMPPS a+0(FP),X1,$0\nVMOVSS X1,(DX)",
		"read scalar length":    "VMOVUPS (SI),X1\nCMPPS (CX),X1,$0\nVMOVSS X1,(DX)",
		"read output":           "VMOVUPS (SI),X1\nCMPPS (DX),X1,$0\nVMOVSS X1,(DX)",
		"write source":          "VMOVUPS (DI),X0\nVMOVUPS (SI),X1\nCMPPS X0,X1,$0\nVMOVSS X1,(DI)",
		"wide output":           "VMOVUPS (DI),X0\nVMOVUPS (SI),X1\nCMPPS X0,X1,$0\nVMOVUPS X1,(DX)",
		// A VEX memory load defines zero upper bytes. Legacy register MOVSS
		// preserves X1's unknown upper bytes, which scalar VCMP copies and
		// the following packed VCMP genuinely reads.
		"unknown upper reused": "VMOVSS (DI),X0\nMOVSS X0,X1\nVCMPSS $0,X0,X1,X2\nVCMPPS $0,X2,X2,X3\nVMOVSS X3,(DX)",
		"mixed CFG":            "CMPQ AX,$0\nJE joined\nVMOVUPS (DI),X0\njoined:\nVMOVUPS (SI),X1\nCMPPS X0,X1,$0\nVMOVSS X1,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			goAssemblerOracleOutput(t, "amd64", assembly, "", true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved compare acquired caller continuation: %v", err)
			}
		})
	}
}
