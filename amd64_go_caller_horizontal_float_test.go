package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86GoCallerHorizontalFloatOriginalSourceReachesObjects(t *testing.T) {
	for _, body := range []string{
		"VMOVUPS (DI),Y0\nLONG $0xc07cffc5\nVMOVSS X0,(DX)",
		"VMOVUPS (DI),Y0\nVMOVUPS (SI),Y1\nVHADDPS Y0,Y1,Y2\nVMOVSS X2,(DX)",
		"VMOVUPS (DI),X0\nVMOVUPS (SI),X1\nHSUBPD X0,X1\nVMOVSS X1,(DX)",
	} {
		t.Run(strings.Split(body, "\n")[1], func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestX86GoCallerHorizontalFloatWholeFamilyByteEffects(t *testing.T) {
	for _, row := range x86HorizontalFloatFormats() {
		if strings.Contains(row, "(BX)") {
			continue
		}
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		form, recognized, err := x86HorizontalFloatProperties(ins, "amd64")
		if !recognized || err != nil || !x86CallerVectorMoveKnown(ins) {
			t.Fatalf("missing shared effect %s: %v", row, err)
		}
		required := x86CallerVectorByteMask(int64(form.byteWidth))
		for _, missing := range []int{-1, form.first, form.second, form.destination} {
			state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": required, "Z1": required, "Z2": 0}}
			if missing >= 0 {
				state.vectors[x86CallerVectorRoot(ins.Args[missing].Reg)] &^= uint64(1) << uint(form.byteWidth-1)
			}
			before, _ := x86CloneCallerVectorState(state.vectors, nil)
			accepted := x86CallerHorizontalFloatStep(&ins, form, &state, nil)
			want := missing == -1 || missing == form.destination && form.spec.vector
			if accepted != want || !accepted && !reflect.DeepEqual(state.vectors, before) {
				t.Fatalf("%s missing %d: %t want %t, invented high source bytes", row, missing, accepted, want)
			}
		}
		for _, upper := range []uint64{0, 0xff00000000, ^required} {
			state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": required, "Z1": required | upper, "Z2": upper}}
			if !x86CallerHorizontalFloatStep(&ins, form, &state, nil) {
				t.Fatal("fully initialized sources rejected")
			}
			want := ^uint64(0)
			if !form.spec.vector {
				want = required | upper
			}
			if got := state.vectors[x86CallerVectorRoot(ins.Args[form.destination].Reg)]; got != want {
				t.Fatalf("%s definitions %x want %x", row, got, want)
			}
		}
	}
}

func TestX86GoCallerHorizontalFloatAllOpcodesAndMemoryBounds(t *testing.T) {
	for _, row := range x86HorizontalFloatFormats() {
		memory := strings.Contains(row, "(BX)")
		legacy := !strings.HasPrefix(row, "V")
		row = strings.Replace(row, "(BX)", "(DI)", 1)
		destination := "X1"
		if !legacy {
			destination = "X2"
		}
		body := fmt.Sprintf("VMOVUPS (DI),Z0\nVMOVUPS (SI),Z1\n%s\nVMOVSS %s,(DX)", row, destination)
		assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
		requireX86GoAssemblerResult(t, "amd64", assembly, true)
		pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
		for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
			err := x86CallerCoreTranslate(t, pkg, assembly, triple)
			if legacy && memory {
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unproved legacy alignment: %s: %v", row, err)
				}
			} else if err != nil {
				t.Fatalf("%s/%s: %v", row, triple, err)
			}
		}
	}
}

func TestX86GoCallerHorizontalFloatDoesNotInventPermissions(t *testing.T) {
	for name, body := range map[string]string{
		"unknown source":                  "VHADDPS X0,X1,X2\nVMOVSS X2,(DX)",
		"not a zero idiom":                "VHSUBPS X0,X0,X2\nVMOVSS X2,(DX)",
		"unknown destructive destination": "VMOVUPS (DI),X0\nHSUBPD X0,X1\nVMOVSS X1,(DX)",
		"partially defined source":        "VMOVSS X0,X1,X2\nVMOVUPS (DI),X0\nVHADDPS X0,X2,X1\nVMOVSS X1,(DX)",
		"unknown input":                   "VMOVUPS (DI),X0\nVHADDPD (BX),X0,X1\nVMOVSS X1,(DX)",
		"physical SP":                     "VMOVUPS (DI),X0\nVHADDPS 0(SP),X0,X1\nVMOVSS X1,(DX)",
		"FP pointer bits":                 "VMOVUPS (DI),X0\nVHSUBPS a+0(FP),X0,X1\nVMOVSS X1,(DX)",
		"length as vector":                "VMOVUPS (DI),X0\nVHADDPD (CX),X0,X1\nVMOVSS X1,(DX)",
		"g as input":                      "VMOVUPS (DI),X0\nVHADDPS (R14),X0,X1\nVMOVSS X1,(DX)",
		"result wider than output":        "VMOVUPS (DI),Y0\nVHADDPS Y0,Y0,Y1\nVMOVUPS Y1,(DX)",
		"write original input":            "VMOVUPS (DI),X0\nVHADDPS X0,X0,X1\nVMOVSS X1,(DI)",
		"CFG missing incoming value":      "CMPQ AX,$0\nJE join\nVMOVUPS (DI),X0\njoin:\nVHADDPS X0,X0,X1\nVMOVSS X1,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved horizontal state passed: %v", err)
			}
		})
	}
}
