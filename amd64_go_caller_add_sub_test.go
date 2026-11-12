package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestX86GoCallerFloatAddSubOriginalSourceReachesObjects(t *testing.T) {
	for _, fixture := range []struct {
		name string
		body string
	}{
		{"original VADDPS LONG", "VMOVUPS (DI),Y2\nVMOVUPS (SI),Y3\nLONG $0xd358ecc5\nVMOVSS X2,(DX)"},
		{"named VADDPS", "VMOVUPS (DI),Y2\nVMOVUPS (SI),Y3\nVADDPS Y3,Y2,Y2\nVMOVSS X2,(DX)"},
		{"original VSUBSS family", "VMOVUPS (DI),X0\nVMOVUPS (SI),X1\nVSUBSS X0,X1,X2\nVMOVSS X2,(DX)"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", fixture.body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestX86GoCallerFloatAddSubWholeFamilyByteEffects(t *testing.T) {
	for _, row := range x86FloatAddSubFormats("amd64") {
		if strings.Contains(row, "(AX)") || strings.Contains(row, "8(AX)") {
			continue
		}
		file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		ins := file.Funcs[0].Instrs[1]
		form, recognized, err := x86FloatAddSubProperties(ins, "amd64")
		if !recognized || err != nil || !x86CallerVectorMoveKnown(ins) {
			t.Fatalf("missing shared family effect %s: %v", row, err)
		}
		for _, missing := range []int{-1, form.first, form.second, form.destination, 4} {
			state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": ^uint64(0), "Z1": ^uint64(0), "Z2": ^uint64(0)}, masks: map[Reg]bool{"K1": true}}
			if missing >= 0 && missing < len(ins.Args) && ins.Args[missing].Kind == OpReg {
				state.vectors[x86CallerVectorRoot(ins.Args[missing].Reg)] &^= 1
			}
			if missing == 4 {
				state.masks["K1"] = false
			}
			before, beforeMasks := x86CloneCallerVectorState(state.vectors, state.masks)
			accepted := x86CallerFloatAddSubStep(&ins, form, &state, nil)
			want := missing == -1 || missing == form.destination && !form.spec.legacy && (form.mask < 0 || form.zeroing) || missing == 4 && form.mask < 0
			if accepted != want || !reflect.DeepEqual(state.masks, beforeMasks) || !accepted && !reflect.DeepEqual(state.vectors, before) {
				t.Fatalf("%s missing %d: %t want %t, invented numerical/mask evidence", row, missing, accepted, want)
			}
		}
		width := int64(form.byteWidth)
		if form.spec.scalar {
			width = int64(form.spec.bits / 8)
		}
		low := x86CallerVectorByteMask(width)
		for _, old := range []uint64{0, 0xff00, 0xff00000000, ^uint64(0)} {
			state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": low, "Z1": low | old, "Z2": low | old}, masks: map[Reg]bool{"K1": true}}
			if !x86CallerFloatAddSubStep(&ins, form, &state, nil) {
				t.Fatalf("low arithmetic requires unrelated unknown bytes: %s", row)
			}
			destination := x86CallerVectorRoot(ins.Args[form.destination].Reg)
			want := ^uint64(0)
			if form.spec.legacy {
				want = low | old
			} else if form.spec.scalar {
				want = ^x86CallerVectorByteMask(16) | low | old&(x86CallerVectorByteMask(16)&^low)
			}
			if state.vectors[destination] != want {
				t.Fatalf("%s physical byte definitions %x want %x", row, state.vectors[destination], want)
			}
		}
	}
}

func TestX86GoCallerFloatAddSubDoesNotInventValuesOrCallerPermissions(t *testing.T) {
	for name, body := range map[string]string{
		"unknown arithmetic source":        "VADDPS X0,X1,X2\nVMOVSS X2,(DX)",
		"SUB is not an integer zero idiom": "VSUBPS X0,X0,X2\nVMOVSS X2,(DX)",
		"unknown destructive destination":  "VMOVUPS (DI),X0\nADDPS X0,X1\nVMOVSS X1,(DX)",
		"unknown merge":                    "VMOVUPS (DI),X0\nVMOVUPS (SI),X1\nKMOVQ AX,K1\nVADDPS X0,X1,K1,X2\nVMOVSS X2,(DX)",
		"unknown mask":                     "VMOVUPS (DI),X0\nVMOVUPS (SI),X1\nVADDPS.Z X0,X1,K1,X2\nVMOVSS X2,(DX)",
		"mask pointer bits":                "VMOVUPS (DI),X0\nKMOVQ DI,K1\nVSUBPS.Z X0,X0,K1,X2\nVMOVSS X2,(DX)",
		"unknown memory":                   "VMOVUPS (DI),X0\nVADDPS (BX),X0,X2\nVMOVSS X2,(DX)",
		"physical stack":                   "VMOVUPS (DI),X0\nVADDPS 0(SP),X0,X2\nVMOVSS X2,(DX)",
		"FP pointer contents":              "VMOVUPS (DI),X0\nVADDPS a+0(FP),X0,X2\nVMOVSS X2,(DX)",
		"read length as vector":            "VMOVUPS (DI),X0\nVADDPS (CX),X0,X2\nVMOVSS X2,(DX)",
		"read g":                           "VMOVUPS (DI),X0\nVADDPS (R14),X0,X2\nVMOVSS X2,(DX)",
		"wide output":                      "VMOVUPS (DI),X0\nVADDPS X0,X0,X2\nVMOVUPS X2,(DX)",
		"write input":                      "VMOVUPS (DI),X0\nVADDPS X0,X0,X2\nVMOVSS X2,(DI)",
		"unknown CFG join":                 "CMPQ AX,$0\nJE joined\nVMOVUPS (DI),X0\njoined:\nVADDPS X0,X0,X2\nVMOVSS X2,(DX)",
		"scalar unknown upper reused":      "VMOVSS (DI),X0\nVADDSS X0,X3,X2\nVADDPS X2,X2,X2\nVMOVSS X2,(DX)",
	} {
		t.Run(name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved add/sub source passed: %v", err)
			}
		})
	}
}

func TestX86GoCallerFloatAddSubAllOpcodesInitializedMemory(t *testing.T) {
	for _, opcode := range x86FloatAddSubOpcodes() {
		t.Run(opcode, func(t *testing.T) {
			args := "(DI),X1"
			destination := "X1"
			if strings.HasPrefix(opcode, "V") {
				args += ",X2"
				destination = "X2"
			}
			body := fmt.Sprintf("VMOVUPS (SI),Z1\n%s %s\nVMOVSS %s,(DX)", opcode, args, destination)
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
