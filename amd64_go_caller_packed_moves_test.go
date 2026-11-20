package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestX86GoCallerPackedMovesPreserveNumericalInputBytes(t *testing.T) {
	for _, form := range []struct{ name, body string }{
		{"VEX input", "VMOVDQU (DI),Y0\nVMOVSS X0,(DX)"},
		{"EVEX input", "VMOVDQU8 (DI),Z31\nVMOVSS X31,(DX)"},
		{"EVEX zero mask", "KMOVQ AX,K1\nVMOVUPS.Z (DI),K1,Z0\nVMOVSS X0,(DX)"},
	} {
		t.Run(form.name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", form.body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestX86GoCallerPackedMovesCompleteFamilyRegisterCopies(t *testing.T) {
	var opcodes []string
	for opcode := range amd64PackedVectorMoveSpecs {
		opcodes = append(opcodes, string(opcode))
	}
	sort.Strings(opcodes)
	for _, opcode := range opcodes {
		spec := amd64PackedVectorMoveSpecs[Op(opcode)]
		for _, bank := range []string{"X", "Y", "Z"} {
			if bank == "Z" && spec.encoding == amd64PackedMoveVEX {
				continue
			}
			for _, mode := range []string{"unmasked", "merge", "zero"} {
				if mode != "unmasked" && spec.encoding == amd64PackedMoveVEX {
					continue
				}
				body := fmt.Sprintf("VMOVDQU8 (DI),%s0\n", bank)
				name, mask := opcode, ""
				if mode != "unmasked" {
					body += fmt.Sprintf("VMOVDQU8 (SI),%s1\nKMOVQ AX,K1\n", bank)
					mask = "K1,"
					if mode == "zero" {
						name += ".Z"
					}
				}
				body += fmt.Sprintf("%s %s0,%s%s1\nVMOVSS X1,(DX)", name, bank, mask, bank)
				t.Run(opcode+"/"+bank+"/"+mode, func(t *testing.T) {
					assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", body, 1)
					requireX86GoAssemblerResult(t, "amd64", assembly, true)
					pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
					if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestX86GoCallerPackedMovesRetainUnknownAndBoundedMemoryFailures(t *testing.T) {
	for _, example := range []struct{ name, body string }{
		{"unknown source", "VMOVUPS X0,X1\nVMOVSS X1,(DX)"},
		{"unknown mask", "VMOVUPS.Z (DI),K1,Z0\nVMOVSS X0,(DX)"},
		{"pointer mask", "KMOVQ DI,K1\nVMOVUPS.Z (DI),K1,Z0\nVMOVSS X0,(DX)"},
		{"unknown merge destination", "KMOVQ AX,K1\nVMOVUPS (DI),K1,Z0\nVMOVSS X0,(DX)"},
		{"unknown source in zero mask", "KMOVQ AX,K1\nVMOVUPS.Z Z0,K1,Z1\nVMOVSS X1,(DX)"},
		{"unknown base", "VMOVUPS (BX),Y0\nVMOVSS X0,(DX)"},
		{"pointer argument bits", "VMOVUPS a+0(FP),X0\nVMOVSS X0,(DX)"},
		{"saved BP bytes", "VMOVUPS 0(SP),X0\nVMOVSS X0,(DX)"},
		{"unknown input alignment", "VMOVAPS (DI),X0\nVMOVSS X0,(DX)"},
		{"unknown integer alignment", "VMOVDQA32 (DI),Y0\nVMOVSS X0,(DX)"},
		{"input write", "VMOVUPS (DI),Y0\nVMOVUPS Y0,(SI)\nVMOVSS X0,(DX)"},
		{"length read too wide", "VMOVUPS (CX),X0\nVMOVSS X0,(DX)"},
		{"length write", "VMOVUPS (DI),X0\nVMOVUPS X0,(CX)\nVMOVSS X0,(DX)"},
		{"wide fresh result", "VMOVUPS (DI),X0\nVMOVUPS X0,(DX)"},
		{"masked wide fresh result", "KMOVQ AX,K1\nVMOVUPS (DI),X0\nVMOVUPS X0,K1,(DX)"},
		{"invalid zero memory store", "KMOVQ AX,K1\nVMOVUPS (DI),X0\nVMOVUPS.Z X0,K1,(DX)"},
		{"indexed fresh result", "VMOVUPS (DI),X0\nVMOVUPS X0,(DX)(AX*1)"},
		{"SP escape", "MOVQ SP,BX\nVMOVUPS (BX),X0\nVMOVSS X0,(DX)"},
		{"g carrier", "VMOVUPS (R14),X0\nVMOVSS X0,(DX)"},
		{"different initialized bytes at join", "CMPQ AX,$0\nJE join\nVMOVUPS (DI),Z0\njoin:\nVMOVSS X0,(DX)"},
	} {
		t.Run(example.name, func(t *testing.T) {
			assembly := strings.Replace(x86CallerFixtureAssembly, "MOVL AX,(DX)", example.body, 1)
			requireX86GoAssemblerResult(t, "amd64", assembly, true)
			pkg, _ := x86CallerCoreFixture(t, x86CallerFixtureSource, assembly)
			if err := x86CallerCoreTranslate(t, pkg, assembly, "x86_64-unknown-linux-gnu"); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("unproved packed move acquired continuation: %v", err)
			}
		})
	}
}

func TestX86PackedMoveInvalidStoreCannotAcquireCallerMemoryCertificate(t *testing.T) {
	for _, opcode := range x86PackedZeroStoreOpcodes {
		for _, bank := range []string{"X", "Y", "Z"} {
			t.Run(opcode+"/"+bank, func(t *testing.T) {
				instruction := fmt.Sprintf("%s.Z %s0,K1,(DX)", opcode, bank)
				parsed, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+instruction+"\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				ins := parsed.Funcs[0].Instrs[1]
				state := x86SourceStackState{
					vectors: map[Reg]uint64{"Z0": ^uint64(0)}, masks: map[Reg]bool{"K1": true},
				}
				if strings.Contains(opcode, "COMPRESS") {
					form, known, err := x86PackedCompactProperties(ins.Op, ins, "amd64")
					if !known || err != nil || !form.undefinedOpcode() {
						t.Fatal("compact syntax lost its independent #UD effect", err)
					}
					if _, known, err := x86TypedCompactExpandByteEffect(ins.Op, ins, "amd64"); !known || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("#UD compact form acquired ordinary numerical effects", err)
					}
				} else {
					form, known, err := amd64PackedVectorMoveProperties(ins, "amd64")
					if !known || err != nil || !form.undefinedOpcode() {
						t.Fatal("move syntax lost its independent #UD effect", err)
					}
					if x86CallerPackedVectorMoveStep(&ins, form, &state, nil) {
						t.Fatal("#UD instruction acquired caller continuation")
					}
				}
				if x86CallerVectorMoveKnown(ins) {
					t.Fatal("#UD instruction acquired an ordinary move effect")
				}
				if _, _, valid := x86CallerMoveMemoryShape(ins, 2); valid {
					t.Fatal("#UD instruction acquired a memory certificate shape")
				}
				if x86CallerVectorMoveStep(&ins, &state, nil) || x86CallerMemoryCertified(ins, 2) {
					t.Fatal("#UD instruction acquired a caller memory certificate")
				}
			})
		}
	}
}

func TestX86GoCallerPackedMoveByteKnowledgeIncludesMaskAndZeroUpperViews(t *testing.T) {
	for _, encoding := range []struct {
		op    string
		width int
	}{
		{"VMOVUPS", 16}, {"VMOVUPD", 32}, {"VMOVDQU8", 64},
		{"VMOVDQU16", 16}, {"VMOVDQU32", 32}, {"VMOVDQU64", 64},
	} {
		bank := map[int]string{16: "X", 32: "Y", 64: "Z"}[encoding.width]
		for _, sourceKnown := range []uint64{0, 0xf, 0xff, ^uint64(0)} {
			for _, oldKnown := range []uint64{0, 0xff, ^uint64(0)} {
				for _, mode := range []string{"", "merge", "zero"} {
					name, mask := encoding.op, ""
					if mode != "" {
						mask = "K1,"
						if mode == "zero" {
							name += ".Z"
						}
					}
					instruction := fmt.Sprintf("%s %s0,%s%s1", name, bank, mask, bank)
					parsed, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+instruction+"\nRET\n")
					if err != nil {
						t.Fatal(err)
					}
					ins := parsed.Funcs[0].Instrs[1]
					form, recognized, err := amd64PackedVectorMoveProperties(ins, "amd64")
					if !recognized || err != nil {
						t.Fatalf("known transfer form: %v", err)
					}
					state := x86SourceStackState{vectors: map[Reg]uint64{"Z0": sourceKnown, "Z1": oldKnown}, masks: map[Reg]bool{"K1": true}}
					if !x86CallerPackedVectorMoveStep(&ins, form, &state, nil) {
						t.Fatal("register-only effect unexpectedly requires a caller region")
					}
					var expected uint64
					for index := 0; index < 64; index++ {
						bit := uint64(1) << uint(index)
						if index >= encoding.width || sourceKnown&bit != 0 && (mode != "merge" || oldKnown&bit != 0) {
							expected |= bit
						}
					}
					if state.vectors["Z1"] != expected || state.vectors["Z0"] != sourceKnown || !reflect.DeepEqual(state.masks, map[Reg]bool{"K1": true}) {
						t.Fatalf("%s changed initialized-byte/mask state: %+v; want %x", instruction, state, expected)
					}
				}
			}
		}
	}
}
