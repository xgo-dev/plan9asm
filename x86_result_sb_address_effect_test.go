package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86LEASBUnknownAddressSource(t *testing.T, arch, declaration, body string) string {
	t.Helper()
	return "DATA ·table<>+0(SB)/8,$7\nGLOBL ·table<>(SB),16,$16\n" +
		x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
}

func TestX86LEASBUnknownAddressCompleteThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		widths := []string{"W", "L"}
		registers := []string{"AX", "CX", "DX", "BX", "SI", "DI", "BP"}
		if target.arch == "amd64" {
			widths = append(widths, "Q")
			registers = []string{"AX", "CX", "DX", "BX", "SI", "DI", "R8", "R9", "R10", "R11", "R12", "R13", "R15"}
		}
		for _, width := range widths {
			for _, register := range registers {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+width+"/"+register+"/"+api, func(t *testing.T) {
						// Neither the address nor its uninitialized W remainder
						// contributes data to this independently defined result.
						body := fmt.Sprintf("MOVL $1,AX\nCMPL AX,$1\nLEA%s ·table<>-1(SB),%s\nSETEQ CL\nMOVL $7,ret+RESULT(FP)", width, register)
						source := x86LEASBUnknownAddressSource(t, target.arch, "func view() uint32", body)
						ir, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32", target.arch, target.triple, api)
						if err != nil || ir == "" {
							t.Fatalf("discarded valid SB address blocked independent NUM result: %v", err)
						}
					})
				}
			}
		}
	}
}

func TestX86LEASBUnknownAddressDoesNotGrantFacts(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		widths := []string{"W", "L"}
		move := "MOVL"
		if target.arch == "amd64" {
			widths, move = append(widths, "Q"), "MOVQ"
		}
		for _, width := range widths {
			for _, test := range []struct{ name, before, after string }{
				{"NUM-result", "", "MOVL DX,ret+RESULT(FP)"},
				{"NUM-compare", "", "TESTW DX,DX\nMOVL $0,CX\nSETEQ CL\nMOVL CX,ret+RESULT(FP)"},
				{"native-read", move + " p+0(FP),DX\n", "MOVB (DX),CL"},
				{"native-write", move + " p+0(FP),DX\n", "MOVB $1,(DX)"},
				{"caller-address", move + " p+0(FP),DX\n", "CMPW DX,$0"},
				{"old-result-address", "LEA" + strings.TrimPrefix(move, "MOV") + " ret+RESULT(FP),DX\n", "MOVL $7,(DX)"},
			} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+width+"/"+test.name+"/"+api, func(t *testing.T) {
						declaration := "func view(p *byte) uint32"
						body := "MOVL $7,ret+RESULT(FP)\n" + test.before + "LEA" + width + " ·table<>(SB),DX\n" + test.after
						source := x86LEASBUnknownAddressSource(t, target.arch, declaration, body)
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatalf("SB address created numerical/caller/result/native authority: IR=%d error=%v", len(ir), err)
						}
					})
				}
			}
		}
		for _, boundary := range []struct{ name, instruction string }{
			{"SP-destination", "LEAL ·table<>(SB),SP"},
			{"indexed-AUTO", "LEAL local+0(SP)(CX*1),DX"},
		} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/physical/"+boundary.name+"/"+api, func(t *testing.T) {
					body := "MOVL $7,ret+RESULT(FP)\nMOVL $0,CX\n" + boundary.instruction
					source := x86LEASBUnknownAddressSource(t, target.arch, "func view() uint32", body)
					if ir, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32", target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatalf("physical source stack acquired backing: %v", err)
					}
				})
			}
		}
		if target.arch == "amd64" {
			for _, width := range widths {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/physical/BP-destination/"+width+"/"+api, func(t *testing.T) {
						body := "LEA" + width + " ·table<>(SB),BP\nMOVL $7,ret+RESULT(FP)"
						source := x86LEASBUnknownAddressSource(t, target.arch, "func view() uint32", body)
						if ir, err := x86ScalarFPBitViewAPI(t, source, "func view() uint32", target.arch, target.triple, api); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatalf("AMD64 physical frame destination acquired ordinary GP authority: %v", err)
						}
					})
				}
			}
		}
	}
}

func TestX86LEASBUnknownAddressWriteEffects(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		widths := []string{"W", "L"}
		if arch == "amd64" {
			widths = append(widths, "Q")
		}
		for _, width := range widths {
			for _, prior := range []uint8{0, 0x55, 0xff} {
				t.Run(fmt.Sprintf("%s/%s/%x", arch, width, prior), func(t *testing.T) {
					state := x86ResultState{flags: x86ByteFlagCF | x86ByteFlagZF, direction: x86ResultDirectionBackward}
					state.gp[2], state.canonicalGP[2] = prior, 0xff
					state.pointerGP[2], state.pointerGP[3] = true, true
					state.callerAddressGP[2], state.callerAddressGP[3] = true, true
					state.callerAddressOrigin[2], state.callerAddressOrigin[3] = 8, 9
					state.resultAddressGP[2] = x86ResultSlotAddress{start: 8, end: 12, valid: true}
					state.resultAddressGP[3] = state.resultAddressGP[2]
					state.predicate = x86ResultPredicate{kind: x86ResultNonzeroMaskGP, register: 2, width: 8}
					before := state.clone()
					ins := x86ScalarLaneInstruction(t, "LEA"+width+" ·table<>-1(SB),DX")
					if accepted, known := x86ResultUnknownSBAddressStep(ins, &state, arch); !accepted || !known {
						t.Fatal("complete SB address write was not retained as unknown")
					}
					mask, zeros := uint8(3), uint8(0)
					if width == "L" {
						mask, zeros = 0x0f, 0xf0
					} else if width == "Q" {
						mask = 0xff
					}
					before.gp[2], before.canonicalGP[2] = prior&^mask|zeros, 0xff&^mask|zeros
					before.pointerGP[2], before.callerAddressGP[2], before.callerAddressOrigin[2] = false, false, 0
					before.resultAddressGP[2], before.predicate = x86ResultSlotAddress{}, x86ResultPredicate{}
					if !reflect.DeepEqual(state, before) {
						t.Fatal("SB address changed unwritten bytes, FLAGS/DF, unrelated identities or created a fact")
					}
					callers := x86ResultCallerAddressesAfter(ins, [16]bool{2: true, 3: true}, nil, arch)
					if callers != ([16]bool{3: true}) {
						t.Fatal("post-consumer retained destination or revoked an unrelated caller identity", callers)
					}
				})
			}
		}
	}
}

func TestX86LEASBUnknownAddressRejectsUnboundRoles(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*Instr)
	}{
		{"raw", func(ins *Instr) { ins.x86Encoded = true }},
		{"address-size", func(ins *Instr) { ins.x86AddressBits = 32 }},
		{"override", func(ins *Instr) { ins.x86UnboundAddressOverride = true }},
		{"segment", func(ins *Instr) { ins.x86SegmentPrefix = 0x64 }},
		{"not-SB", func(ins *Instr) { ins.Args[0].Sym = "table" }},
		{"unresolved", func(ins *Instr) { ins.Args[0].Sym = "table+MISSING(SB)" }},
		{"SP", func(ins *Instr) { ins.Args[1].Reg = SP }},
		{"BP", func(ins *Instr) { ins.Args[1].Reg = BP }},
		{"g", func(ins *Instr) { ins.Args[1].Reg = "R14" }},
		{"byte-alias", func(ins *Instr) { ins.Args[1].Reg = "DH" }},
		{"high-bank", func(ins *Instr) { ins.Args[1].Reg = "R16" }},
		{"FP-destination", func(ins *Instr) { ins.Args[1] = Operand{Kind: OpFP} }},
		{"non-LEA", func(ins *Instr) { ins.Op = "MOVL" }},
		{"extra-operand", func(ins *Instr) { ins.Args = append(ins.Args, Operand{Kind: OpReg, Reg: CX}) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			ins := x86ScalarLaneInstruction(t, "LEAL ·table<>(SB),DX")
			test.edit(&ins)
			state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
			state.gp[2], state.callerAddressGP[2], state.callerAddressGP[3] = 0xff, true, true
			before := state.clone()
			if accepted, _ := x86ResultUnknownSBAddressStep(ins, &state, "amd64"); accepted || !reflect.DeepEqual(state, before) {
				t.Fatal("unbound role borrowed named SB address availability")
			}
			if ins.x86Encoded || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
				if got := x86ResultCallerAddressesAfter(ins, before.callerAddressGP, nil, "amd64"); got != ([16]bool{}) {
					t.Fatal("unbound physical role retained caller facts", got)
				}
			}
		})
	}
	ins := x86ScalarLaneInstruction(t, "LEAL ·table<>(SB),DX")
	if accepted, known := x86ResultUnknownSBAddressStep(ins, nil, "amd64"); accepted || !known {
		t.Fatal("nil state acquired unknown-address availability")
	}
	ins.Op = "LEAQ"
	if accepted, _ := x86ResultUnknownSBAddressStep(ins, &x86ResultState{}, "386"); accepted {
		t.Fatal("mode32 acquired a qword GP write")
	}
}

func TestX86LEASBUnknownAddressReachingIndexAndUnrelatedPointers(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		widths, move := []string{"W", "L"}, "MOVL"
		if target.arch == "amd64" {
			widths, move = append(widths, "Q"), "MOVQ"
		}
		for _, width := range widths {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(target.triple+"/"+width+"/unrelated-pointer/"+api, func(t *testing.T) {
					declaration := "func view(p *byte) uint32"
					body := move + " p+0(FP),BX\nLEA" + width + " ·table<>(SB),DX\nMOVB (BX),CL\nMOVL $7,ret+RESULT(FP)"
					source := x86LEASBUnknownAddressSource(t, target.arch, declaration, body)
					if ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api); err != nil || ir == "" {
						t.Fatal("dead SB write revoked an unrelated reaching pointer", err)
					}
				})
			}
			if target.arch != "386" {
				continue // Named AMD64 SB operands cannot have a SIB index.
			}
			for _, test := range []struct {
				name, before string
				accepted     bool
			}{
				{"complete", "MOVL $1,CX\n", true},
				{"self-alias", "MOVL $1,DX\nMOVL DX,CX\n", true},
				{"unknown", "", false},
				{"partial", "MOVB $1,CX\n", false},
				{"opaque-pointer", "MOVL p+0(FP),CX\n", false},
				{"prior-SB-address", "LEAL ·table<>(SB),CX\n", false},
			} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(target.triple+"/"+width+"/index/"+test.name+"/"+api, func(t *testing.T) {
						declaration := "func view(p *byte) uint32"
						body := test.before + "LEA" + width + " ·table<>(SB)(BP)(CX*2),CX\nMOVL $7,ret+RESULT(FP)"
						source := x86LEASBUnknownAddressSource(t, target.arch, declaration, body)
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, target.arch, target.triple, api)
						if test.accepted {
							if err != nil || ir == "" {
								t.Fatal("complete reaching numerical index was not read before its overwrite", err)
							}
						} else if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatalf("unknown/partial/address index acquired NUM permission: %v", err)
						}
					})
				}
			}
		}
	}
}
