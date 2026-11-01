package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func x86COMINativeInputSource(arch, name, op, setup, address, tail string) string {
	word, size := "Q", 8
	if arch == "386" {
		word, size = "L", 4
	}
	return fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\nMOV%s p+0(FP),DX\n"+
		"MOVL $0,AX\nMOVL AX,X1\nMOVL $2,CX\n%s%s %s,X1\n%s"+
		"PUSHF%s\nPOP%s AX\nMOV%s AX,ret+%d(FP)\nRET\n",
		name, 2*size, word, setup, op, address, tail, word, word, word, size)
}

func x86COMINativeInputStatusProjection(arch, name, op, setup, address, tail string) string {
	source := x86COMINativeInputSource(arch, name, op, setup, address, tail)
	word := "Q"
	if arch == "386" {
		word = "L"
	}
	// COMI defines only the six status flags, not incoming DF or ID. Keep
	// the original full-word observation below as an explicit negative.
	pop := "POP" + word + " AX\n"
	return strings.Replace(source, pop, pop+"AND"+word+" $0x8d5,AX\n", 1)
}

func TestX86COMINativeInputCompleteFiveTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			var source, declarations strings.Builder
			for _, op := range x86COMIOracleNames() {
				source.WriteString(x86COMINativeInputStatusProjection(target.arch, op, op, "", "-7(DX)(CX*4)", ""))
				fmt.Fprintf(&declarations, "func %s(p *byte) uintptr\n", op)
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
				if err != nil {
					t.Fatal("initialized native compare input rejected", api, err)
				}
				if strings.Count(ir, "asm sideeffect") != 8 ||
					strings.Count(ir, "elementtype([4 x i8])") != 4 ||
					strings.Count(ir, "elementtype([8 x i8])") != 4 {
					t.Fatal("native comparison lost its exact scalar access or MXCSR effect", api)
				}
				for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, target.triple, text, level)
					}
				}
			}
		})
	}
}

func TestX86COMINativeInputCannotSupplyOtherRoles(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word, triple := "L", "i386-unknown-linux-gnu"
		if arch == "amd64" {
			word, triple = "Q", "x86_64-unknown-linux-gnu"
		}
		for _, op := range x86COMIOracleNames() {
			for _, row := range []struct{ name, remove, setup, address, tail string }{
				{"vector-input", "MOVL AX,X1\n", "", "(DX)", ""},
				{"index-input", "MOVL $2,CX\n", "", "(DX)(CX*4)", ""},
				{"pointer-index", "", "MOV" + word + " p+0(FP),CX\n", "(DX)(CX*4)", ""},
				{"numeric-base", "", "MOVL $4,DX\n", "(DX)", ""},
				{"unknown-base", "MOV" + word + " p+0(FP),DX\n", "", "(DX)", ""},
				{"unbound-symbol", "", "", "external(SB)", ""},
				{"unbound-segment", "", "", "(FS)", ""},
				{"unknown-store", "", "", "(DX)", "MOVL BX,(DX)\n"},
				{"no-future-pointer", "", "", "(DX)", "MOVL (DX),DX\n" + op + " (DX),X1\n"},
			} {
				t.Run(arch+"/"+op+"/"+row.name, func(t *testing.T) {
					source := x86COMINativeInputStatusProjection(arch, "view", op, row.setup, row.address, row.tail)
					if row.remove != "" {
						source = strings.Replace(source, row.remove, "", 1)
					}
					for _, api := range []string{"text", "module", "Go"} {
						ir, err := x86ScalarFPBitViewAPI(t, source, "var external [8]byte\nfunc view(p *byte) uintptr\n", arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("native comparison supplied missing input or storage authority", api, err)
						}
					}
				})
			}
		}
	}
}

func TestX86COMINativeStatusDoesNotInventDFOrID(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, op := range x86COMIOracleNames() {
			source := x86COMINativeInputSource(target.arch, "view", op, "", "-7(DX)(CX*4)", "")
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, "func view(p *byte) uintptr\n", target.arch, target.triple, api)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("native status query invented full FLAGS including unknown DF/ID", target, op, api, err)
				}
			}
		}
	}
}

func TestX86COMINativeReadPreservesUnrelatedState(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, op := range x86COMIOracleNames() {
			for missing := -1; missing < 64; missing++ {
				ins := x86ScalarLaneInstruction(t, op+" -7(DX)(CX*4),X1")
				state := x86ResultState{direction: x86ResultDirectionBackward,
					valueStack: &x86ResultValueStack{bytes: []uint8{1, 2}, id: true}}
				state.gp[1], state.pointerGP[2], state.masks[7] = 0xff, true, true
				state.callerAddressGP[2], state.flags = true, x86ByteFlagCF
				bytes := ^uint64(0)
				if missing >= 0 {
					bytes &^= 1 << uint(missing)
				}
				state.writeVector(1, 64, bytes, false)
				before := state.clone()
				if accepted, known := x86ResultCOMIStep(ins, &state, nil, arch); !known || accepted || !reflect.DeepEqual(state, before) {
					t.Fatal("standalone observer borrowed a conditional native read", arch, op, missing)
				}
				width := 4
				if strings.HasSuffix(op, "D") {
					width = 8
				}
				want := missing < 0 || missing >= width
				accepted, known := x86ResultCOMIStepWithRead(ins, &state, nil, arch, true)
				if want {
					before.flags = x86ByteFlagsAll
				}
				if !known || accepted != want || !reflect.DeepEqual(state, before) {
					t.Fatal("native continuation changed unrelated state or ignored a missing scalar byte", arch, op, missing)
				}
			}
		}
	}
}
