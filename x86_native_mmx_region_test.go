package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const x86NativeMMXTestIntegerNames = `PACKSSLW PACKSSWB PACKUSWB PADDB PADDL PADDW
	PADDSB PADDSW PADDUSB PADDUSW PAND PANDN POR PXOR PAVGB PAVGW
	PCMPEQB PCMPEQW PCMPEQL PCMPGTB PCMPGTW PCMPGTL PMADDWL
	PMULLW PMULHW PMULHUW PMULULQ PUNPCKHBW PUNPCKHWL PUNPCKHLQ
	PUNPCKLBW PUNPCKLWL PUNPCKLLQ PHADDD PSHUFW
	PSLLW PSLLL PSLLQ PSRLW PSRLL PSRLQ PSRAW PSRAL`

func x86NativeMMXTestPlan(t *testing.T, instruction string) (*x86NativeMMXRegion, Func, FuncSig) {
	t.Helper()
	_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64",
		instruction+"\nEMMS\nRET")
	fn := file.Funcs[0]
	plan, err := newX86NativeMMXRegion(fn, sig, "amd64", "x86_64-unknown-linux-gnu")
	if err != nil || plan == nil {
		t.Fatal("complete ordinary MMX source lost its private region", err)
	}
	return plan, fn, sig
}

func TestX86NativeMMXCompleteIntegerBankEffects(t *testing.T) {
	// Independent list, not an iteration over the implementation's map. The
	// existing Go-table witness also binds every row, prefix and opcode byte.
	names := strings.Fields(x86NativeMMXTestIntegerNames)
	if len(names) != 43 || len(x86LegacyMMXReadSpecs) != len(names) {
		t.Fatal("complete integer MMX family changed")
	}
	for _, name := range names {
		for _, source := range []string{"M1", "BX", "a+0(FP)", "(AX)"} {
			t.Run(name+"/"+source, func(t *testing.T) {
				instruction := name + " " + source + ",M0"
				if name == "PSHUFW" {
					instruction = name + " $27," + source + ",M0"
				}
				plan, fn, _ := x86NativeMMXTestPlan(t, instruction)
				ordinal := plan.begin
				ins := fn.Instrs[ordinal]
				state := x86ResultState{fp: make([]bool, 16), flags: x86ByteFlagsAll,
					direction: x86ResultDirectionBackward, stringCount: x86StringCountNonzero}
				owned := make([]bool, 16)
				for offset := range state.fp {
					state.fp[offset], owned[offset] = true, true
				}
				state.nativeMMX[0], state.nativeMMX[1], state.nativeMMX[3] = 0xff, 0xff, 0xff
				state.gp[0], state.gp[3], state.pointerGP[0] = 0xff, 0xff, true
				state.xmm[0], state.vectorUpper[0] = 0x55aa, 0xffff0000
				before := state.clone()
				if accepted, known := plan.transfer(ordinal, ins, &state, owned, 8, "amd64"); !accepted || !known || !reflect.DeepEqual(before, state) {
					t.Fatal("MMX writer changed another register, address, FLAGS or DF domain", accepted, known)
				}
				missing := before.clone()
				switch source {
				case "M1":
					missing.nativeMMX[1] = 0x7f
				case "BX":
					missing.nativeMMX[3] = 0 // The defined GP BX cannot supply physical M3.
				case "a+0(FP)":
					width := 8
					if name == "PUNPCKLBW" || name == "PUNPCKLWL" || name == "PUNPCKLLQ" {
						width = 4
						missing.fp[4] = false // Low unpack must not over-read its m32 source.
						if accepted, _ := plan.transfer(ordinal, ins, &missing, owned, 8, "amd64"); !accepted {
							t.Fatal("low unpack incorrectly required the upper m64 bytes")
						}
					}
					missing.fp[width-1] = false
				case "(AX)":
					missing.pointerGP[0] = false
				}
				if accepted, known := plan.transfer(ordinal, ins, &missing, owned, 8, "amd64"); accepted || !known {
					t.Fatal("private numerical shadows supplied a missing physical bank or memory source")
				}
				missing = before.clone()
				missing.nativeMMX[0] = 0
				accepted, known := plan.transfer(ordinal, ins, &missing, owned, 8, "amd64")
				if !known || accepted != (name == "PSHUFW") {
					t.Fatal("old MMX destination dependency changed", accepted, known)
				}
			})
		}
	}
}

func TestX86NativeMMXWordDoesNotCreatePointerOrCanonicalFacts(t *testing.T) {
	for _, op := range []string{"MOVL", "MOVQ"} {
		plan, fn, _ := x86NativeMMXTestPlan(t, op+" M0,AX")
		state := x86ResultState{flags: x86ByteFlagsAll, direction: x86ResultDirectionForward}
		state.nativeMMX[0], state.canonicalGP[0] = 0xff, 0xff
		state.pointerGP[0], state.callerAddressGP[0], state.callerAddressOrigin[0] = true, true, 7
		state.resultAddressGP[0] = x86ResultSlotAddress{start: 8, end: 16, valid: true}
		if accepted, known := plan.transfer(plan.begin, fn.Instrs[plan.begin], &state, nil, 8, "amd64"); !accepted || !known {
			t.Fatal(op, "initialized physical MMX word not transported")
		}
		canonical := uint8(0)
		if op == "MOVL" {
			canonical = 0xf0 // Only the actually cleared upper dword is known zero.
		}
		if state.gp[0] != 0xff || state.canonicalGP[0] != canonical || state.pointerGP[0] ||
			state.callerAddressGP[0] || state.callerAddressOrigin[0] != 0 || state.resultAddressGP[0].valid ||
			state.flags != x86ByteFlagsAll || state.direction != x86ResultDirectionForward {
			t.Fatal(op, "numerical MMX transport retained another source authority")
		}
	}
	plan, fn, _ := x86NativeMMXTestPlan(t, "MOVQ M1,M0")
	state := x86ResultState{}
	state.nativeMMX[1] = 0xff
	if accepted, known := plan.transfer(plan.begin, fn.Instrs[plan.begin], &state, nil, 8, "amd64"); accepted || !known {
		t.Fatal("Go's GP CX encoding borrowed initialized M1")
	}
	state.gp[1] = 0xff
	if accepted, _ := plan.transfer(plan.begin, fn.Instrs[plan.begin], &state, nil, 8, "amd64"); !accepted || state.nativeMMX[0] != 0xff {
		t.Fatal("actual initialized GP CX did not supply Go's selected word row")
	}
}

func TestX86NativeMMXRegionBindsSourceSignatureAndTarget(t *testing.T) {
	plan, fn, sig := x86NativeMMXTestPlan(t, "MOVQ a+0(FP),M0\nMOVQ M0,ret+8(FP)")
	const triple = "x86_64-unknown-linux-gnu"
	if !plan.matches(fn, sig, "amd64", triple) {
		t.Fatal("fresh source-bound region does not match its owner")
	}
	changed := fn
	changed.Instrs = cloneX86ReplayInstrs(fn.Instrs)
	changed.Instrs[plan.begin].Args[0].FPOffset++
	if plan.matches(changed, sig, "amd64", triple) || plan.matches(fn, sig, "386", triple) ||
		plan.matches(fn, sig, "amd64", "x86_64-pc-windows-msvc") {
		t.Fatal("MMX region was rebound to changed source or target")
	}
	state := x86ResultState{shapeOnly: true}
	if accepted, known := plan.transfer(plan.begin, changed.Instrs[plan.begin], &state, nil, 8, "amd64"); accepted || !known {
		t.Fatal("a mutated source operand borrowed an already bound transfer")
	}
	changedSig := sig
	changedSig.Name += "Changed"
	if plan.matches(fn, changedSig, "amd64", triple) {
		t.Fatal("MMX region was rebound to another declaration")
	}
	for _, row := range []struct{ name, body string }{
		{"unclosed", "MOVQ a+0(FP),M0\nRET"},
		{"interleaved", "MOVQ a+0(FP),M0\nMOVQ $1,AX\nEMMS\nRET"},
		{"call", "MOVQ a+0(FP),M0\nEMMS\nCALL other(SB)\nRET"},
		{"x87", "FLD1\nMOVQ a+0(FP),M0\nEMMS\nRET"},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, file, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", row.body)
			if _, err := newX86NativeMMXRegion(file.Funcs[0], sig, "amd64", triple); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("incomplete source acquired another MMX/x87 role", err)
			}
		})
	}
	for _, change := range []func(*Func){
		func(fn *Func) { fn.FrameSize = 16 },
		func(fn *Func) { fn.Instrs[plan.begin].x86Encoded = true },
		func(fn *Func) { fn.Instrs[plan.begin].x86AddressBits = 32 },
	} {
		changed := fn
		changed.Instrs = cloneX86ReplayInstrs(fn.Instrs)
		change(&changed)
		if _, err := newX86NativeMMXRegion(changed, sig, "amd64", triple); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("a foreign entry or physical origin borrowed the ordinary MMX region", err)
		}
	}
}

func TestX86NativeMMXSelfZeroAndImmediateCountDependencies(t *testing.T) {
	for _, op := range strings.Fields("PXOR PANDN PCMPEQB PCMPEQW PCMPEQL PCMPGTB PCMPGTW PCMPGTL") {
		plan, fn, _ := x86NativeMMXTestPlan(t, op+" M0,M0")
		state := x86ResultState{}
		if accepted, known := plan.transfer(plan.begin, fn.Instrs[plan.begin], &state, nil, 8, "amd64"); !accepted || !known || state.nativeMMX[0] != 0xff {
			t.Fatal("self-zero/all-ones physical MMX operation retained a false input dependency", op)
		}
	}
	for _, op := range strings.Fields("PSLLW PSLLL PSLLQ PSRLW PSRLL PSRLQ PSRAW PSRAL") {
		plan, fn, _ := x86NativeMMXTestPlan(t, fmt.Sprintf("%s $3,M0", op))
		state := x86ResultState{}
		if accepted, known := plan.transfer(plan.begin, fn.Instrs[plan.begin], &state, nil, 8, "amd64"); accepted || !known {
			t.Fatal("immediate shift count supplied missing MMX data", op)
		}
		state.nativeMMX[0] = 0xff
		if accepted, _ := plan.transfer(plan.begin, fn.Instrs[plan.begin], &state, nil, 8, "amd64"); !accepted {
			t.Fatal("complete immediate-count MMX row rejected", op)
		}
	}
}
