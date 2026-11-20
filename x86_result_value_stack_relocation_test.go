package plan9asm

import (
	"errors"
	"reflect"
	"testing"
)

func TestX86PrivateStackAbsoluteRelocationBitsStayOpaque(t *testing.T) {
	state := x86ResultState{valueStack: new(x86ResultValueStack), flags: x86ByteFlagsAll,
		direction: x86ResultDirectionBackward}
	before := state.clone()
	push := x86ScalarLaneInstruction(t, "PUSHL $·cell+8(SB)")
	if !x86ResultTransfer(push, &state, nil, 0, "386") {
		t.Fatal("complete Go absolute-relocation push lost its private copy role")
	}
	if len(state.valueStack.bytes) != 4 || !reflect.DeepEqual(state.valueStack.bytes, []uint8{0, 0, 0, 0}) {
		t.Fatal("relocation address invented numerical byte values", state.valueStack.bytes)
	}
	if state.gp != before.gp || state.pointerGP != before.pointerGP || state.callerAddressGP != before.callerAddressGP ||
		state.flags != before.flags || state.direction != before.direction {
		t.Fatal("private address copy changed unrelated state or created pointer authority")
	}
	state.gp[0], state.canonicalGP[0], state.pointerGP[0] = 0xff, 0xff, true
	pop := x86ScalarLaneInstruction(t, "POPL AX")
	if !x86ResultTransfer(pop, &state, nil, 0, "386") || len(state.valueStack.bytes) != 0 {
		t.Fatal("balanced opaque address pop was rejected")
	}
	if state.gp[0]&0xf != 0 || state.canonicalGP[0]&0xf != 0 || state.pointerGP[0] {
		t.Fatal("opaque address pop revived numerical, canonical or pointer bytes")
	}
}

func TestX86PrivateStackAbsoluteRelocationCannotSupplyValuesOrStorage(t *testing.T) {
	for _, row := range []struct{ name, declaration, body string }{
		{"NUM-result", "func Value() uint32", "MOVL AX,ret+0(FP)"},
		{"comparison", "func Value() uint32", "TESTL AX,AX\nMOVL $0,BX\nSETEQ BL\nMOVL BX,ret+0(FP)"},
		{"native-load", "func Value() uint32", "MOVL (AX),BX\nMOVL BX,ret+0(FP)"},
		{"native-store", "func Value()", "MOVL $7,(AX)"},
		{"FLAGS", "func Value()", "PUSHL AX\nPOPFL\nSETCS BL"},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(row.name+"/"+api, func(t *testing.T) {
				args := "0"
				if row.name == "NUM-result" || row.name == "native-load" || row.name == "comparison" {
					args = "4"
				}
				source := "TEXT ·Value(SB),4,$0-" + args + "\nPUSHL $·cell(SB)\nPOPL AX\n" + row.body + "\nRET\n"
				ir, err := x86ScalarFPBitViewAPI(t, source, row.declaration, "386", "i386-unknown-linux-gnu", api)
				if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatal("a private relocation copy acquired unrelated data/address authority", err)
				}
			})
		}
	}
}
