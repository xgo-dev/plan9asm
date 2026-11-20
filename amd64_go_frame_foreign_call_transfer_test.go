package plan9asm

import (
	"errors"
	"testing"
)

func TestGoAMD64FrameForeignABI0TypedPointerTransfer(t *testing.T) {
	sig := FuncSig{Name: "foreign.Consume", Args: []LLVMType{Ptr, I64}, Ret: Void,
		Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 8, Type: I64, Index: 1, Field: -1}}}}
	binding := &x86FixedLocalBinding{symbols: map[string]string{"foreign·Consume": sig.Name},
		signatures: map[string]FuncSig{sig.Name: sig},
		callees:    map[string]goAMD64FrameDeclaration{sig.Name: {signature: sig, transport: goAMD64FrameCompositeTransport}}}
	proof := &x86FixedLocalProof{binding: binding, frame: 64}
	call := x86ScalarLaneInstruction(t, "CALL foreign·Consume(SB)")
	before := fixedLocalExchangeState()
	origin := fixedLocalOrigin(x86FixedLocalOrigin{parameter: 0})
	before.opaqueCells[0], before.opaqueCells[24] = origin, origin
	before.bytes.setRange(8, 8, true)
	before.bytes.setRange(40, 8, true)
	before.addresses[48] = 56
	before.known[AX], before.vectors["Z0"], before.masks["K1"] = 255, ^uint64(0), true
	before.flags = x86ByteFlagCF
	t.Run("opaque-word-and-independent-spills", func(t *testing.T) {
		state := cloneFixedLocalState(before)
		if err := fixedLocalOrdinaryCallStep(call, &state, proof); err != nil {
			t.Fatal("typed opaque pointer argument was not accepted", err)
		}
		if state.opaqueCells[0].valid() || !state.opaqueCells[24].equal(origin) || !state.bytes.all(40, 8) ||
			state.addresses[48] != 56 || state.bytes.all(8, 8) || len(state.known)+len(state.opaque)+len(state.vectors)+len(state.masks) != 0 || state.flags != 0 {
			t.Fatal("CALL lost private spills or retained outgoing/scratch authority", state)
		}
	})
	for _, name := range []string{"missing-pointer", "partial-numeric-word", "private-frame-pointer", "unknown-callee", "changed-SP"} {
		t.Run(name, func(t *testing.T) {
			state := cloneFixedLocalState(before)
			instruction := call
			switch name {
			case "missing-pointer":
				delete(state.opaqueCells, 0)
			case "partial-numeric-word":
				delete(state.opaqueCells, 0)
				state.bytes.setRange(0, 7, true)
			case "private-frame-pointer":
				delete(state.opaqueCells, 0)
				state.addresses[0] = 40
			case "unknown-callee":
				instruction = x86ScalarLaneInstruction(t, "CALL foreign·Other(SB)")
			case "changed-SP":
				state.pointers[SP] = 8
			}
			if err := fixedLocalOrdinaryCallStep(instruction, &state, proof); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("uninitialized/unbound/private pointer acquired a call contract", err)
			}
		})
	}
}
