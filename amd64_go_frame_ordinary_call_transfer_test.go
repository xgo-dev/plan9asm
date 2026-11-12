package plan9asm

import (
	"errors"
	"testing"
)

// Pure typed-state tests run on the translator's minimum SDK too. They do not
// impersonate the separately audited Go1.27 object/source producer.
func TestGoAMD64FrameOrdinaryCallTypedTransfer(t *testing.T) {
	sig := FuncSig{Name: "example.Callee", Args: []LLVMType{I64}, Ret: I64,
		Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I64, Field: -1}}, Results: []FrameSlot{{Offset: 8, Type: I64, Field: -1}}}}
	binding := &x86FixedLocalBinding{
		symbols: map[string]string{"·Callee": sig.Name}, signatures: map[string]FuncSig{sig.Name: sig},
		callees: map[string]goAMD64FrameDeclaration{sig.Name: {signature: sig, transport: goAMD64FrameNumericTransport}},
	}
	proof := &x86FixedLocalProof{binding: binding, frame: 48}
	call := x86ScalarLaneInstruction(t, "CALL ·Callee(SB)")
	state := fixedLocalExchangeState()
	state.bytes.setRange(0, 48, true)
	state.booleanBytes.setRange(0, 48, true)
	state.bytes.setRange(8, 8, false)
	state.addresses[8] = 32
	state.opaqueCells[8] = fixedLocalOrigin(x86FixedLocalOrigin{parameter: 0})
	state.known[AX], state.booleans[AX], state.constants[AX] = 255, 255, 1
	state.ranges = map[Reg]x86UnsignedRange{AX: {minimum: 1, maximum: 1}}
	state.comparison = x86FixedLocalComparison{register: AX, constant: 1}
	state.pointers[BX] = 32
	state.opaque[CX] = fixedLocalOrigin(x86FixedLocalOrigin{parameter: 0})
	state.vectors["Z0"], state.masks["K1"] = ^uint64(0), true
	before := cloneFixedLocalState(state)
	if err := fixedLocalOrdinaryCallStep(call, &state, proof); err != nil {
		t.Fatal(err)
	}
	if state.bytes.all(0, 8) || !state.bytes.all(8, 8) || !state.bytes.all(32, 8) ||
		state.booleanBytes.all(0, 16) || !state.booleanBytes.all(32, 8) ||
		len(state.addresses) != 0 || len(state.opaqueCells) != 0 ||
		len(state.known)+len(state.booleans)+len(state.constants)+len(state.ranges)+len(state.opaque) != 0 ||
		len(state.pointers) != 1 || state.pointers[SP] != 0 || len(state.vectors)+len(state.masks) != 0 || state.flags != 0 ||
		state.comparison != (x86FixedLocalComparison{}) {
		t.Fatal("CALL retained outgoing aliases/predicates/scratch or lost unescaped private bytes", state)
	}
	for index := int64(0); index < 16; index++ {
		if state.booleanBytes.has(index) {
			t.Fatal("an old outgoing bool byte survived a nonboolean call result", index)
		}
	}
	for _, test := range []string{"missing-byte", "private-pointer", "unknown-call", "wrong-SP", "short-frame"} {
		t.Run(test, func(t *testing.T) {
			state := cloneFixedLocalState(before)
			ins, localProof := call, *proof
			switch test {
			case "missing-byte":
				state.bytes.set(7, false)
			case "private-pointer":
				state.bytes.setRange(0, 8, false)
				state.addresses[0] = 32
			case "unknown-call":
				ins = x86ScalarLaneInstruction(t, "CALL ·Foreign(SB)")
			case "wrong-SP":
				state.pointers[SP] = 8
			case "short-frame":
				localProof.frame = 8
			}
			if err := fixedLocalOrdinaryCallStep(ins, &state, &localProof); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("an incomplete/unbound outgoing call acquired a result", err)
			}
		})
	}
	t.Run("narrow-result-padding", func(t *testing.T) {
		narrow := sig
		narrow.Args, narrow.Ret = []LLVMType{I8}, I8
		narrow.Frame = FrameLayout{Params: []FrameSlot{{Offset: 0, Type: I8, Field: -1}}, Results: []FrameSlot{{Offset: 8, Type: I8, Field: -1}}}
		localBinding := *binding
		localBinding.signatures = map[string]FuncSig{sig.Name: narrow}
		localBinding.callees = map[string]goAMD64FrameDeclaration{sig.Name: {signature: narrow, transport: goAMD64FrameNumericTransport}}
		localProof := *proof
		localProof.binding = &localBinding
		state := cloneFixedLocalState(before)
		if err := fixedLocalOrdinaryCallStep(call, &state, &localProof); err != nil {
			t.Fatal(err)
		}
		for index := int64(0); index < 16; index++ {
			if state.bytes.has(index) != (index == 8) {
				t.Fatal("narrow result or ABI0 trailing padding acquired initialized bytes", index)
			}
		}
	})
}
