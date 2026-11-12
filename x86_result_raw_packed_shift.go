package plan9asm

import "reflect"

// Zero is absent physical identity, never an assertion that an instruction was
// VEX. Low-bank unmasked X/Y operands do not distinguish VEX from EVEX.
type x86RawPackedShiftEncoding uint8

const (
	x86RawPackedShiftAbsent x86RawPackedShiftEncoding = iota
	x86RawPackedShiftVEX
	x86RawPackedShiftEVEX
)

type x86RawPackedShiftIdentity struct {
	arch     string
	encoding x86RawPackedShiftEncoding
	w        bool
}

func x86PackedShiftRawIdentity(ins Instr, arch string) x86RawPackedShiftIdentity {
	form, known, err := x86PackedShiftProperties(ins.Op, ins, arch)
	if !known || err != nil || form.legacy || !ins.x86Encoded ||
		ins.x86PackedShiftEncoding != x86RawPackedShiftVEX && ins.x86PackedShiftEncoding != x86RawPackedShiftEVEX {
		return x86RawPackedShiftIdentity{}
	}
	return x86RawPackedShiftIdentity{arch, ins.x86PackedShiftEncoding, ins.x86PackedShiftW}
}

func x86RawPackedShiftEncodingSource(ins Instr, arch string) bool {
	form, known, err := x86PackedShiftProperties(ins.Op, ins, arch)
	origin := ins.x86SourceRaw
	return known && err == nil && !form.legacy && origin != nil && origin.packedShift.arch == arch &&
		origin.packedShift == x86PackedShiftRawIdentity(ins, arch) && origin.op == ins.Op &&
		origin.vectorBytes == ins.x86VectorBytes && origin.addressBits == ins.x86AddressBits &&
		(reflect.DeepEqual(origin.args, ins.Args) || x86RawLiteralSourceIdentity(ins, arch))
}

func x86RawPackedShiftSource(ins Instr, arch string) bool {
	form, known, err := x86PackedShiftProperties(ins.Op, ins, arch)
	if !known || err != nil || !x86RawPackedShiftEncodingSource(ins, arch) ||
		x86Mode32VectorRegisterContext(ins, arch) != nil {
		return false
	}
	// Immediate selectors retain their original position and byte. The selected
	// operand checks ordinary native memory only; RIP/DATA and logical fields
	// retain separate owners and cannot borrow this continuation.
	source := form.data
	if form.memory >= 0 {
		source = form.memory
	}
	return x86RawOrdinaryVectorSourceAt(ins, arch, source)
}

// Select this restriction from the immutable decoded inventory, before strict
// NUM success. Erasing a mutable origin must not turn raw bytes into a genuine
// named instruction. No replay supplies any missing input or native entry.
func x86PackedShiftRawReplayRequired(fn Func, arch string) bool {
	if fn.x86RawReplay == nil {
		return false
	}
	for _, ins := range fn.x86RawReplay.decoded {
		if form, known, _ := x86PackedShiftProperties(ins.Op, ins, arch); known && !form.legacy {
			return true
		}
	}
	return false
}

// Only lowering's complete-source owner may project the exact decoded shift
// onto the existing typed byte/count/mask effect. It creates neither reusable
// memory facts nor caller, frame, raw-RET, physical-SP or entry permissions.
func x86LoweredRawPackedShiftStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86PackedShiftProperties(ins.Op, ins, arch)
	if !known || x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	if err != nil || !x86RawPackedShiftSource(ins, arch) {
		return false, true
	}
	local := ins
	local.x86Encoded, local.x86SourceRaw = false, nil
	local.x86PackedShiftEncoding, local.x86PackedShiftW = x86RawPackedShiftAbsent, false
	// Keep the already-validated physical form: mode32 masks have four operands
	// even though Go's genuine named mode32 frontend still has its old arity cap.
	return x86ResultPackedShiftInputs(local, form, state, owned, arch, true), true
}
