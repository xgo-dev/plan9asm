package plan9asm

import "golang.org/x/arch/x86/x86asm"

// The decoder discards NOP's inert ModRM/SIB fields only after validating the
// complete encoding. Preserve existing source facts through that exact handoff,
// not through a different physical instruction or an unbound address contract.
// This observation creates no numerical, pointer, memory or raw-entry fact.
func x86NOPPreservesSourceState(ins Instr) bool {
	if ins.Op != "NOP" || len(ins.Args) != 0 || ins.x86Encoded || ins.x86RawNearReturn != nil ||
		ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return false
	}
	origin := ins.x86SourceRaw
	return origin == nil || origin.op == "NOP" && len(origin.args) == 0
}

// The pinned decoder lacks the REX.W form of 0F 1F /0 (LLVM 22 NOOPQ).
// Only its operand width is inert. Keep every other prefix and use the decoder
// for the complete ModRM/SIB/displacement length and prefix validity. This
// narrowly scoped adapter never changes 90's XCHG/PAUSE aliases or another
// opcode, and its result is consumed only by the operand-free NOP handoff.
func decodedX86REXWNOP(code []byte) (x86asm.Inst, bool) {
	if len(code) > 15 {
		code = code[:15]
	}
	i := 0
	for i < len(code) {
		switch code[i] {
		case 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3:
			i++
		default:
			goto opcode
		}
	}

opcode:
	if i+4 > len(code) || code[i]&0xf8 != 0x48 ||
		code[i+1] != 0x0f || code[i+2] != 0x1f || code[i+3]&0x38 != 0 {
		return x86asm.Inst{}, false
	}
	var adjusted [15]byte
	copy(adjusted[:], code)
	adjusted[i] &^= 8
	inst, err := x86asm.Decode(adjusted[:len(code)], 64)
	if err != nil || inst.Op != x86asm.NOP || inst.Len <= i+3 {
		return x86asm.Inst{}, false
	}
	return inst, true
}
