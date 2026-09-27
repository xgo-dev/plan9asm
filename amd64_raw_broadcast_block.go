package plan9asm

import (
	"fmt"
	"strings"
)

type x86RawBlockBroadcastForm struct {
	op          Op
	sourceBytes int
	minLength   int
	allowX      bool
}

// Go 1.27's complete EVEX packed-block broadcast rows. The corresponding
// VEX F128/I128 memory forms have a separate two-form decoder.
var x86RawBlockBroadcastForms = map[[2]int]x86RawBlockBroadcastForm{
	{0x19, 0}: {op: "VBROADCASTF32X2", sourceBytes: 8, minLength: 1, allowX: true},
	{0x59, 0}: {op: "VBROADCASTI32X2", sourceBytes: 8, minLength: 0, allowX: true},
	{0x1a, 0}: {op: "VBROADCASTF32X4", sourceBytes: 16, minLength: 1},
	{0x1a, 1}: {op: "VBROADCASTF64X2", sourceBytes: 16, minLength: 1},
	{0x5a, 0}: {op: "VBROADCASTI32X4", sourceBytes: 16, minLength: 1},
	{0x5a, 1}: {op: "VBROADCASTI64X2", sourceBytes: 16, minLength: 1},
	{0x1b, 0}: {op: "VBROADCASTF32X8", sourceBytes: 32, minLength: 2},
	{0x1b, 1}: {op: "VBROADCASTF64X4", sourceBytes: 32, minLength: 2},
	{0x5b, 0}: {op: "VBROADCASTI32X8", sourceBytes: 32, minLength: 2},
	{0x5b, 1}: {op: "VBROADCASTI64X4", sourceBytes: 32, minLength: 2},
}

// decodedX86RawBlockBroadcastInstruction decodes every EVEX block-broadcast
// shape, including register-backed X2 sources and K merge/zero masking.
func decodedX86RawBlockBroadcastInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || !p.evex || p.mapNumber != 2 || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	w := 0
	if p.w {
		w = 1
	}
	form, recognized := x86RawBlockBroadcastForms[[2]int{p.opcode, w}]
	if !recognized {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("EVEX block broadcast: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if !p.fixed || p.addressOverride || p.broadcast || p.upper != 0 ||
		p.vectorLength < form.minLength || p.vectorLength > 2 {
		return fail("invalid EVEX fixed, address, broadcast, vvvv, or vector-length bits")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if p.zero && p.mask == 0 {
		return fail("zeroing requires a nonzero mask")
	}
	modRM := code[p.modRM]
	if modRM>>6 == 3 && !form.allowX {
		return fail("this block width requires a memory source")
	}
	destinationNumber := int(modRM>>3&7) + p.r*8
	if mode == 32 && p.vectorLength == 2 && destinationNumber >= 8 {
		return fail("386 Z-register exceeds the Go assembler frontend's register class")
	}
	vector := [...]string{"X", "Y", "Z"}[p.vectorLength]
	source, consumed, err := decodedX86EVEXRMOperand(
		code[p.modRM:], mode, p.b, p.x, p.segment, "X", form.sourceBytes,
	)
	if err != nil {
		return Instr{}, 0, true, err
	}
	op := form.op
	if p.zero {
		op += ".Z"
	}
	args := []Operand{source}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", vector, destinationNumber))})
	printed := make([]string, len(args))
	for index := range args {
		printed[index] = args[index].String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, p.modRM + consumed, true, nil
}
