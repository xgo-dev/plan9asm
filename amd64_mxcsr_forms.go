package plan9asm

import (
	"fmt"
	"strings"
)

// Go's ysvrs_mo, ysvrs_om and _yvldmxcsr rows have one m32 operand.
// This descriptor gives no source, memory, frame or MXCSR control authority.
func x86MXCSRProperties(ins Instr, arch string) (write, known bool, err error) {
	base, _, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	switch base {
	case "LDMXCSR", "VLDMXCSR":
	case "STMXCSR", "VSTMXCSR":
		write = true
	default:
		return false, false, nil
	}
	if arch != "amd64" && arch != "386" || dotted || len(ins.Args) != 1 ||
		!isAMD64MemoryOperand(ins.Args[0]) || !x86PackedShiftMemoryValid(ins.Args[0], arch) {
		return write, true, fmt.Errorf("%s %s expects one Go m32 operand without suffixes: %q", arch, ins.Op, ins.Raw)
	}
	return write, true, nil
}

func x86TypedMXCSRByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	if ins.Op != "" && !strings.EqualFold(string(op), string(ins.Op)) {
		if _, known, _ := x86MXCSRProperties(Instr{Op: op}, arch); known {
			return x86TypedByteEffect{}, true, fmt.Errorf("MXCSR effect/source identity differs: %s/%s", op, ins.Op)
		}
		return x86TypedByteEffect{}, false, nil
	}
	ins.Op = op
	write, known, err := x86MXCSRProperties(ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	return x86TypedByteEffect{operands: []x86TypedByteOperand{
		{index: 0, operand: ins.Args[0], width: 4, read: !write, write: write},
	}}, true, nil // All six integer status bits and DF are unaffected.
}

// Both _yvldmxcsr rows use VEX.L0.0F AE, with a fixed ModRM extension and
// no encoded vector operand. The memory policy remains owned by the caller.
func decodedX86VEXMXCSRInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	p, known := decodeX86RawVectorEncoding(code)
	if !known || p.evex || p.mapNumber != 1 || p.pp != 0 || p.opcode != 0xae {
		return Instr{}, 0, false, nil
	}
	if len(code) <= p.modRM {
		return Instr{}, 0, true, fmt.Errorf("MXCSR is missing its ModRM byte")
	}
	modRM := code[p.modRM]
	op := Op("VLDMXCSR")
	switch modRM >> 3 & 7 {
	case 2:
	case 3:
		op = "VSTMXCSR"
	default:
		return Instr{}, 0, false, nil
	}
	if mode != 32 && mode != 64 || p.addressOverride || p.vectorLength != 0 || p.upper != 0 ||
		p.r != 0 || modRM>>6 == 3 || mode == 32 && (p.x != 0 || p.b != 0) {
		return Instr{}, 0, true, fmt.Errorf("%s requires its original VEX m32 encoding", op)
	}
	operand, length, err := memory.scalar(code[p.modRM:], mode, p.b, p.x, p.segment, 1)
	if err != nil {
		return Instr{}, 0, true, err
	}
	instruction := Instr{
		Op: op, Args: []Operand{operand}, Raw: string(op) + " " + operand.String(), x86Encoded: true,
	}
	return instruction, p.modRM + length, true, nil
}
