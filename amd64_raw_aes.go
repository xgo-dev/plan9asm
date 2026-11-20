package plan9asm

import (
	"fmt"
	"strings"
)

// VAES is absent from the pinned generic decoder. Decode its complete actual
// Go VEX/EVEX family without lending another instruction's operand/PC proof.
func decodedX86AESInstruction(code []byte, mode int) (Instr, int, bool, error) {
	return decodedX86AESInstructionWithMemory(code, mode, x86RawMemoryDecoder{})
}

func decodedX86AESInstructionWithMemory(code []byte, mode int, memory x86RawMemoryDecoder) (Instr, int, bool, error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i, segment, addressOverride := 0, Reg(""), false
	for i < len(code) {
		switch code[i] {
		case 0x64:
			segment = FS
			i++
		case 0x65:
			segment = GS
			i++
		case 0x67:
			addressOverride = true
			i++
		default:
			goto prefix
		}
	}
prefix:
	if i >= len(code) {
		return Instr{}, 0, false, nil
	}
	var opcodeIndex, modRMIndex, mapSelect, width, rExt, rHigh, xExt, bExt, vRegister, vHigh, rmHigh int
	evex := false
	switch code[i] {
	case 0xc4:
		if len(code) < i+4 {
			return Instr{}, 0, false, nil
		}
		p0, p1 := code[i+1], code[i+2]
		opcodeIndex, modRMIndex, mapSelect = i+3, i+4, int(p0&31)
		if p1&3 != 1 || x86AESRawOpcode(mapSelect, code[opcodeIndex]) == "" {
			return Instr{}, 0, false, nil
		}
		rExt, xExt, bExt = int(^p0>>7)&1, int(^p0>>6)&1, int(^p0>>5)&1
		vRegister = int(^p1>>3) & 15
		width = 16
		if p1&4 != 0 {
			width = 32
		}
	case 0x62:
		if len(code) < i+5 {
			return Instr{}, 0, false, nil
		}
		p0, p1, p2 := code[i+1], code[i+2], code[i+3]
		opcodeIndex, modRMIndex, mapSelect = i+4, i+5, int(p0&3)
		if p0&0x0c != 0 || p1&3 != 1 || x86AESRawOpcode(mapSelect, code[opcodeIndex]) == "" {
			return Instr{}, 0, false, nil
		}
		evex = true
		if p1&4 != 4 || p2&0x97 != 0 {
			return Instr{}, 0, true, fmt.Errorf("AES EVEX has reserved bit/mask/zeroing/broadcast attributes")
		}
		rExt, rHigh, xExt, bExt = int(^p0>>7)&1, int(^p0>>4)&1, int(^p0>>6)&1, int(^p0>>5)&1
		vRegister, vHigh, rmHigh = int(^p1>>3)&15, int(^p2>>3)&1, xExt
		switch p2 >> 5 & 3 {
		case 0:
			width = 16
		case 1:
			width = 32
		case 2:
			width = 64
		default:
			return Instr{}, 0, true, fmt.Errorf("reserved AES EVEX vector length")
		}
	default:
		return Instr{}, 0, false, nil
	}
	op := x86AESRawOpcode(mapSelect, code[opcodeIndex])
	unary := op == "VAESIMC" || op == "VAESKEYGENASSIST"
	if unary && (evex || width != 16 || vRegister != 0) {
		return Instr{}, 0, true, fmt.Errorf("AES unary requires VEX.128 with reserved vvvv")
	}
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing AES ModRM")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("%w: AES native address-size override is not bound", ErrProbeNeedsContext)
	}
	destinationNumber := int(code[modRMIndex]>>3&7) + rExt*8 + rHigh*16
	stateNumber := vRegister + vHigh*16
	if mode == 32 && (destinationNumber >= 8 || stateNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("%w: extended AES vector in physical mode32", ErrProbeNeedsContext)
	}
	if mode == 32 && code[modRMIndex]>>6 == 3 && int(code[modRMIndex]&7)+bExt*8+rmHigh*16 >= 8 {
		return Instr{}, 0, true, fmt.Errorf("%w: extended AES source vector in physical mode32", ErrProbeNeedsContext)
	}
	destination, valid := decodedX86VectorRegister(destinationNumber, width)
	if !valid {
		return Instr{}, 0, true, fmt.Errorf("invalid AES destination")
	}
	disp8Scale := 1
	if evex {
		disp8Scale = width
	}
	var source Operand
	var consumed int
	var err error
	if code[modRMIndex]>>6 == 3 {
		source, consumed, err = decodedX86VectorRMSource(code[modRMIndex:], mode, bExt, xExt, rmHigh, width, segment, disp8Scale)
	} else {
		source, consumed, err = decodedX86RMSourceWithPC(code[modRMIndex:], mode, bExt, xExt, segment, disp8Scale, memory.physicalPC)
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	length := modRMIndex + consumed
	args := []Operand{source}
	if op == "VAESKEYGENASSIST" {
		if len(code) <= length {
			return Instr{}, 0, true, fmt.Errorf("missing AES imm8")
		}
		args = append([]Operand{{Kind: OpImm, Imm: int64(code[length])}}, args...)
		length++
	}
	if !unary {
		state, _ := decodedX86VectorRegister(stateNumber, width)
		args = append(args, Operand{Kind: OpReg, Reg: state})
	}
	args = append(args, Operand{Kind: OpReg, Reg: destination})
	spelling := make([]string, len(args))
	for index, a := range args {
		spelling[index] = a.String()
	}
	return Instr{Op: op, Args: args, Raw: string(op) + " " + strings.Join(spelling, ", "), x86Encoded: true}, length, true, nil
}

func x86AESRawOpcode(mapSelect int, opcode byte) Op {
	if mapSelect == 3 && opcode == 0xdf {
		return "VAESKEYGENASSIST"
	}
	if mapSelect == 2 {
		switch opcode {
		case 0xdb:
			return "VAESIMC"
		case 0xdc:
			return "VAESENC"
		case 0xdd:
			return "VAESENCLAST"
		case 0xde:
			return "VAESDEC"
		case 0xdf:
			return "VAESDECLAST"
		}
	}
	return ""
}
