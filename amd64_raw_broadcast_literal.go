package plan9asm

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

type x86RawLiteralRange struct {
	first  int
	last   int
	source int
}

// decodeX86RawPackedBroadcastLiteral resolves a RIP-relative packed scalar
// broadcast only when its source bytes live in the same raw directive group.
// The caller must still prove that those bytes are not reachable instructions.
// A displacement into another TEXT, a missing constant pool, and segment- or
// address-size-relative loads stay on the rejecting decoder path.
func decodeX86RawPackedBroadcastLiteral(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}

	// A segment or address-size prefix changes the effective source.
	switch code[offset] {
	case 0x64, 0x65, 0x67:
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}

	modRMIndex := -1
	laneBytes := 0
	if len(code) >= offset+5 && code[offset] == 0xc4 && code[offset+1]&0x1f == 2 {
		modRMIndex = offset + 4
		switch code[offset+3] {
		case 0x78:
			laneBytes = 1
		case 0x79:
			laneBytes = 2
		case 0x58:
			laneBytes = 4
		case 0x59:
			laneBytes = 8
		}
	} else if len(code) >= offset+6 && code[offset] == 0x62 && code[offset+1]&0x0f == 2 {
		modRMIndex = offset + 5
		switch code[offset+4] {
		case 0x78:
			laneBytes = 1
		case 0x79:
			laneBytes = 2
		case 0x58:
			laneBytes = 4
		case 0x59:
			laneBytes = 8
		}
	}
	if laneBytes == 0 || modRMIndex < 0 || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	patched, value, literal, err := x86RawRIPLiteral(code, offset, modRMIndex, laneBytes)
	if err != nil {
		return Instr{}, 0, x86RawLiteralRange{}, true, err
	}
	length := len(patched)
	instruction, consumed, ok, err := decodedX86VEXPackedBroadcastInstruction(patched, mode)
	if err != nil || !ok || consumed != length {
		if err == nil {
			err = fmt.Errorf("RIP-relative packed broadcast did not match its VEX/EVEX grammar")
		}
		return Instr{}, 0, x86RawLiteralRange{}, true, err
	}

	setX86RawRIPLiteral(&instruction, value)
	return instruction, length, literal, true, nil
}

// decodeX86RawVMOVIntegerLiteral covers all memory-to-X VMOVW/VMOVD/VMOVQ VEX and
// EVEX encodings, including VMOVQ's alternate F3 7E encoding. The ordinary
// decoder validates the full grammar after the fixed-length ModRM rewrite.
func decodeX86RawVMOVIntegerLiteral(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}

	switch code[offset] {
	case 0x64, 0x65, 0x67:
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := -1
	width := 0
	if len(code) >= offset+4 && code[offset] == 0xc5 {
		modRMIndex = offset + 3
		width = x86RawVMOVLoadWidth(code[offset+2], code[offset+1]&3, false, false)
	} else if len(code) >= offset+5 && code[offset] == 0xc4 && code[offset+1]&0x1f == 1 {
		modRMIndex = offset + 4
		width = x86RawVMOVLoadWidth(code[offset+3], code[offset+2]&3, code[offset+2]&0x80 != 0, false)
	} else if len(code) >= offset+6 && code[offset] == 0x62 {
		modRMIndex = offset + 5
		if code[offset+1]&0x0f == 1 {
			width = x86RawVMOVLoadWidth(code[offset+4], code[offset+2]&3, code[offset+2]&0x80 != 0, true)
		} else if code[offset+1]&0x0f == 5 && code[offset+4] == 0x6e && code[offset+2]&3 == 1 {
			width = 2
		}
	}
	if width == 0 || modRMIndex < 0 || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}

	patched, value, literal, err := x86RawRIPLiteral(code, offset, modRMIndex, width)
	if err != nil {
		return Instr{}, 0, x86RawLiteralRange{}, true, err
	}
	instruction, consumed, ok, err := decodedX86VMOVQInstruction(patched, mode)
	if err != nil || !ok || consumed != len(patched) ||
		len(instruction.Args) != 2 || instruction.Args[0].Kind != OpMem {
		if err == nil {
			err = fmt.Errorf("RIP-relative VMOVW/VMOVD/VMOVQ load did not match its VEX/EVEX grammar")
		}
		return Instr{}, 0, x86RawLiteralRange{}, true, err
	}
	setX86RawRIPLiteral(&instruction, value)
	return instruction, len(patched), literal, true, nil
}

// decodeX86RawScalarFloatBroadcastLiteral resolves VBROADCASTSS/SD loads
// through the same source-local, unreachable constant-pool proof.
func decodeX86RawScalarFloatBroadcastLiteral(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || p.mapNumber != 2 || p.pp != 1 ||
		(p.opcode != 0x18 && p.opcode != 0x19) ||
		p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 4
	if p.opcode == 0x19 {
		width = 8
	}
	patched, value, literal, err := x86RawRIPLiteral(code, offset, modRMIndex, width)
	if err != nil {
		return Instr{}, 0, x86RawLiteralRange{}, true, err
	}
	instruction, consumed, ok, err := decodedX86ScalarBroadcastInstruction(patched, mode)
	if err != nil || !ok || consumed != len(patched) ||
		len(instruction.Args) < 2 || instruction.Args[0].Kind != OpMem {
		if err == nil {
			err = fmt.Errorf("RIP-relative scalar float broadcast did not match its VEX/EVEX grammar")
		}
		return Instr{}, 0, x86RawLiteralRange{}, true, err
	}
	setX86RawRIPLiteral(&instruction, value)
	return instruction, len(patched), literal, true, nil
}

func x86RawVMOVLoadWidth(opcode, pp byte, width64, evex bool) int {
	if opcode == 0x6e && pp == 1 {
		if width64 {
			return 8
		}
		return 4
	}
	if opcode == 0x7e && pp == 2 && (width64 == evex) {
		return 8
	}
	return 0
}

func x86RawRIPLiteral(code []byte, offset, modRMIndex, width int) ([]byte, int64, x86RawLiteralRange, error) {
	patched, data, literal, err := x86RawRIPBytes(code, offset, modRMIndex, width)
	if err != nil {
		return nil, 0, x86RawLiteralRange{}, err
	}
	if width > 8 {
		return nil, 0, x86RawLiteralRange{}, fmt.Errorf("%d-byte RIP literal does not fit an immediate", width)
	}
	var value uint64
	for index, b := range data {
		value |= uint64(b) << (8 * index)
	}
	return patched, int64(value), literal, nil
}

func x86RawRIPBytes(code []byte, offset, modRMIndex, width int) ([]byte, []byte, x86RawLiteralRange, error) {
	return x86RawRIPBytesWithSuffix(code, offset, modRMIndex, width, 0)
}

func x86RawRIPBytesWithSuffix(code []byte, offset, modRMIndex, width, trailingBytes int) ([]byte, []byte, x86RawLiteralRange, error) {
	if trailingBytes < 0 || len(code) < modRMIndex+5+trailingBytes {
		return nil, nil, x86RawLiteralRange{}, fmt.Errorf("truncated RIP-relative literal")
	}
	length := modRMIndex + 5 + trailingBytes - offset
	displacement := int32(binary.LittleEndian.Uint32(code[modRMIndex+1 : modRMIndex+5]))
	first := offset + length + int(displacement)
	last := first + width
	if width <= 0 || first < 0 || last > len(code) || last < first {
		return nil, nil, x86RawLiteralRange{}, fmt.Errorf("RIP-relative literal [%d,%d) is outside directive group", first, last)
	}

	// A base-register disp32 has the same byte length as RIP+disp32, allowing
	// the existing VEX/EVEX grammar to validate every other encoding field.
	patched := append([]byte(nil), code[offset:offset+length]...)
	patched[modRMIndex-offset] = patched[modRMIndex-offset]&0x38 | 0x80
	data := append([]byte(nil), code[first:last]...)
	return patched, data, x86RawLiteralRange{first: first, last: last}, nil
}

// decodeX86RawPackedMoveRIPData handles source-local X/Y/Z memory loads for
// the complete packed float and VEX integer move decoder families.
func decodeX86RawPackedMoveRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	packedFloat := (p.opcode == 0x10 || p.opcode == 0x28) && p.pp <= 1
	packedInteger := p.opcode == 0x6f && !p.evex && (p.pp == 1 || p.pp == 2)
	if !matched || p.mapNumber != 1 || (!packedFloat && !packedInteger) ||
		p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width,
		decodedX86PackedMoveInstruction, "packed move",
	)
}

// decodeX86RawEVEXPackedIntegerMoveRIPData covers the six EVEX VMOVDQA/DQU
// load opcodes across X/Y/Z widths and optional K masks.
func decodeX86RawEVEXPackedIntegerMoveRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || !p.evex || p.mapNumber != 1 || p.opcode != 0x6f ||
		(p.pp != 1 && p.pp != 2 && p.pp != 3) ||
		p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width,
		decodedX86EVEXPackedIntegerMoveInstruction, "EVEX packed integer move",
	)
}

// decodeX86RawVBROADCAST128RIPData resolves both VEX.256 F128/I128
// m128-to-Y forms through their shared source-memory grammar.
func decodeX86RawVBROADCAST128RIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || p.evex || p.mapNumber != 2 || p.pp != 1 ||
		p.vectorLength != 1 || (p.opcode != 0x1a && p.opcode != 0x5a) ||
		p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, 16,
		decodedX86VBROADCAST128Instruction, "VBROADCASTF128/VBROADCASTI128",
	)
}

// decodeX86RawPackedLogicalRIPData covers VEX VPAND/ANDN/OR/XOR and their
// EVEX D/Q counterparts. EVEX.b reads one scalar lane; other forms read the
// full X/Y/Z-width vector from the same unreachable source-local pool.
func decodeX86RawPackedLogicalRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || p.mapNumber != 1 || p.pp != 1 ||
		p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	switch p.opcode {
	case 0xdb, 0xdf, 0xeb, 0xef:
	default:
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	decoder := x86RawInstructionDecoder(decodedX86VEXPackedIntegerLogicalInstruction)
	family := "VEX packed integer logical"
	if p.evex {
		decoder = decodedX86EVEXPackedLogicalInstruction
		family = "EVEX packed logical"
		if p.broadcast {
			width = 4
			if p.w {
				width = 8
			}
		}
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width, decoder, family,
	)
}

// decodeX86RawFloatLogicalRIPData covers VEX/EVEX VAND/ANDN/OR/XOR PS/PD
// reads from an unreachable source-local X/Y/Z-width constant pool.
func decodeX86RawFloatLogicalRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || p.mapNumber != 1 || p.pp > 1 ||
		p.opcode < 0x54 || p.opcode > 0x57 ||
		p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	decoder := x86RawInstructionDecoder(decodedX86VEXPackedFloatLogicalInstruction)
	if p.evex {
		decoder = decodedX86RawEVEXFloatLogicalInstruction
		if p.broadcast {
			width = 4
			if p.w {
				width = 8
			}
		}
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width, decoder, "packed floating logical",
	)
}

// decodeX86RawHorizontalFloatRIPData covers VHADD/VHSUB/VADDSUB PS/PD
// VEX X/Y reads from unreachable source-local vector constants.
func decodeX86RawHorizontalFloatRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || p.evex || p.mapNumber != 1 ||
		(p.pp != 1 && p.pp != 3) || p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	switch p.opcode {
	case 0x7c, 0x7d, 0xd0:
	default:
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, 16<<p.vectorLength,
		decodedX86VEXHorizontalFloatInstruction, "horizontal/alternating floating",
	)
}

// decodeX86RawImmediatePackedBlendRIPData covers the complete Go 1.27
// legacy and VEX immediate blend family. The immediate follows disp32, so
// the pool displacement is relative to the byte after that immediate.
func decodeX86RawImmediatePackedBlendRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := -1
	width := 16
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if matched && !p.evex && p.mapNumber == 3 && p.pp == 1 &&
		p.segment == "" && !p.addressOverride {
		switch p.opcode {
		case 0x02, 0x0c, 0x0d, 0x0e:
			modRMIndex = offset + p.modRM
			width <<= p.vectorLength
		}
	}
	if modRMIndex < 0 && code[offset] == 0x66 {
		i := offset + 1
		if i < len(code) && code[i]&0xf0 == 0x40 {
			i++ // Optional REX extension for the legacy X registers.
		}
		if len(code) >= i+4 && code[i] == 0x0f && code[i+1] == 0x3a {
			switch code[i+2] {
			case 0x0c, 0x0d, 0x0e:
				modRMIndex = i + 3
			}
		}
	}
	if modRMIndex < 0 || len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	return x86RawRIPDataThroughDecoderOperand(
		code, offset, mode, modRMIndex, width, 1, 1,
		decodedX86ImmediatePackedBlendInstruction, "immediate packed blend",
	)
}

// decodeX86RawCLMULRIPData covers legacy PCLMULQDQ and all VEX/EVEX
// VPCLMULQDQ widths. The imm8 follows the source displacement.
func decodeX86RawCLMULRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := -1
	width := 16
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if matched && p.mapNumber == 3 && p.pp == 1 && p.opcode == 0x44 &&
		p.segment == "" && !p.addressOverride && p.vectorLength <= 2 {
		modRMIndex = offset + p.modRM
		width <<= p.vectorLength
	}
	if modRMIndex < 0 && code[offset] == 0x66 {
		i := offset + 1
		if i < len(code) && code[i]&0xf0 == 0x40 {
			i++
		}
		if len(code) >= i+4 && code[i] == 0x0f && code[i+1] == 0x3a && code[i+2] == 0x44 {
			modRMIndex = i + 3
		}
	}
	if modRMIndex < 0 || len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	return x86RawRIPDataThroughDecoderOperand(
		code, offset, mode, modRMIndex, width, 1, 1,
		decodedX86RawCLMULInstruction, "carryless multiply",
	)
}

// decodeX86RawMaskBlendRIPData folds source-local vector constants, or one
// D/Q broadcast lane, for all six EVEX mask-blend operations.
func decodeX86RawMaskBlendRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || !p.evex || p.mapNumber != 2 || p.pp != 1 ||
		p.opcode < 0x64 || p.opcode > 0x66 ||
		p.segment != "" || p.addressOverride || p.vectorLength > 2 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	if p.broadcast {
		width = 4
		if p.w {
			width = 8
		}
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width,
		decodedX86RawMaskBlendInstruction, "EVEX mask blend",
	)
}

// decodeX86RawScalarMoveRIPData covers memory-to-X VMOVSS/VMOVSD VEX and
// EVEX encodings plus raw EVEX VMOVSH. The typed scalar decoder enforces
// reserved fields and masks.
func decodeX86RawScalarMoveRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	half := p.evex && p.mapNumber == 5 && p.pp == 2
	if !matched || (p.mapNumber != 1 && !half) || p.opcode != 0x10 ||
		(p.pp != 2 && p.pp != 3) || p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 4
	if half {
		width = 2
	} else if p.pp == 3 {
		width = 8
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width,
		decodedX86ScalarMoveInstruction, "scalar move",
	)
}

// decodeX86RawMinMaxRIPData covers the complete VEX/EVEX packed integer
// min/max family. EVEX.b reads one D/Q lane; other forms read a full vector.
func decodeX86RawMinMaxRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	for _, spec := range amd64PackedIntegerMinMaxSpecs {
		if p.mapNumber != spec.mapNumber || p.opcode != spec.opcode {
			continue
		}
		if !p.evex && spec.laneBits == 64 {
			continue
		}
		if p.evex && spec.laneBits >= 32 && p.w != (spec.laneBits == 64) {
			continue
		}
		width := 16 << p.vectorLength
		if p.evex && p.broadcast {
			width = spec.laneBits / 8
		}
		return x86RawRIPDataThroughDecoder(
			code, offset, mode, modRMIndex, width,
			decodedX86PackedIntegerMinMaxInstruction, "packed integer min/max",
		)
	}
	return Instr{}, 0, x86RawLiteralRange{}, false, nil
}

// decodeX86RawPackedCompareRIPData covers all VPCMPEQ/GT B/W/D/Q source
// memory forms. The ordinary decoder checks the EVEX mask-result grammar.
func decodeX86RawPackedCompareRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	for _, spec := range amd64PackedIntegerCompareSpecs {
		if p.mapNumber != spec.mapNumber || p.opcode != spec.opcode {
			continue
		}
		width := 16 << p.vectorLength
		if p.evex && p.broadcast {
			width = spec.laneBits / 8
		}
		return x86RawRIPDataThroughDecoder(
			code, offset, mode, modRMIndex, width,
			decodedX86PackedIntegerCompareInstruction, "packed integer compare",
		)
	}
	return Instr{}, 0, x86RawLiteralRange{}, false, nil
}

// decodeX86RawVariableShiftRIPData covers the VEX and EVEX per-lane variable
// shift family, including scalar D/Q memory broadcast in EVEX encodings.
func decodeX86RawVariableShiftRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || p.mapNumber != 2 || p.pp != 1 ||
		p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	for _, spec := range amd64PerLaneVariableShiftSpecs {
		if p.opcode != int(spec.opcode) || p.w != (spec.laneBits != 32) ||
			!p.evex && !spec.vex {
			continue
		}
		width := 16 << p.vectorLength
		if p.evex && p.broadcast {
			width = spec.laneBits / 8
		}
		return x86RawRIPDataThroughDecoder(
			code, offset, mode, modRMIndex, width,
			decodedX86PerLaneVariableShiftInstruction, "per-lane variable shift",
		)
	}
	return Instr{}, 0, x86RawLiteralRange{}, false, nil
}

// decodeX86RawVPSHUFBRIPData covers every VEX and EVEX vector-width load
// accepted by Go's VPSHUFB table. The instruction has no scalar broadcast.
func decodeX86RawVPSHUFBRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || p.mapNumber != 2 || p.pp != 1 || p.opcode != 0 ||
		p.w || p.broadcast || p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width,
		decodedX86VPSHUFBInstruction, "VPSHUFB",
	)
}

// decodeX86RawPackedArithmeticRIPData covers the complete VEX/EVEX VPADD
// and VPSUB families, including their D/Q scalar memory broadcasts.
func decodeX86RawPackedArithmeticRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || p.mapNumber != 1 || p.pp != 1 ||
		p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	properties, recognized := decodedX86PackedIntegerArithmeticOps[byte(p.opcode)]
	if !recognized {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	if p.evex && p.broadcast {
		width = properties.laneBytes
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width,
		decodedX86PackedIntegerArithmeticInstruction, "packed integer arithmetic",
	)
}

// decodeX86RawFMA3RIPData handles all packed and scalar FMA3 encodings.
// Scalar operations read one lane; packed EVEX.b memory forms broadcast it.
func decodeX86RawFMA3RIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	half := p.evex && p.mapNumber == 6
	if !matched || p.mapNumber != 2 && !half || p.pp != 1 ||
		p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	spec, recognized := decodedX86VEXFMA3Ops[byte(p.opcode)]
	if !recognized {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	if spec.scalar || p.evex && p.broadcast {
		width = 4
		if p.w {
			width = 8
		}
		if half {
			width = 2
		}
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width,
		decodedX86VEXFMA3Instruction, "FMA3",
	)
}

// decodeX86RawBinaryFloatRIPData covers VADD/MUL/SUB/MIN/DIV/MAX packed and
// scalar forms, including raw AVX-512 FP16, plus scalar VSQRT and packed
// memory broadcast.
func decodeX86RawBinaryFloatRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	half := p.evex && p.mapNumber == 5 && (p.pp == 0 || p.pp == 2)
	if !matched || (p.mapNumber != 1 && !half) || p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	switch p.opcode {
	case 0x58, 0x59, 0x5c, 0x5d, 0x5e, 0x5f:
	case 0x51:
		if p.pp < 2 && !half {
			return Instr{}, 0, x86RawLiteralRange{}, false, nil
		}
	default:
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	if half {
		if p.pp == 2 || p.broadcast {
			width = 2
		}
	} else if p.pp >= 2 || p.evex && p.broadcast {
		width = 4
		if p.pp == 1 || p.pp == 3 {
			width = 8
		}
	}
	decoder := decodedX86VEXBinaryFloatInstruction
	if half && p.opcode == 0x51 && p.pp == 0 {
		decoder = decodedX86SameWidthConversionInstruction
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width,
		decoder, "binary floating",
	)
}

// decodeX86RawScalarFlagCompareRIPData covers VCOMIS{S,D} and
// VUCOMIS{S,D} VEX/EVEX memory sources. EVEX.b remains register-only SAE.
func decodeX86RawScalarFlagCompareRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || p.mapNumber != 1 || (p.opcode != 0x2e && p.opcode != 0x2f) ||
		(p.pp != 0 && p.pp != 1) || p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 4
	if p.pp == 1 {
		width = 8
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width,
		decodedX86ScalarFlagCompareInstruction, "scalar flag compare",
	)
}

// decodeX86RawVectorFloatCompareRIPData accounts for VCMP's trailing imm8
// when resolving the RIP displacement and its second Plan 9 operand.
func decodeX86RawVectorFloatCompareRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || p.mapNumber != 1 || p.opcode != 0xc2 ||
		p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	if p.pp >= 2 || p.evex && p.broadcast {
		width = 4
		if p.pp == 1 || p.pp == 3 {
			width = 8
		}
	}
	return x86RawRIPDataThroughDecoderOperand(
		code, offset, mode, modRMIndex, width, 1, 1,
		decodedX86VectorFloatCompareInstruction, "vector floating compare",
	)
}

// decodeX86RawPackedMultiplyRIPData covers the five packed word/D/Q multiply
// opcode rows, including EVEX D/Q memory broadcast and masked widths.
func decodeX86RawPackedMultiplyRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || p.pp != 1 || p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	form, recognized := x86PackedMultiplyFormFor(byte(p.mapNumber), byte(p.opcode))
	if !recognized || p.evex && p.broadcast && form.broadcastByte == 0 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	if p.evex && p.broadcast {
		width = form.broadcastByte
		if p.w {
			width = 8
		}
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width,
		decodedX86PackedMultiplyInstruction, "packed multiply",
	)
}

// decodeX86RawPackedAbsRIPData resolves source-local X/Y/Z VPABS loads,
// including the D/Q EVEX memory-broadcast lanes.
func decodeX86RawPackedAbsRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || p.mapNumber != 2 || p.pp != 1 || p.opcode < 0x1c || p.opcode > 0x1f ||
		p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	if p.evex && p.broadcast {
		width = [...]int{1, 2, 4, 8}[p.opcode-0x1c]
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width,
		decodedX86RawPackedAbsInstruction, "VPABS",
	)
}

// decodeX86RawVEXRoundRIPData accounts for VROUND's trailing imm8 while
// resolving packed or scalar source-local constant loads.
func decodeX86RawVEXRoundRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || p.mapNumber != 3 || p.pp != 1 || p.opcode < 0x08 || p.opcode > 0x0b ||
		p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	if p.opcode == 0x0a {
		width = 4
	} else if p.opcode == 0x0b {
		width = 8
	}
	return x86RawRIPDataThroughDecoderOperand(
		code, offset, mode, modRMIndex, width, 1, 1,
		decodedX86RawVEXRoundInstruction, "VROUND",
	)
}

// decodeX86RawDuplicateMoveRIPData covers legacy, VEX and EVEX MOVDDUP,
// MOVSLDUP and MOVSHDUP. The X-width DDUP form reads only one 64-bit lane;
// all other forms read the complete source vector.
func decodeX86RawDuplicateMoveRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := -1
	width := 0
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if matched && p.mapNumber == 1 && p.segment == "" && !p.addressOverride {
		double := p.pp == 3 && p.opcode == 0x12
		single := p.pp == 2 && (p.opcode == 0x12 || p.opcode == 0x16)
		if double || single {
			modRMIndex = offset + p.modRM
			width = 16 << p.vectorLength
			if double && p.vectorLength == 0 {
				width = 8
			}
		}
	} else {
		i := offset
		prefix := code[i]
		if prefix == 0xf2 || prefix == 0xf3 {
			i++
			if i < len(code) && code[i]&0xf0 == 0x40 {
				i++
			}
			if len(code) >= i+3 && code[i] == 0x0f &&
				(prefix == 0xf2 && code[i+1] == 0x12 ||
					prefix == 0xf3 && (code[i+1] == 0x12 || code[i+1] == 0x16)) {
				modRMIndex = i + 2
				width = 16
				if prefix == 0xf2 {
					width = 8
				}
			}
		}
	}
	if modRMIndex < 0 || len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width,
		decodedX86DuplicateMoveInstruction, "duplicate move",
	)
}

// decodeX86RawVectorByteShiftRIPData resolves EVEX X/Y/Z memory forms of
// VPSLLDQ and VPSRLDQ, accounting for the trailing shift-count imm8.
func decodeX86RawVectorByteShiftRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || !p.evex || p.mapNumber != 1 || p.pp != 1 || p.opcode != 0x73 ||
		p.segment != "" || p.addressOverride {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	group := int(code[modRMIndex]>>3) & 7
	if group != 3 && group != 7 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	return x86RawRIPDataThroughDecoderOperand(
		code, offset, mode, modRMIndex, 16<<p.vectorLength, 1, 1,
		decodedX86RawVectorByteShiftInstruction, "vector byte shift",
	)
}

// decodeX86RawPackedMADDRIPData covers VEX and EVEX VPMADDWD/VPMADDUBSW.
// Their memory operand reads the full vector and never broadcasts.
func decodeX86RawPackedMADDRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || p.pp != 1 || p.segment != "" || p.addressOverride ||
		p.evex && p.vectorLength > 2 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	if !(p.mapNumber == 1 && p.opcode == 0xf5 ||
		p.mapNumber == 2 && p.opcode == 0x04) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	decode := x86RawInstructionDecoder(decodedX86VEXPackedMADDInstruction)
	if p.evex {
		decode = decodedX86EVEXPackedMADDInstruction
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, 16<<p.vectorLength,
		decode, "packed multiply-add",
	)
}

// decodeX86RawVariableBlendRIPData covers all three VEX variable-blend
// mnemonics in their X/Y memory forms. The mask register follows the RIP
// displacement as an immediate selector, so it contributes to PC-relative
// target calculation but is not part of the memory operand.
func decodeX86RawVariableBlendRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || p.evex || p.mapNumber != 3 || p.pp != 1 || p.w ||
		p.segment != "" || p.addressOverride || p.vectorLength > 1 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	if p.opcode != 0x4a && p.opcode != 0x4b && p.opcode != 0x4c {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	return x86RawRIPDataThroughDecoderOperand(
		code, offset, mode, modRMIndex, 16<<p.vectorLength, 1, 1,
		decodedX86VariableBlendInstruction, "variable blend",
	)
}

// VPTERNLOGD/Q and VALIGND/Q share Go's immediate three-vector grammar.
// Their RIP-relative source is a full vector or a scalar broadcast, while
// imm8 trails the displacement in both cases.
func decodeX86RawImmediateThreeVectorRIPData(
	code []byte, offset, mode int, opcode byte,
	decode x86RawInstructionDecoder, family string,
) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || !p.evex || p.mapNumber != 3 || p.pp != 1 ||
		p.opcode != int(opcode) || p.segment != "" || p.addressOverride ||
		p.vectorLength > 2 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	if p.broadcast {
		width = 4
		if p.w {
			width = 8
		}
	}
	return x86RawRIPDataThroughDecoderOperand(
		code, offset, mode, modRMIndex, width, 1, 1, decode, family,
	)
}

func decodeX86RawPackedWidenConversionRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || !p.evex || p.mapNumber != 1 || p.pp != 1 ||
		p.segment != "" || p.addressOverride || p.vectorLength > 2 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	ops := x86RawPackedWidenConversionByOpcode
	if p.w {
		ops = x86RawPackedDoubleConversionByOpcode
	}
	if _, recognized := ops[p.opcode]; !recognized {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 8 << p.vectorLength
	if p.w {
		width *= 2
	}
	if p.broadcast {
		width = 4
		if p.w {
			width = 8
		}
	}
	return x86RawRIPDataThroughDecoderOperand(
		code, offset, mode, modRMIndex, width, 0, 0,
		decodedX86PackedWidenConversionInstruction, "packed widening conversion",
	)
}

// decodeX86RawLegacySIMDMoveRIPData covers the six 128-bit and two scalar
// legacy MOV loads in Go's yxmov table. The other direction is a store and
// does not read the RIP-relative source bytes.
func decodeX86RawLegacySIMDMoveRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	i := offset
	prefix := byte(0)
	unsafeAddress := false
	for i < len(code) {
		switch code[i] {
		case 0x64, 0x65, 0x67:
			unsafeAddress = true
		case 0x66, 0xf2, 0xf3:
			if prefix != 0 {
				return Instr{}, 0, x86RawLiteralRange{}, false, nil
			}
			prefix = code[i]
		default:
			if code[i] >= 0x40 && code[i] <= 0x4f {
				i++
			}
			goto opcode
		}
		i++
	}

opcode:
	if len(code) < i+3 || code[i] != 0x0f {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	opcode := code[i+1]
	valid := opcode == 0x10 ||
		opcode == 0x28 && (prefix == 0 || prefix == 0x66) ||
		opcode == 0x6f && (prefix == 0x66 || prefix == 0xf3)
	if !valid || code[i+2]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	if unsafeAddress {
		return Instr{}, 0, x86RawLiteralRange{}, true, fmt.Errorf("segment/address override is not source-layout safe")
	}
	width := 16
	if opcode == 0x10 && prefix == 0xf3 {
		width = 4
	} else if opcode == 0x10 && prefix == 0xf2 {
		width = 8
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, i+2, width,
		decodedX86LegacySIMDMoveInstruction, "legacy SIMD move",
	)
}

func decodedX86LegacySIMDMoveInstruction(code []byte, mode int) (Instr, int, bool, error) {
	inst, err := x86asm.Decode(code, mode)
	if err != nil || inst.Len <= 0 {
		return Instr{}, 0, true, err
	}
	syntax, err := decodedX86GoSyntax(inst, code[:inst.Len])
	if err != nil {
		return Instr{}, 0, true, err
	}
	instrs, err := parseDecodedX86Instruction(syntax)
	if err != nil || len(instrs) != 1 {
		if err == nil {
			err = fmt.Errorf("legacy SIMD move decoded as %d instructions", len(instrs))
		}
		return Instr{}, 0, true, err
	}
	return instrs[0], inst.Len, true, nil
}

type x86RawInstructionDecoder func([]byte, int) (Instr, int, bool, error)

// decodeX86RawIndexedPermuteRIPData preserves local vector/scalar constants
// for the complete VPERMI2/VPERMT2 family.
func decodeX86RawIndexedPermuteRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || !p.evex || p.mapNumber != 2 || p.pp != 1 ||
		(p.opcode < 0x75 || p.opcode > 0x77) && (p.opcode < 0x7d || p.opcode > 0x7f) ||
		p.segment != "" || p.addressOverride || p.vectorLength > 2 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	if p.broadcast {
		width = 4
		if p.opcode == 0x76 || p.opcode == 0x77 || p.opcode == 0x7e || p.opcode == 0x7f {
			if p.w {
				width = 8
			}
		}
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width,
		decodedX86IndexedPermuteInstruction, "EVEX indexed permute",
	)
}

// decodeX86RawEVEXVariableDwordPermuteRIPData preserves local Y/Z data or
// scalar broadcast constants for VPERMD and VPERMPS.
func decodeX86RawEVEXVariableDwordPermuteRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || !p.evex || p.mapNumber != 2 || p.pp != 1 || p.w ||
		(p.opcode != 0x36 && p.opcode != 0x16) ||
		p.segment != "" || p.addressOverride || p.vectorLength < 1 || p.vectorLength > 2 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	if p.broadcast {
		width = 4
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width,
		decodedX86EVEXVariableDwordPermuteInstruction, "EVEX variable dword permute",
	)
}

// decodeX86RawMaskCompareRIPData resolves local full-vector or D/Q broadcast
// constants and accounts for the comparison's trailing imm8.
func decodeX86RawMaskCompareRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	w := 0
	if p.w {
		w = 1
	}
	form, recognized := x86RawMaskCompareForms[[2]int{p.opcode, w}]
	if !matched || !p.evex || p.mapNumber != 3 || p.pp != 1 || !recognized ||
		p.segment != "" || p.addressOverride || p.vectorLength > 2 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	if p.broadcast {
		width = form.laneBytes
	}
	return x86RawRIPDataThroughDecoderOperand(
		code, offset, mode, modRMIndex, width, 1, 1,
		decodedX86RawMaskCompareInstruction, "EVEX mask compare",
	)
}

// decodeX86RawScaledRoundRIPData accounts for the trailing imm8 while
// resolving packed vectors, packed broadcasts, and scalar local constants.
func decodeX86RawScaledRoundRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	w := 0
	if p.w {
		w = 1
	}
	form, recognized := x86RawScaledRoundForms[[2]int{p.opcode, w}]
	if !matched || !p.evex || p.mapNumber != 3 || p.pp != 1 || !recognized ||
		p.segment != "" || p.addressOverride || p.vectorLength > 2 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	if form.scalar || p.broadcast {
		width = form.laneBytes
	}
	return x86RawRIPDataThroughDecoderOperand(
		code, offset, mode, modRMIndex, width, 1, 1,
		decodedX86RawScaledRoundInstruction, "EVEX scaled round",
	)
}

// decodeX86RawEVEXUnpackRIPData preserves source-local full-vector and
// broadcast-lane constants for all eight EVEX integer interleave rows.
func decodeX86RawEVEXUnpackRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	form, recognized := x86RawEVEXUnpackForms[p.opcode]
	if !matched || !p.evex || p.mapNumber != 1 || p.pp != 1 || !recognized ||
		p.segment != "" || p.addressOverride || p.vectorLength > 2 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	if p.broadcast {
		width = form.broadcastBytes
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width,
		decodedX86EVEXPackedUnpackInstruction, "EVEX packed unpack",
	)
}

// decodeX86RawBlockBroadcastRIPData resolves source-local m64/m128/m256
// blocks for all Go EVEX packed-block broadcasts.
func decodeX86RawBlockBroadcastRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	w := 0
	if p.w {
		w = 1
	}
	form, recognized := x86RawBlockBroadcastForms[[2]int{p.opcode, w}]
	if !matched || !p.evex || p.mapNumber != 2 || p.pp != 1 || !recognized ||
		p.segment != "" || p.addressOverride || p.vectorLength > 2 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, form.sourceBytes,
		decodedX86RawBlockBroadcastInstruction, "EVEX block broadcast",
	)
}

// decodeX86RawVariableRotateRIPData preserves local vector or scalar
// constant pools for all four EVEX per-lane variable-rotate forms.
func decodeX86RawVariableRotateRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	if !matched || !p.evex || p.mapNumber != 2 || p.pp != 1 ||
		(p.opcode != 0x14 && p.opcode != 0x15) ||
		p.segment != "" || p.addressOverride || p.vectorLength > 2 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	if p.broadcast {
		width = 4
		if p.w {
			width = 8
		}
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width,
		decodedX86RawVariableRotateInstruction, "EVEX variable rotate",
	)
}

// decodeX86RawQQToFloatRIPData resolves source-local literal pools for all
// QWORD-to-PS/PD encodings before the raw-byte decoder treats them as memory.
func decodeX86RawQQToFloatRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, matched := decodeX86RawVectorEncoding(code[offset:])
	_, _, recognized := x86RawQQToFloatForm(p)
	if !matched || !p.evex || !p.w || p.mapNumber != 1 || !recognized ||
		p.segment != "" || p.addressOverride || p.vectorLength > 2 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + p.modRM
	if len(code) <= modRMIndex || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 16 << p.vectorLength
	if p.broadcast {
		width = 8
	}
	return x86RawRIPDataThroughDecoder(
		code, offset, mode, modRMIndex, width,
		decodedX86RawQQToFloatInstruction, "QWORD-to-float conversion",
	)
}

func x86RawRIPDataThroughDecoder(
	code []byte, offset, mode, modRMIndex, width int,
	decode x86RawInstructionDecoder, family string,
) (Instr, int, x86RawLiteralRange, bool, error) {
	return x86RawRIPDataThroughDecoderOperand(
		code, offset, mode, modRMIndex, width, 0, 0, decode, family,
	)
}

func x86RawRIPDataThroughDecoderOperand(
	code []byte, offset, mode, modRMIndex, width, trailingBytes, sourceIndex int,
	decode x86RawInstructionDecoder, family string,
) (Instr, int, x86RawLiteralRange, bool, error) {
	patched, data, literal, err := x86RawRIPBytesWithSuffix(code, offset, modRMIndex, width, trailingBytes)
	if err != nil {
		return Instr{}, 0, x86RawLiteralRange{}, true, err
	}
	instruction, consumed, ok, err := decode(patched, mode)
	if err != nil || !ok || consumed != len(patched) ||
		len(instruction.Args) <= sourceIndex || instruction.Args[sourceIndex].Kind != OpMem {
		if err == nil {
			err = fmt.Errorf("RIP-relative %s did not match its grammar", family)
		}
		return Instr{}, 0, x86RawLiteralRange{}, true, err
	}
	setX86RawRIPDataOperand(&instruction, sourceIndex, data)
	return instruction, len(patched), literal, true, nil
}

func setX86RawRIPDataOperand(instruction *Instr, sourceIndex int, data []byte) {
	instruction.Args[sourceIndex] = Operand{Kind: OpSym, Sym: "·__plan9asm_raw_literal_pending(SB)"}
	instruction.x86Encoded = true
	instruction.x86RIPLiteral = true
	instruction.x86RIPLiteralData = data
	rawArgs := make([]string, len(instruction.Args))
	for index, operand := range instruction.Args {
		rawArgs[index] = operand.String()
	}
	instruction.Raw = fmt.Sprintf("%s %s", instruction.Op, strings.Join(rawArgs, ", "))
}

func setX86RawRIPLiteral(instruction *Instr, value int64) {
	instruction.Args[0] = Operand{Kind: OpImm, Imm: value}
	instruction.x86Encoded = true
	instruction.x86RIPLiteral = true
	rawArgs := make([]string, len(instruction.Args))
	for index, operand := range instruction.Args {
		rawArgs[index] = operand.String()
	}
	instruction.Raw = fmt.Sprintf("%s %s", instruction.Op, strings.Join(rawArgs, ", "))
}
