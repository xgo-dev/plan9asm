package plan9asm

import (
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

// Intel SDM Vol. 2A specifies 66/F3 0F 38 F6 /r for ADCX/ADOX. REX.W
// alone selects 64 bits: 0x66 is mandatory, not a 16-bit width override.
// Reuse the decoder's ADD r/m,reg ModRM/SIB grammar, never its flag semantics.
func decodeX86RawADX(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	return decodeX86RawADXWithMemory(code, offset, mode, x86RawMemoryDecoder{})
}

func decodeX86RawADXWithMemory(code []byte, offset, mode int, strategy x86RawMemoryDecoder) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 32 && mode != 64 || offset < 0 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	bytes := code[offset:]
	i := 0
	var repeat, segment, rex byte
	operandOverride, addressOverride, locked := false, false, false
	for i < len(bytes) {
		switch bytes[i] {
		case 0xf2, 0xf3:
			repeat, rex = bytes[i], 0
		case 0x66:
			operandOverride, rex = true, 0
		case 0x67:
			addressOverride, rex = true, 0
		case 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65:
			segment, rex = bytes[i], 0
		case 0xf0:
			locked, rex = true, 0
		default:
			if mode == 64 && bytes[i] >= 0x40 && bytes[i] <= 0x4f {
				rex = bytes[i]
				i++
				continue
			}
			goto opcode
		}
		i++
	}

opcode:
	prefix := repeat
	if prefix == 0 && operandOverride {
		prefix = 0x66
	}
	if prefix != 0x66 && prefix != 0xf3 || len(bytes) < i+3 ||
		bytes[i] != 0x0f || bytes[i+1] != 0x38 || bytes[i+2] != 0xf6 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	fail := func(reason string) (Instr, int, x86RawLiteralRange, bool, error) {
		return Instr{}, 0, x86RawLiteralRange{}, true, fmt.Errorf("ADX: %s", reason)
	}
	if locked {
		return fail("LOCK is not permitted")
	}
	bits := 32
	if rex&8 != 0 {
		bits = 64
	}
	var op Op
	for name, spec := range amd64ADXSpecs {
		if spec.prefix == prefix && spec.bits == bits {
			op = name
			break
		}
	}
	var equivalent []byte
	if segment == 0x64 || segment == 0x65 {
		equivalent = append(equivalent, segment)
	}
	if addressOverride {
		equivalent = append(equivalent, 0x67)
	}
	if rex != 0 {
		equivalent = append(equivalent, rex)
	}
	equivalent = append(equivalent, 0x03)
	header := len(equivalent)
	equivalent = append(equivalent, bytes[i+3:]...)
	decoded, err := x86asm.Decode(equivalent, mode)
	if err != nil || decoded.Op != x86asm.ADD || decoded.Len <= header {
		return fail("truncated or invalid ModRM/SIB address")
	}
	length := i + 3 + decoded.Len - header
	if length > 15 {
		return fail("encoding exceeds the 15-byte instruction limit")
	}
	if strategy.physicalPC {
		// A whole-object observer needs only the validated instruction's PC
		// and length. Do not patch RIP bytes, require source-local literal
		// storage, or return operands that could be mistaken for read facts.
		return Instr{}, length, x86RawLiteralRange{}, true, nil
	}
	if decoded.PCRel != 0 {
		if decoded.AddrSize != 64 || segment == 0x64 || segment == 0x65 {
			return fail("PC-relative source needs an unsegmented source-local literal")
		}
		patched, data, literal, err := x86RawRIPBytes(code, offset, offset+i+3, bits/8)
		if err != nil {
			return Instr{}, 0, x86RawLiteralRange{}, true, err
		}
		instruction, _, _, matched, err := decodeX86RawADX(patched, 0, mode)
		if err != nil || !matched {
			return fail("cannot represent patched source-local literal")
		}
		setX86RawRIPDataOperand(&instruction, 0, data)
		return instruction, length, literal, true, nil
	}
	memory, isMemory := decoded.Args[1].(x86asm.Mem)
	if isMemory {
		// The textual parser has only two address groups. Attach FS/GS
		// structurally so a 16-bit BX+SI address does not gain a third one.
		memory.Segment = 0
		decoded.Args[1] = memory
	}
	syntax, err := decodedX86GoSyntax(decoded, equivalent[:decoded.Len])
	if err != nil {
		return fail("cannot represent decoded operands")
	}
	parsed, err := parseDecodedX86Instruction(syntax)
	if err != nil || len(parsed) != 1 || len(parsed[0].Args) != 2 {
		return fail("cannot represent decoded register/memory form")
	}
	instruction := parsed[0]
	if isMemory {
		if memory.Base == 0 && memory.Index == 0 {
			instruction.Args[0] = Operand{Kind: OpMem, Mem: MemRef{Off: memory.Disp}}
		}
		if instruction.Args[0].Kind != OpMem {
			return fail("cannot represent decoded source as memory")
		}
		switch segment {
		case 0x64:
			instruction.Args[0].Mem.Segment = FS
		case 0x65:
			instruction.Args[0].Mem.Segment = GS
		}
	}
	instruction.Op = op
	instruction.x86Encoded = true
	instruction.x86AddressBits = decoded.AddrSize
	instruction.Raw = fmt.Sprintf("%s %s, %s", op, instruction.Args[0], instruction.Args[1])
	return instruction, length, x86RawLiteralRange{}, true, nil
}
