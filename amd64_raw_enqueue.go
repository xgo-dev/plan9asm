package plan9asm

import (
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

// Decode the shared ModRM/SIB grammar using an equivalent LEA understood by
// x/arch. ENQCMD's register width follows address size, not REX.W or 0x66.
func decodedX86EnqueueInstruction(code []byte, mode int) (Instr, int, bool, error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	var mandatory, segment, rex byte
	addressOverride, locked := false, false
	for i < len(code) {
		switch code[i] {
		case 0xf2, 0xf3:
			mandatory, rex = code[i], 0
		case 0x64, 0x65:
			segment, rex = code[i], 0
		case 0x26, 0x2e, 0x36, 0x3e:
			segment, rex = 0, 0
		case 0x66:
			rex = 0
		case 0x67:
			addressOverride, rex = true, 0
		case 0xf0:
			locked, rex = true, 0
		default:
			if mode == 64 && code[i] >= 0x40 && code[i] <= 0x4f {
				rex = code[i]
				i++
				continue
			}
			goto opcode
		}
		i++
	}

opcode:
	if len(code) < i+3 || code[i] != 0x0f || code[i+1] != 0x38 || code[i+2] != 0xf8 {
		return Instr{}, 0, false, nil
	}
	var op Op
	for name, prefix := range x86EnqueueOps {
		if prefix == mandatory {
			op = Op(name)
		}
	}
	if op == "" {
		return Instr{}, 0, false, nil
	}
	fail := func(reason string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("%s: %s", op, reason)
	}
	if locked {
		return fail("LOCK is not permitted")
	}
	if len(code) <= i+3 {
		return fail("missing ModRM byte")
	}
	if code[i+3]>>6 == 3 {
		return fail("the command source must be memory")
	}
	var lea []byte
	if segment != 0 {
		lea = append(lea, segment)
	}
	if addressOverride {
		lea = append(lea, 0x67)
	}
	if mode == 64 {
		lea = append(lea, rex|0x48)
	}
	lea = append(lea, 0x8d)
	leaHeader := len(lea)
	lea = append(lea, code[i+3:]...)
	decoded, err := x86asm.Decode(lea, mode)
	if err != nil || decoded.Op != x86asm.LEA {
		return fail("truncated or invalid memory address")
	}
	memory, ok := decoded.Args[1].(x86asm.Mem)
	if !ok {
		return fail("decoded source is not memory")
	}
	if memory.Base == x86asm.RIP || memory.Base == x86asm.EIP {
		return fail("PC-relative command source requires source-layout context")
	}
	// x/arch prints segment overrides as FS:..., while the Plan 9 parser
	// represents them as (...)(FS). Carry the segment structurally instead.
	memory.Segment = 0
	decoded.Args[1] = memory
	parsed, err := parseDecodedX86Instruction(x86asm.GoSyntax(decoded, 0, nil))
	if err != nil || len(parsed) != 1 || len(parsed[0].Args) != 2 {
		return fail("cannot represent decoded memory address")
	}
	length := i + 3 + decoded.Len - leaHeader
	if length > 15 {
		return fail("encoding exceeds the 15-byte instruction limit")
	}
	ins := parsed[0]
	if memory.Base == 0 && memory.Index == 0 {
		ins.Args[0] = Operand{Kind: OpMem, Mem: MemRef{Off: memory.Disp}}
	}
	if ins.Args[0].Kind != OpMem {
		return fail("cannot represent decoded source as memory")
	}
	switch segment {
	case 0x64:
		ins.Args[0].Mem.Segment = FS
	case 0x65:
		ins.Args[0].Mem.Segment = GS
	}
	ins.Op = op
	ins.x86AddressBits = decoded.AddrSize
	ins.Raw = fmt.Sprintf("%s %s, %s", op, ins.Args[0], ins.Args[1])
	return ins, length, true, nil
}
