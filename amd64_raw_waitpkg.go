package plan9asm

import "fmt"

// WAITPKG shares the 0F AE group with fences, CLWB and FSGSBASE. Mandatory
// prefix plus mod=3 and /6 select the family; REX.B selects the GP register.
// See Intel SDM volume 2B (UMONITOR, UMWAIT, TPAUSE), not x86asm's legacy
// MFENCE decoding of these bytes.
func decodedX86WaitPackageInstruction(code []byte, mode int) (Instr, int, bool, error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	var repeat, segment, rex byte
	operandOverride, addressOverride, locked := false, false, false
	for i < len(code) {
		switch code[i] {
		case 0xf2, 0xf3:
			repeat, rex = code[i], 0
		case 0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65:
			segment, rex = code[i], 0
		case 0x66:
			operandOverride, rex = true, 0
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
	prefix := repeat
	if prefix == 0 && operandOverride {
		prefix = 0x66
	}
	if prefix == 0 || len(code) < i+2 || code[i] != 0x0f || code[i+1] != 0xae {
		return Instr{}, 0, false, nil
	}
	if len(code) < i+3 {
		return Instr{}, 0, true, fmt.Errorf("truncated WAITPKG ModRM")
	}
	modrm := code[i+2]
	if modrm&0x38 != 0x30 || modrm>>6 != 3 {
		// In particular, 66 0F AE /6 with a memory operand is CLWB.
		return Instr{}, 0, false, nil
	}
	if locked || i+3 > 15 {
		return Instr{}, 0, true, fmt.Errorf("invalid WAITPKG LOCK prefix or instruction length")
	}
	var op Op
	for name, spec := range amd64ImplicitSystemSpecs {
		if spec.rawPrefix == prefix {
			op = name
			break
		}
	}
	register, ok := decodedX86GeneralRegister(int(modrm&7) + int(rex&1)*8)
	if !ok || op == "" {
		return Instr{}, 0, true, fmt.Errorf("invalid WAITPKG register or mandatory prefix")
	}
	ins := Instr{
		Op: op, Args: []Operand{{Kind: OpReg, Reg: register}},
		Raw: fmt.Sprintf("%s %s", op, register), x86Encoded: true,
	}
	if amd64ImplicitSystemSpecs[op].operand == amd64ImplicitSystemAddressGP {
		ins.x86AddressBits = mode
		if addressOverride {
			ins.x86AddressBits /= 2
		}
		ins.x86SegmentPrefix = segment
	}
	return ins, i + 3, true, nil
}
