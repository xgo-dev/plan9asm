package plan9asm

import (
	"fmt"
	"strings"
)

// Opcode E6 has three Go 1.27 conversion grammars. VEX.W is ignored; EVEX.W
// distinguishes the dword/double family from qword/double instructions. LL
// selects the vector width except when EVEX.b enables rounding or SAE on a
// register-source 512-bit double-to-dword form.
func decodedX86PackedDoubleDwordInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, matched := decodeX86RawVectorEncoding(code)
	if !matched || p.mapNumber != 1 || p.opcode != 0xe6 || (p.pp != 1 && p.pp != 2 && p.pp != 3) {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("packed double/dword conversion: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if p.upper != 0 {
		return fail("reserved vvvv/V' field")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	if p.evex {
		if p.w != (p.pp != 2) {
			// EVEX.W selects another conversion family, such as VCVTQQ2PD.
			return Instr{}, 0, false, nil
		}
		if !p.fixed || p.zero && p.mask == 0 {
			return fail("invalid EVEX fixed, mask or zeroing field")
		}
	} else if p.vectorLength > 1 {
		return fail("invalid VEX vector length")
	}
	registerSource := code[p.modRM]>>6 == 3
	if mode == 32 {
		if !p.evex && (p.r != 0 || p.b != 0 || p.x != 0) {
			return fail("extended VEX register in 32-bit mode")
		}
		if p.evex && !registerSource && (p.b != 0 || p.x != 0) {
			return fail("extended memory address in 32-bit mode")
		}
	}
	rounding := p.evex && p.broadcast && registerSource
	broadcast := p.evex && p.broadcast && !registerSource
	if p.pp == 2 && rounding {
		return fail("dword-to-double has no SAE or rounding form")
	}
	if p.evex && !rounding && p.vectorLength > 2 {
		return fail("reserved EVEX vector length")
	}
	if p.pp != 2 && rounding && !p.evex {
		return fail("rounding or SAE requires EVEX")
	}

	vectorLength := p.vectorLength
	if rounding {
		vectorLength = 2 // Register-source SAE/rounding implies 512 bits.
	}
	var op Op
	var sourcePrefix, destinationPrefix string
	var memoryScale int
	if p.pp == 2 {
		op = "VCVTDQ2PD"
		destinationPrefix = [...]string{"X", "Y", "Z"}[vectorLength]
		sourcePrefix = "X"
		if vectorLength == 2 {
			sourcePrefix = "Y"
		}
		memoryScale = 8 << vectorLength
	} else {
		stem := "VCVTPD2DQ"
		if p.pp == 1 {
			stem = "VCVTTPD2DQ"
		}
		sourcePrefix = [...]string{"X", "Y", "Z"}[vectorLength]
		destinationPrefix = "X"
		if vectorLength == 2 {
			destinationPrefix = "Y"
		}
		op = Op(stem)
		if vectorLength < 2 {
			op = Op(stem + [...]string{"X", "Y"}[vectorLength])
		}
		memoryScale = 16 << vectorLength
	}
	if mode == 32 {
		if sourcePrefix == "Z" && registerSource && (p.b != 0 || p.x != 0) {
			return fail("Z8-Z31 are not Go assembler source registers in 32-bit mode")
		}
		if destinationPrefix == "Z" && p.r != 0 {
			return fail("Z8-Z31 are not Go assembler destination registers in 32-bit mode")
		}
	}
	if _, exists := amd64PackedDoubleDwordOps[string(op)]; !exists {
		return fail("encoding has no Go packed conversion form")
	}
	if rounding {
		if p.pp == 1 {
			op += ".SAE"
		} else {
			op += [...]Op{".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE"}[p.vectorLength]
		}
	} else if broadcast {
		op += ".BCST"
		if p.pp == 2 {
			memoryScale = 4
		} else {
			memoryScale = 8
		}
	}
	if p.zero {
		op += ".Z"
	}

	var source Operand
	var consumed int
	var err error
	if p.evex {
		source, consumed, err = decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, sourcePrefix, memoryScale)
	} else {
		source, consumed, err = decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, sourcePrefix)
	}
	if err != nil {
		return Instr{}, 0, true, err
	}
	destination := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", destinationPrefix, int(code[p.modRM]>>3&7)+p.r*8))}
	args := []Operand{source}
	if p.mask != 0 {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
	}
	args = append(args, destination)
	printed := make([]string, len(args))
	for i, arg := range args {
		printed[i] = arg.String()
	}
	return Instr{Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", "))}, p.modRM + consumed, true, nil
}
