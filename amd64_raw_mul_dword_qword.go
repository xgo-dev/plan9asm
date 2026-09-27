package plan9asm

import (
	"fmt"
	"strings"
)

// decodedX86DwordToQwordMultiplyInstruction recognizes every VEX and EVEX
// encoding of VPMULDQ and VPMULUDQ in Go 1.27's _yvandnpd table. x/arch
// v0.14 does not decode these encodings, so raw BYTE/LONG directive users
// need the complete X/Y/Z, memory, mask, zeroing, and broadcast family here.
func decodedX86DwordToQwordMultiplyInstruction(code []byte, mode int) (instruction Instr, length int, ok bool, err error) {
	if mode != 32 && mode != 64 {
		return Instr{}, 0, false, nil
	}
	i := 0
	segment := Reg("")
	addressOverride := false
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
			goto vex
		}
	}

vex:
	if i >= len(code) {
		return Instr{}, 0, false, nil
	}

	var (
		opcodeIndex int
		modRMIndex  int
		mapSelect   int
		width       int
		rExt        int
		rHigh       int
		xExt        int
		bExt        int
		vRegister   int
		vHigh       int
		rmHigh      int
		masked      bool
		zeroing     bool
		broadcast   bool
		mask        int
		evex        bool
	)

	switch code[i] {
	case 0xc5:
		if len(code) < i+3 {
			return Instr{}, 0, false, nil
		}
		vexByte := code[i+1]
		opcodeIndex, modRMIndex = i+2, i+3
		mapSelect = 1
		if vexByte&3 != 1 || code[opcodeIndex] != 0xf4 {
			return Instr{}, 0, false, nil
		}
		rExt = int(^vexByte>>7) & 1
		vRegister = int(^vexByte>>3) & 15
		width = 16
		if vexByte&4 != 0 {
			width = 32
		}
	case 0xc4:
		if len(code) < i+4 {
			return Instr{}, 0, false, nil
		}
		vexExt, vexByte := code[i+1], code[i+2]
		opcodeIndex, modRMIndex = i+3, i+4
		mapSelect = int(vexExt & 0x1f)
		if vexByte&3 != 1 || !x86DwordToQwordMultiplyOpcode(mapSelect, code[opcodeIndex]) {
			return Instr{}, 0, false, nil
		}
		ok = true
		if vexByte&0x80 != 0 {
			return Instr{}, 0, true, fmt.Errorf("VEX.W must be zero")
		}
		rExt = int(^vexExt>>7) & 1
		xExt = int(^vexExt>>6) & 1
		bExt = int(^vexExt>>5) & 1
		vRegister = int(^vexByte>>3) & 15
		width = 16
		if vexByte&4 != 0 {
			width = 32
		}
	case 0x62:
		if len(code) < i+5 {
			return Instr{}, 0, false, nil
		}
		p0, p1, p2 := code[i+1], code[i+2], code[i+3]
		opcodeIndex, modRMIndex = i+4, i+5
		mapSelect = int(p0 & 3)
		if p0&0x0c != 0 || p1&3 != 1 || !x86DwordToQwordMultiplyOpcode(mapSelect, code[opcodeIndex]) {
			return Instr{}, 0, false, nil
		}
		ok, evex = true, true
		if p1&0x84 != 0x84 {
			return Instr{}, 0, true, fmt.Errorf("EVEX.W must be one and reserved bit must be set")
		}
		rExt = int(^p0>>7) & 1
		rHigh = int(^p0>>4) & 1
		xExt = int(^p0>>6) & 1
		bExt = int(^p0>>5) & 1
		vRegister = int(^p1>>3) & 15
		vHigh = int(^p2>>3) & 1
		rmHigh = xExt
		zeroing = p2&0x80 != 0
		broadcast = p2&0x10 != 0
		mask = int(p2 & 7)
		masked = mask != 0
		switch p2 >> 5 & 3 {
		case 0:
			width = 16
		case 1:
			width = 32
		case 2:
			width = 64
		default:
			return Instr{}, 0, true, fmt.Errorf("reserved EVEX vector length")
		}
	default:
		return Instr{}, 0, false, nil
	}

	if !ok {
		ok = true
	}
	if len(code) <= modRMIndex {
		return Instr{}, 0, true, fmt.Errorf("missing ModRM byte")
	}
	if addressOverride {
		return Instr{}, 0, true, fmt.Errorf("address-size override is not source-layout safe")
	}
	modRM := code[modRMIndex]
	if evex && broadcast && modRM>>6 == 3 {
		return Instr{}, 0, true, fmt.Errorf("EVEX broadcast requires a memory source")
	}
	if zeroing && !masked {
		return Instr{}, 0, true, fmt.Errorf("EVEX zeroing requires a nonzero mask")
	}

	destinationNumber := int(modRM>>3&7) + rExt*8 + rHigh*16
	secondNumber := vRegister + vHigh*16
	if mode == 32 && (destinationNumber >= 8 || secondNumber >= 8) {
		return Instr{}, 0, true, fmt.Errorf("extended vector or address register in 32-bit mode")
	}
	destination, valid := decodedX86VectorRegister(destinationNumber, width)
	if !valid {
		return Instr{}, 0, true, fmt.Errorf("invalid destination vector register %d", destinationNumber)
	}
	second, valid := decodedX86VectorRegister(secondNumber, width)
	if !valid {
		return Instr{}, 0, true, fmt.Errorf("invalid second-source vector register %d", secondNumber)
	}
	first, consumed, err := decodedX86VectorRMSource(code[modRMIndex:], mode, bExt, xExt, rmHigh, width, segment)
	if err != nil {
		return Instr{}, 0, true, err
	}

	op := "VPMULUDQ"
	if mapSelect == 2 {
		op = "VPMULDQ"
	}
	var suffixes []string
	if broadcast {
		suffixes = append(suffixes, "BCST")
	}
	if zeroing {
		suffixes = append(suffixes, "Z")
	}
	if len(suffixes) != 0 {
		op += "." + strings.Join(suffixes, ".")
	}
	args := []Operand{first, {Kind: OpReg, Reg: second}}
	if masked {
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", mask))})
	}
	args = append(args, Operand{Kind: OpReg, Reg: destination})
	rawArgs := make([]string, len(args))
	for index := range args {
		rawArgs[index] = args[index].String()
	}
	return Instr{Op: Op(op), Args: args, Raw: op + " " + strings.Join(rawArgs, ", ")}, modRMIndex + consumed, true, nil
}

func x86DwordToQwordMultiplyOpcode(mapSelect int, opcode byte) bool {
	return mapSelect == 1 && opcode == 0xf4 || mapSelect == 2 && opcode == 0x28
}

func decodedX86VectorRMSource(code []byte, mode, bExt, xExt, highExt, width int, segment Reg) (Operand, int, error) {
	if len(code) == 0 {
		return Operand{}, 0, fmt.Errorf("missing ModRM byte")
	}
	if code[0]>>6 != 3 {
		return decodedX86VEXRMSource(code, mode, bExt, xExt, segment)
	}
	number := int(code[0]&7) + bExt*8 + highExt*16
	if mode == 32 && number >= 8 {
		return Operand{}, 0, fmt.Errorf("extended vector register in 32-bit mode")
	}
	register, ok := decodedX86VectorRegister(number, width)
	if !ok {
		return Operand{}, 0, fmt.Errorf("invalid first-source vector register %d", number)
	}
	return Operand{Kind: OpReg, Reg: register}, 1, nil
}

func decodedX86VectorRegister(number, width int) (Reg, bool) {
	prefix := ""
	switch width {
	case 16:
		prefix = "X"
	case 32:
		prefix = "Y"
	case 64:
		prefix = "Z"
	default:
		return "", false
	}
	if number < 0 || number >= 32 {
		return "", false
	}
	return Reg(fmt.Sprintf("%s%d", prefix, number)), true
}
