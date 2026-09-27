package plan9asm

import (
	"fmt"
	"strings"
)

type x86RawHalfConversionForm struct {
	op        Op
	mapNumber int
	opcode    int
	immediate bool
	rawOnly   bool
}

// The complete F16C/AVX-512 half/single conversion rows. The FP16 map5/map6
// forms are raw-only in Go 1.27. Only legacy VCVTPS2PH reverses ModRM roles
// and appends imm8; FP16 narrowing instead loads and supports broadcasts.
var x86RawHalfConversionForms = [...]x86RawHalfConversionForm{
	{op: "VCVTPH2PS", mapNumber: 2, opcode: 0x13},
	{op: "VCVTPS2PH", mapNumber: 3, opcode: 0x1d, immediate: true},
	{op: "VCVTPH2PSX", mapNumber: 6, opcode: 0x13, rawOnly: true},
	{op: "VCVTPS2PHX", mapNumber: 5, opcode: 0x1d, rawOnly: true},
}

func decodedX86PackedHalfConversionInstruction(code []byte, mode int) (Instr, int, bool, error) {
	p, recognized := decodeX86RawVectorEncoding(code)
	if !recognized || p.pp != 1 {
		return Instr{}, 0, false, nil
	}
	var form x86RawHalfConversionForm
	for _, candidate := range x86RawHalfConversionForms {
		if p.mapNumber == candidate.mapNumber && p.opcode == candidate.opcode {
			form = candidate
			break
		}
	}
	if form.op == "" {
		return Instr{}, 0, false, nil
	}
	fail := func(message string) (Instr, int, bool, error) {
		return Instr{}, 0, true, fmt.Errorf("packed half conversion: %s", message)
	}
	if mode != 32 && mode != 64 {
		return fail("unsupported x86 mode")
	}
	if p.addressOverride {
		return fail("address-size override is not source-layout safe")
	}
	if form.rawOnly && !p.evex {
		return fail("FP16 conversion requires EVEX")
	}
	if p.upper != 0 || p.w || p.evex && !p.fixed {
		return fail("invalid reserved vvvv/V', W or EVEX fixed bit")
	}
	if p.evex && p.zero && p.mask == 0 {
		return fail("zeroing requires a nonzero mask")
	}
	if len(code) <= p.modRM {
		return fail("missing ModRM byte")
	}
	registerSource := code[p.modRM]>>6 == 3
	vectorLength := p.vectorLength
	op := form.op
	if p.broadcast && form.rawOnly {
		if registerSource {
			vectorLength = 2
			if form.op == "VCVTPS2PHX" {
				op += [...]Op{".RN_SAE", ".RD_SAE", ".RU_SAE", ".RZ_SAE"}[p.vectorLength]
			} else {
				// LLVM emits LL=00 for SAE-only; LL does not encode VL here.
				op += ".SAE"
			}
		} else {
			op += ".BCST"
		}
	}
	if vectorLength > 2 {
		return fail("reserved vector length")
	}
	if form.rawOnly && mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0) {
		return fail("extended register or address in 32-bit mode")
	}
	if !p.evex && mode == 32 && (p.r != 0 || p.b != 0 || p.x != 0) {
		return fail("extended VEX register in 32-bit mode")
	}
	if p.evex && mode == 32 && code[p.modRM]>>6 != 3 && (p.b != 0 || p.x != 0) {
		return fail("extended memory address in 32-bit mode")
	}
	if p.broadcast && !form.rawOnly {
		if !p.evex || p.vectorLength != 2 || form.op == "VCVTPH2PS" && code[p.modRM]>>6 != 3 {
			return fail("SAE requires the EVEX Z-width register form")
		}
		op += ".SAE"
	}

	vector := [...]string{"X", "Y", "Z"}[vectorLength]
	shorter := "X"
	if vectorLength == 2 {
		shorter = "Y"
	}
	if p.zero {
		op += ".Z"
	}
	modRM := code[p.modRM]
	regNumber := int(modRM>>3&7) + p.r*8
	register := func(prefix string) Operand {
		return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("%s%d", prefix, regNumber))}
	}
	decodeRM := func(prefix string) (Operand, int, error) {
		if p.evex {
			width := 8 << vectorLength
			if form.op == "VCVTPS2PHX" {
				width *= 2
			}
			if form.rawOnly && p.broadcast && !registerSource {
				width = amd64HalfConversionSpecs[string(form.op)].inputBits / 8
			}
			return decodedX86EVEXRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, prefix, width)
		}
		return decodedX86VEXVectorRMOperand(code[p.modRM:], mode, p.b, p.x, p.segment, prefix)
	}

	args := make([]Operand, 0, 4)
	var consumed int
	if !form.immediate {
		sourcePrefix, destinationPrefix := shorter, vector
		if form.op == "VCVTPS2PHX" {
			sourcePrefix, destinationPrefix = vector, shorter
		}
		source, n, err := decodeRM(sourcePrefix)
		if err != nil {
			return Instr{}, 0, true, err
		}
		consumed = n
		args = append(args, source)
		if p.mask != 0 {
			args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
		}
		args = append(args, register(destinationPrefix))
	} else {
		destination, n, err := decodeRM(shorter)
		if err != nil {
			return Instr{}, 0, true, err
		}
		consumed = n
		if len(code) <= p.modRM+consumed {
			return fail("missing imm8 rounding control")
		}
		args = append(args, Operand{Kind: OpImm, Imm: int64(code[p.modRM+consumed])})
		args = append(args, register(vector))
		if p.mask != 0 {
			args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("K%d", p.mask))})
		}
		args = append(args, destination)
		consumed++
	}
	printed := make([]string, len(args))
	for index, arg := range args {
		printed[index] = arg.String()
	}
	return Instr{
		Op: op, Args: args, Raw: fmt.Sprintf("%s %s", op, strings.Join(printed, ", ")),
		x86Encoded: form.rawOnly, x86VectorBytes: 16 << vectorLength,
	}, p.modRM + consumed, true, nil
}

func decodeX86RawFP16ConversionRIPData(code []byte, offset, mode int) (Instr, int, x86RawLiteralRange, bool, error) {
	if mode != 64 || offset >= len(code) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	p, ok := decodeX86RawVectorEncoding(code[offset:])
	if !ok || !p.evex || p.pp != 1 || p.segment != "" || p.addressOverride ||
		!(p.mapNumber == 6 && p.opcode == 0x13 || p.mapNumber == 5 && p.opcode == 0x1d) {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	modRM := offset + p.modRM
	if len(code) <= modRM || code[modRM]&0xc7 != 5 {
		return Instr{}, 0, x86RawLiteralRange{}, false, nil
	}
	width := 8 << p.vectorLength
	if p.broadcast {
		width = 2
	}
	if p.mapNumber == 5 {
		width *= 2
	}
	return x86RawRIPDataThroughDecoder(code, offset, mode, modRM, width, decodedX86PackedHalfConversionInstruction, "FP16 conversion")
}
