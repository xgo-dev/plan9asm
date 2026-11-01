package plan9asm

import (
	"fmt"
	"strings"
)

type x86PackedLogicalEncoding uint8

const (
	x86PackedLogicalLegacyFP x86PackedLogicalEncoding = iota
	x86PackedLogicalLegacyInteger
	x86PackedLogicalVEX
	x86PackedLogicalVEXOrEVEX
	x86PackedLogicalEVEX
)

type x86PackedLogicalSpec struct {
	laneBits int
	mode     amd64PackedLogicalMode
	encoding x86PackedLogicalEncoding
	// These are opcode attributes, not inferred from a shared ytab. Go's
	// avx_optabs supplies N4 for PS/D and N8 for PD/Q, and zeroing for each
	// EVEX row. VEX-only integer and legacy forms have neither attribute.
	broadcastBytes int
	zeroing        bool
}

var x86PackedLogicalSpecs = map[Op]x86PackedLogicalSpec{
	"ANDPS":   {32, amd64PackedLogicalAnd, x86PackedLogicalLegacyFP, 0, false},
	"ANDPD":   {64, amd64PackedLogicalAnd, x86PackedLogicalLegacyFP, 0, false},
	"ANDNPS":  {32, amd64PackedLogicalAndNot, x86PackedLogicalLegacyFP, 0, false},
	"ANDNPD":  {64, amd64PackedLogicalAndNot, x86PackedLogicalLegacyFP, 0, false},
	"ORPS":    {32, amd64PackedLogicalOr, x86PackedLogicalLegacyFP, 0, false},
	"ORPD":    {64, amd64PackedLogicalOr, x86PackedLogicalLegacyFP, 0, false},
	"XORPS":   {32, amd64PackedLogicalXor, x86PackedLogicalLegacyFP, 0, false},
	"XORPD":   {64, amd64PackedLogicalXor, x86PackedLogicalLegacyFP, 0, false},
	"PAND":    {8, amd64PackedLogicalAnd, x86PackedLogicalLegacyInteger, 0, false},
	"PANDN":   {8, amd64PackedLogicalAndNot, x86PackedLogicalLegacyInteger, 0, false},
	"POR":     {8, amd64PackedLogicalOr, x86PackedLogicalLegacyInteger, 0, false},
	"PXOR":    {8, amd64PackedLogicalXor, x86PackedLogicalLegacyInteger, 0, false},
	"VANDPS":  {32, amd64PackedLogicalAnd, x86PackedLogicalVEXOrEVEX, 4, true},
	"VANDPD":  {64, amd64PackedLogicalAnd, x86PackedLogicalVEXOrEVEX, 8, true},
	"VANDNPS": {32, amd64PackedLogicalAndNot, x86PackedLogicalVEXOrEVEX, 4, true},
	"VANDNPD": {64, amd64PackedLogicalAndNot, x86PackedLogicalVEXOrEVEX, 8, true},
	"VORPS":   {32, amd64PackedLogicalOr, x86PackedLogicalVEXOrEVEX, 4, true},
	"VORPD":   {64, amd64PackedLogicalOr, x86PackedLogicalVEXOrEVEX, 8, true},
	"VXORPS":  {32, amd64PackedLogicalXor, x86PackedLogicalVEXOrEVEX, 4, true},
	"VXORPD":  {64, amd64PackedLogicalXor, x86PackedLogicalVEXOrEVEX, 8, true},
	"VPAND":   {8, amd64PackedLogicalAnd, x86PackedLogicalVEX, 0, false},
	"VPANDN":  {8, amd64PackedLogicalAndNot, x86PackedLogicalVEX, 0, false},
	"VPOR":    {8, amd64PackedLogicalOr, x86PackedLogicalVEX, 0, false},
	"VPXOR":   {8, amd64PackedLogicalXor, x86PackedLogicalVEX, 0, false},
	"VPANDD":  {32, amd64PackedLogicalAnd, x86PackedLogicalEVEX, 4, true},
	"VPANDQ":  {64, amd64PackedLogicalAnd, x86PackedLogicalEVEX, 8, true},
	"VPANDND": {32, amd64PackedLogicalAndNot, x86PackedLogicalEVEX, 4, true},
	"VPANDNQ": {64, amd64PackedLogicalAndNot, x86PackedLogicalEVEX, 8, true},
	"VPORD":   {32, amd64PackedLogicalOr, x86PackedLogicalEVEX, 4, true},
	"VPORQ":   {64, amd64PackedLogicalOr, x86PackedLogicalEVEX, 8, true},
	"VPXORD":  {32, amd64PackedLogicalXor, x86PackedLogicalEVEX, 4, true},
	"VPXORQ":  {64, amd64PackedLogicalXor, x86PackedLogicalEVEX, 8, true},
}

type x86PackedLogicalForm struct {
	x86PackedBinaryForm
	spec   x86PackedLogicalSpec
	source Operand
}

// The first input is known; these bits still depend on the second input.
// ANDNOT is first & ^second in Go operand order, so it has AND's dependency.
// This numerical projection neither removes the first read nor grants storage.
func x86PackedLogicalSecondBits(mode amd64PackedLogicalMode, first byte) byte {
	switch mode {
	case amd64PackedLogicalAnd, amd64PackedLogicalAndNot:
		return first
	case amd64PackedLogicalOr:
		return ^first
	default:
		return 255 // XOR cannot remove an unknown input bit.
	}
}

// This is a pure numerical-byte dependency, shared by independent consumers.
// A validated form and initialized mask are prerequisites; the result grants
// no memory, frame, source-selection or caller permission. Higher physical
// bytes are updated separately according to the consumer's encoding model.
func x86PackedLogicalDefinedBytes(ins Instr, form x86PackedLogicalForm, first, second, old uint64) uint64 {
	width := x86CallerVectorByteMask(int64(form.byteWidth))
	known := first & second & width
	if form.memory < 0 && ins.Args[form.first].Reg == ins.Args[form.second].Reg &&
		(form.spec.mode == amd64PackedLogicalXor || form.spec.mode == amd64PackedLogicalAndNot) {
		known = width
	}
	if form.mask >= 0 && !form.zeroing {
		known &= old // A defined mask is not necessarily all ones.
	}
	return known
}

// Reuse the complete logical grammar and its numerical zero identity. A
// legacy XMM operation preserves upper aliases and requires aligned m128;
// neither the descriptor nor a same-register zero grants memory authority.
func x86TypedLegacyLogicalByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	local := ins
	local.Op = op
	form, known, err := x86PackedLogicalProperties(local, arch)
	if known && ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return x86TypedByteEffect{}, true, fmt.Errorf("packed logical dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	if !known || err != nil || !form.legacy || form.mmx {
		return x86TypedByteEffect{}, known && (err != nil || form.legacy && !form.mmx), err
	}
	effect := x86PackedBinaryDependencyEffect(ins, form.x86PackedBinaryForm, form.source)
	return x86PackedLogicalZeroDependencies(ins, form, effect), true, nil
}

// Apply the shared numerical identity only after the consumer has validated
// its encoding and storage roles. A memory operand never becomes a zero idiom.
func x86PackedLogicalZeroDependencies(ins Instr, form x86PackedLogicalForm, effect x86TypedByteEffect) x86TypedByteEffect {
	if x86PackedLogicalDefinedBytes(ins, form, 0, 0, 0) != 0 {
		for index := range effect.operands {
			effect.operands[index].read = false
		}
	}
	return effect
}

// These fields describe only an operand grammar. Arithmetic, interleave and
// bitwise effects remain in their own typed operation specs and consumers.
type x86PackedBinarySpec struct {
	encoding       x86PackedLogicalEncoding
	broadcastBytes int
	zeroing        bool
}

type x86PackedBinaryForm struct {
	byteWidth, first, second, destination int
	mask, memory, memoryBytes             int
	legacy, mmx, broadcast, zeroing       bool
}

// Go accepts some X/Y high-bank spellings in mode32 without proving their
// physical register identity. Apply this only after the family's syntax has
// been validated; it grants no initialized values, ABI or memory permissions.
func x86Mode32VectorRegisterContext(ins Instr, goarch string) error {
	if goarch != "386" {
		return nil
	}
	for _, operand := range ins.Args {
		index, valid := amd64VectorRegisterIndex(operand.Reg, amd64VectorByteWidth(operand.Reg))
		if operand.Kind == OpReg && valid && index >= 8 {
			return fmt.Errorf("%w: 386 %s register %s has no proved physical mode32 binding", ErrProbeNeedsContext, ins.Op, operand.Reg)
		}
	}
	return nil
}

// This grammar supplies no initialized values, address bounds or caller
// privileges. The emitter and the private source/CFG proof share only forms.
func x86PackedLogicalProperties(ins Instr, goarch string) (x86PackedLogicalForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, recognized := x86PackedLogicalSpecs[Op(base)]
	if !recognized {
		return x86PackedLogicalForm{}, false, nil
	}
	local := ins
	if spec.encoding == x86PackedLogicalLegacyInteger {
		var err error
		local, err = x86LegacyMMXReadInstruction(ins, goarch)
		if err != nil {
			return x86PackedLogicalForm{}, true, err
		}
	}
	form, err := x86PackedBinaryProperties(local, goarch, x86PackedBinarySpec{
		encoding: spec.encoding, broadcastBytes: spec.broadcastBytes, zeroing: spec.zeroing,
	})
	if err == nil {
		err = x86Mode32VectorRegisterContext(ins, goarch)
	}
	result := x86PackedLogicalForm{x86PackedBinaryForm: form, spec: spec}
	if err == nil {
		result.source = local.Args[form.first]
	}
	return result, true, err
}

func x86PackedBinaryProperties(ins Instr, goarch string, spec x86PackedBinarySpec) (x86PackedBinaryForm, error) {
	return x86PackedBinaryOperandGrammar(ins, goarch, spec, false)
}

// Only a validated unary projection or physical decoder may avoid the named
// four-operand frontend cap. Every other grammar axis keeps the actual GOARCH.
func x86PackedBinaryOperandGrammar(ins Instr, goarch string, spec x86PackedBinarySpec, mode32MaskOperands bool) (x86PackedBinaryForm, error) {
	_, suffix, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	form := x86PackedBinaryForm{first: 0, second: 1, destination: len(ins.Args) - 1, mask: -1, memory: -1}
	fail := func() (x86PackedBinaryForm, error) {
		return form, fmt.Errorf("%s %s operands/suffix outside Go packed binary grammar: %q", goarch, ins.Op, ins.Raw)
	}
	if goarch != "386" && goarch != "amd64" {
		return fail()
	}
	form.legacy = spec.encoding == x86PackedLogicalLegacyFP || spec.encoding == x86PackedLogicalLegacyInteger
	if form.legacy {
		if dotted || len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
			return fail()
		}
		form.byteWidth = 16
		_, form.mmx = amd64ParseMReg(ins.Args[1].Reg)
		if form.mmx {
			if spec.encoding != x86PackedLogicalLegacyInteger || goarch != "amd64" {
				return fail()
			}
			form.byteWidth = 8
		}
	} else {
		switch suffix {
		case "":
			if dotted {
				return fail()
			}
		case "Z":
			form.zeroing = true
		case "BCST":
			form.broadcast = true
		case "BCST.Z":
			form.broadcast, form.zeroing = true, true
		default:
			return fail()
		}
		if len(ins.Args) != 3 && len(ins.Args) != 4 || form.broadcast && spec.broadcastBytes == 0 || form.zeroing && !spec.zeroing {
			return fail()
		}
		if len(ins.Args) == 4 {
			if goarch == "386" && !mode32MaskOperands || spec.encoding == x86PackedLogicalVEX || !amd64NonzeroKOperand(ins.Args[2]) {
				return fail()
			}
			form.mask = 2
		} else if form.zeroing {
			return fail()
		}
		form.byteWidth = amd64VectorByteWidth(ins.Args[form.destination].Reg)
	}
	register := func(operand Operand) bool {
		if form.mmx {
			_, valid := amd64ParseMReg(operand.Reg)
			return operand.Kind == OpReg && valid
		}
		if form.legacy {
			index, valid := amd64ParseXReg(operand.Reg)
			return operand.Kind == OpReg && valid && (goarch == "amd64" && index < 16 || goarch == "386" && index < 8)
		}
		if spec.encoding == x86PackedLogicalVEX {
			return (form.byteWidth == 16 || form.byteWidth == 32) && amd64VEXVectorRegister(operand, form.byteWidth)
		}
		return amd64GoPackedVectorMoveRegister(operand, form.byteWidth, goarch)
	}
	if !register(ins.Args[form.destination]) || !register(ins.Args[form.second]) {
		return fail()
	}
	first := ins.Args[form.first]
	if isAMD64MemoryOperand(first) {
		if first.Kind == OpSym {
			symbol := strings.TrimSpace(first.Sym)
			_, absolute := parseInt(symbol)
			if strings.HasPrefix(symbol, "$") || !strings.HasSuffix(symbol, "(SB)") && absolute != nil {
				return fail()
			}
		}
		if first.Kind == OpMem {
			// Go asmandsz requires signed disp32 in amd64 mode. Its historical
			// 386 rule additionally admits uint32 spellings for the same bits;
			// packed logical rows have no LEAL-only overflow exception.
			displacement := first.Mem.Off
			if displacement != int64(int32(displacement)) &&
				(goarch != "386" || displacement != int64(uint32(displacement))) {
				return fail()
			}
			if !x86MemoryRegistersValidForArch(first.Mem, goarch) || first.Mem.Index != "" &&
				(first.Mem.Index == SP || first.Mem.Scale != 1 && first.Mem.Scale != 2 && first.Mem.Scale != 4 && first.Mem.Scale != 8) {
				return fail()
			}
		}
		form.memory, form.memoryBytes = form.first, form.byteWidth
		if form.broadcast {
			form.memoryBytes = spec.broadcastBytes
		}
	} else if form.broadcast || !register(first) {
		return fail()
	}
	return form, nil
}
