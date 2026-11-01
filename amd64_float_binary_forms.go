package plan9asm

import (
	"fmt"
	"strings"
)

// Go's yxm, _yvaddpd and _yvaddsd shapes are shared by binary floating
// arithmetic. Operation semantics are deliberately not part of this grammar.
type x86FloatBinaryForm struct {
	bits                                     int
	legacy, scalar                           bool
	first, second, destination, mask, memory int
	byteWidth, memoryBytes                   int
	broadcast, zeroing                       bool
	literal                                  bool // family-authorized Go constant-pool rewrite
	sae                                      bool // independently validated standalone suppression
	rounding                                 string
}

// Parse only shared operand axes. The registered family supplies precision
// and encoding generation; its lowerer retains operation-specific semantics.
func x86FloatBinaryOperandProperties(ins Instr, goarch string, bits int, legacy, scalar, literal bool, family string) (x86FloatBinaryForm, error) {
	return x86FloatOperandProperties(ins, goarch, bits, legacy, scalar, literal, false, family)
}

// Unary packed arithmetic shares the width, memory and EVEX control axes,
// but has no second numerical input and allows three-operand masks on 386.
func x86FloatOperandProperties(ins Instr, goarch string, bits int, legacy, scalar, literal, unary bool, family string) (x86FloatBinaryForm, error) {
	_, suffix, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	form := x86FloatBinaryForm{
		bits: bits, legacy: legacy, scalar: scalar, literal: literal,
		first: 0, second: 1, destination: len(ins.Args) - 1, mask: -1, memory: -1,
	}
	if unary {
		form.second = form.destination
	}
	fail := func() (x86FloatBinaryForm, error) {
		return form, fmt.Errorf("%s %s operands/suffix outside Go floating %s grammar: %q", goarch, ins.Op, family, ins.Raw)
	}
	if goarch != "386" && goarch != "amd64" {
		return fail()
	}
	if legacy {
		if dotted || len(ins.Args) != 2 {
			return fail()
		}
		form.byteWidth = 16
	} else {
		operands := 3
		if unary {
			operands = 2
		}
		properties, valid := parseAMD64FMA3Suffix(suffix)
		if !valid || dotted && suffix == "" || scalar && properties.broadcast || len(ins.Args) != operands && len(ins.Args) != operands+1 {
			return fail()
		}
		form.broadcast, form.zeroing, form.rounding = properties.broadcast, properties.zeroing, properties.rounding
		if len(ins.Args) == operands+1 {
			if goarch == "386" && operands == 3 && !ins.x86Encoded || !amd64NonzeroKOperand(ins.Args[operands-1]) {
				return fail()
			}
			form.mask = operands - 1
		} else if form.zeroing {
			return fail()
		}
		form.byteWidth = amd64VectorByteWidth(ins.Args[form.destination].Reg)
		if scalar && form.byteWidth != 16 || form.rounding != "" && !scalar && form.byteWidth != 64 {
			return fail()
		}
	}
	register := func(operand Operand) bool {
		if legacy {
			index, valid := amd64ParseXReg(operand.Reg)
			return operand.Kind == OpReg && valid && (goarch == "amd64" && index < 16 || goarch == "386" && index < 8)
		}
		return amd64GoPackedVectorMoveRegister(operand, form.byteWidth, goarch)
	}
	if !register(ins.Args[form.second]) || !register(ins.Args[form.destination]) {
		return fail()
	}
	first := ins.Args[form.first]
	if literal {
		if !legacy || !scalar || first.Kind != OpImm || !first.ImmIsFloat || first.ImmRaw != "" {
			return fail()
		}
	} else if isAMD64MemoryOperand(first) {
		if form.rounding != "" {
			return fail()
		}
		if first.Kind == OpSym {
			symbol := strings.TrimSpace(first.Sym)
			_, absolute := parseInt(symbol)
			if strings.HasPrefix(symbol, "$") || !strings.HasSuffix(symbol, "(SB)") && absolute != nil {
				return fail()
			}
		}
		if first.Kind == OpMem {
			displacement := first.Mem.Off
			if displacement != int64(int32(displacement)) && (goarch != "386" || displacement != int64(uint32(displacement))) ||
				!x86MemoryRegistersValidForArch(first.Mem, goarch) || first.Mem.Index != "" &&
				(first.Mem.Index == SP || first.Mem.Scale != 1 && first.Mem.Scale != 2 && first.Mem.Scale != 4 && first.Mem.Scale != 8) {
				return fail()
			}
		}
		form.memory, form.memoryBytes = 0, form.byteWidth
		if scalar || form.broadcast {
			form.memoryBytes = bits / 8
		}
	} else if form.broadcast || !register(first) {
		return fail()
	}
	return form, nil
}
