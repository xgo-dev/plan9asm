package plan9asm

import (
	"fmt"
	"strings"
)

func x86ImplicitMaskMoveProperties(op Op, ins Instr, arch string) (amd64ImplicitMaskMoveSpec, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64ImplicitMaskMoveSpecs[Op(name)]
	if !known {
		return spec, false, nil
	}
	if arch == "" {
		arch = "amd64"
	}
	fail := func() (amd64ImplicitMaskMoveSpec, bool, error) {
		return spec, true, fmt.Errorf("%s %s outside complete Go implicit mask-store grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || dotted || len(ins.Args) != 2 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail()
	}
	for _, operand := range ins.Args {
		if operand.Kind != OpReg {
			return fail()
		}
		if spec.byteWidth == 8 {
			if _, valid := amd64ParseMReg(operand.Reg); !valid {
				return fail()
			}
			continue
		}
		index, valid := amd64ParseXReg(operand.Reg)
		if !valid || index >= 16 || arch == "386" && index >= 8 {
			return fail()
		}
	}
	return spec, true, nil
}

func x86TypedImplicitMaskMoveByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	spec, known, err := x86ImplicitMaskMoveProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width := int64(spec.byteWidth)
	return x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: 0, operand: ins.Args[0], width: width, read: true},
		{index: 1, operand: ins.Args[1], width: width, read: true},
		{index: -1, operand: Operand{Kind: OpMem, Mem: MemRef{Base: DI}}, width: width, write: true},
	}}, true, nil
}

// MASKMOVQ belongs exclusively to its complete physical MMX/EMMS region.
// SIMD stores also need the actual paired opcode and incoming DI identity;
// an encoding, numerical address or zero mask provides neither storage nor
// initialized bytes. A masked write establishes no new memory facts.
func x86ResultImplicitMaskMoveStep(ins Instr, state *x86ResultState, arch string, native bool) (bool, bool) {
	spec, known, err := x86ImplicitMaskMoveProperties(ins.Op, ins, arch)
	if !known || err != nil || !x86ResultNamedPredicateInstruction(ins) {
		return false, known
	}
	if !native || spec.byteWidth == 8 {
		return false, true
	}
	required := x86CallerVectorByteMask(int64(spec.byteWidth))
	for _, operand := range ins.Args {
		index, _ := amd64ParseXReg(operand.Reg)
		if state.vectorBytes(index)&required != required {
			return false, true
		}
	}
	return x86ResultIncomingPointerAddressIdentity(Operand{Kind: OpMem, Mem: MemRef{Base: DI}}, state, arch), true
}
