package plan9asm

import (
	"fmt"
)

type amd64UnaryImmediateFloatingShape struct {
	laneBits  int
	scalar    bool
	twoSource bool
}

type amd64UnaryImmediateFloatingForm struct {
	properties  amd64BinaryFloatingSuffix
	source      Operand
	passthrough Operand
	destination Operand
	byteWidth   int
	mask        string
	immediate   uint8
}

// parseUnaryImmediateFloatingForm models Go 1.27's related unary-immediate
// and FIXUPIMM operand grammars. Semantic families supply only their lane
// width, packed/scalar shape, and whether packed forms have two sources;
// width, memory, BCST, SAE, mask, zeroing, and 386 frontend constraints are
// validated once here.
func (c *amd64Ctx) parseUnaryImmediateFloatingForm(baseOp, suffix string, shape amd64UnaryImmediateFloatingShape, ins Instr) (amd64UnaryImmediateFloatingForm, error) {
	var form amd64UnaryImmediateFloatingForm
	properties, validSuffix := parseAMD64BinaryFloatingSuffix(suffix)
	if !validSuffix || properties.rounding != "" {
		return form, fmt.Errorf("%s %s has a suffix absent from Go 1.27's unary-immediate floating optabs: %q", c.goarch, baseOp, ins.Raw)
	}
	if shape.scalar && properties.broadcast {
		return form, fmt.Errorf("%s %s scalar forms do not support broadcast: %q", c.goarch, baseOp, ins.Raw)
	}
	hasPassthrough := shape.scalar || shape.twoSource
	wantArgs := 3
	if hasPassthrough {
		wantArgs = 4
	}
	if len(ins.Args) != wantArgs && len(ins.Args) != wantArgs+1 {
		return form, fmt.Errorf("%s %s has the wrong operand count for its packed/scalar grammar: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind != OpImm || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
		return form, fmt.Errorf("%s %s immediate must be an unsigned byte: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == wantArgs+1
	if c.goarch == "386" && (hasPassthrough || masked) {
		return form, fmt.Errorf("386 %s form exceeds the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if properties.zeroing && !masked {
		return form, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	maskIndex := len(ins.Args) - 2
	if masked && !amd64NonzeroKOperand(ins.Args[maskIndex]) {
		return form, fmt.Errorf("%s %s masked form expects K1-K7: %q", c.goarch, baseOp, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return form, fmt.Errorf("%s %s destination must be a vector register: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	passthrough := Operand{}
	if shape.scalar {
		passthrough = ins.Args[2]
		if byteWidth != 16 || !c.isGoEVEXVectorRegister(destination, 16) || !c.isGoEVEXVectorRegister(passthrough, 16) {
			return form, fmt.Errorf("%s %s scalar pass-through and destination must be X registers: %q", c.goarch, baseOp, ins.Raw)
		}
	} else {
		if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 || !c.isGoEVEXVectorRegister(destination, byteWidth) {
			return form, fmt.Errorf("%s %s packed destination must be an in-range X, Y, or Z register: %q", c.goarch, baseOp, ins.Raw)
		}
		if shape.twoSource {
			passthrough = ins.Args[2]
			if !c.isGoEVEXVectorRegister(passthrough, byteWidth) {
				return form, fmt.Errorf("%s %s second packed source must match the destination width: %q", c.goarch, baseOp, ins.Raw)
			}
		}
	}
	source := ins.Args[1]
	if properties.broadcast {
		if !isAMD64MemoryOperand(source) {
			return form, fmt.Errorf("%s %s.BCST requires a scalar memory source: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if source.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(source, byteWidth) {
			return form, fmt.Errorf("%s %s source register must match the destination width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return form, fmt.Errorf("%s %s source must be a matching vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	if properties.sae && (source.Kind != OpReg || !shape.scalar && byteWidth != 64) {
		return form, fmt.Errorf("%s %s.SAE requires a register source and scalar or Z form: %q", c.goarch, baseOp, ins.Raw)
	}
	mask := ""
	if masked {
		var err error
		mask, err = c.loadK(ins.Args[maskIndex].Reg)
		if err != nil {
			return form, err
		}
	}
	return amd64UnaryImmediateFloatingForm{
		properties: properties, source: source, passthrough: passthrough,
		destination: destination, byteWidth: byteWidth, mask: mask,
		immediate: uint8(ins.Args[0].Imm),
	}, nil
}
