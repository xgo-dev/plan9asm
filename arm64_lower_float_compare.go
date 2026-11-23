package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64VectorFloatCompare(op Op, ins Instr) (ok bool, terminated bool, err error) {
	var operation *arm64FloatCompareOperation
	for i := range arm64FloatCompareOperations {
		candidate := &arm64FloatCompareOperations[i]
		if candidate.op == op && !candidate.absolute {
			operation = candidate
			break
		}
	}
	if operation == nil {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects register compare or $(0.0) compare form and no suffix: %q", op, ins.Raw)
	}

	zeroForm := ins.Args[0].Kind == OpImm
	if zeroForm {
		if ins.Args[0].Imm != 0 || ins.Args[0].ImmRaw != "" || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s immediate compare requires exactly $(0.0), Vsrc.<T>, Vdst.<T>: %q", op, ins.Raw)
		}
	} else {
		if operation.binary.single == 0 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s register compare form is absent from Go 1.27's optab: %q", op, ins.Raw)
		}
	}

	start := 1
	if !zeroForm {
		start = 0
	}
	arrangement, valid := parseARM64VectorArrangement(ins.Args[start].Reg)
	if !valid || !((arrangement.elementBits == 32 && (arrangement.lanes == 2 || arrangement.lanes == 4)) ||
		(arrangement.elementBits == 64 && arrangement.lanes == 2)) {
		return true, false, fmt.Errorf("arm64 %s accepts only S2, S4, or D2 arrangements: %q", op, ins.Raw)
	}
	var registers [3]int
	for i := start; i < len(ins.Args); i++ {
		parsed, ok := parseARM64VectorArrangement(ins.Args[i].Reg)
		register, valid := arm64ParseVReg(ins.Args[i].Reg)
		if !ok || !valid || parsed != arrangement {
			return true, false, fmt.Errorf("arm64 %s arrangements must match: %q", op, ins.Raw)
		}
		registers[i] = register
	}

	return true, false, c.lowerRawFloatCompare(arm64RawFloatCompare{
		operation: operation, arrangement: arrangement, zero: zeroForm,
		first: registers[1], second: registers[0], destination: registers[2],
	})
}

func (c *arm64Ctx) lowerRawFloatCompare(form arm64RawFloatCompare) error {
	leftReg := Reg(fmt.Sprintf("V%d", form.first))
	rightReg := Reg(fmt.Sprintf("V%d", form.second))
	destination := Reg(fmt.Sprintf("V%d", form.destination))
	op := form.operation
	arrangement := form.arrangement
	if !arm64ScalarConversionNativeTarget(c.targetTriple) {
		if arrangement.lanes == 1 {
			return fmt.Errorf("%w: ARM64 %s scalar comparison requires a native little-endian AArch64 target",
				ErrProbeNeedsContext, op.mnemonic)
		}
		return c.lowerARM64VectorFloatCompareValues(op.predicate, op.absolute, arrangement, leftReg, rightReg, form.zero, destination)
	}

	width := arrangement.lanes * arrangement.elementBits
	left, err := c.loadVRegWidth(leftReg, width)
	if err != nil {
		return err
	}
	secondOperand, constraints := "#0.0", "=w,w"
	arguments := "<16 x i8> " + left
	if !form.zero {
		rightWidth := width
		if arrangement.lanes == 1 {
			// With FEAT_AFP and FPCR.NEP set, upper result bits are copied
			// from the second source of a scalar register comparison.
			rightWidth = 128
		}
		right, err := c.loadVRegWidth(rightReg, rightWidth)
		if err != nil {
			return err
		}
		secondOperand = arm64NativeSIMDReg(2, arrangement)
		constraints += ",w"
		arguments += ", <16 x i8> " + right
	}
	assembly := fmt.Sprintf("%s %s, %s, %s", op.mnemonic,
		arm64NativeSIMDReg(0, arrangement), arm64NativeSIMDReg(1, arrangement), secondOperand)
	result := c.newTmp()
	c.emitMachineNeutralNativeIR("  %%%s = call <16 x i8> asm sideeffect %q, %q(%s)\n",
		result, assembly, constraints+",~{memory}", arguments)
	return c.storeVReg(destination, "%"+result)
}

func (c *arm64Ctx) lowerARM64VectorFloatCompareValues(
	predicate string,
	absolute bool,
	arrangement arm64VectorArrangement,
	leftReg Reg,
	rightReg Reg,
	zero bool,
	destination Reg,
) error {
	left, err := c.loadARM64VectorFloat(leftReg, arrangement)
	if err != nil {
		return err
	}
	right := "zeroinitializer"
	if !zero {
		right, err = c.loadARM64VectorFloat(rightReg, arrangement)
		if err != nil {
			return err
		}
	}
	floatType := arm64RawFloatType(arrangement.elementBits)
	vectorType := fmt.Sprintf("<%d x %s>", arrangement.lanes, floatType)
	if absolute {
		leftAbs := c.newTmp()
		rightAbs := c.newTmp()
		intrinsic := fmt.Sprintf("@llvm.fabs.v%df%d", arrangement.lanes, arrangement.elementBits)
		fmt.Fprintf(c.b, "  %%%s = call %s %s(%s %s)\n", leftAbs, vectorType, intrinsic, vectorType, left)
		fmt.Fprintf(c.b, "  %%%s = call %s %s(%s %s)\n", rightAbs, vectorType, intrinsic, vectorType, right)
		left = "%" + leftAbs
		right = "%" + rightAbs
	}
	compared := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fcmp %s %s %s, %s\n", compared, predicate, vectorType, left, right)
	allBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext <%d x i1> %%%s to <%d x i%d>\n", allBits, arrangement.lanes, compared, arrangement.lanes, arrangement.elementBits)
	return c.storeARM64VectorInteger(destination, arrangement, "%"+allBits)
}
