package plan9asm

import (
	"fmt"
	"strings"
)

func arm64FloatComparePredicate(op Op) (string, bool) {
	predicates := map[Op]string{
		"VFCMEQ": "oeq",
		"VFCMGE": "oge",
		"VFCMGT": "ogt",
		"VFCMLE": "ole",
		"VFCMLT": "olt",
		"VFACGE": "oge",
		"VFACGT": "ogt",
	}
	predicate, ok := predicates[op]
	return predicate, ok
}

func (c *arm64Ctx) lowerARM64VectorFloatCompare(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VFCMEQ" && op != "VFCMGE" && op != "VFCMGT" && op != "VFCMLE" && op != "VFCMLT" {
		return false, false, nil
	}
	predicate, _ := arm64FloatComparePredicate(op)
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects register compare or $(0.0) compare form and no suffix: %q", op, ins.Raw)
	}

	zeroForm := ins.Args[0].Kind == OpImm
	if zeroForm {
		if ins.Args[0].Imm != 0 || ins.Args[0].ImmRaw != "" || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s immediate compare requires exactly $(0.0), Vsrc.<T>, Vdst.<T>: %q", op, ins.Raw)
		}
	} else {
		if op == "VFCMLE" || op == "VFCMLT" || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s register compare form is absent from Go 1.27's optab: %q", op, ins.Raw)
		}
	}

	sourceIndex := 1
	if !zeroForm {
		sourceIndex = 0
	}
	arrangement, valid := parseARM64VectorArrangement(ins.Args[sourceIndex].Reg)
	if !valid || !((arrangement.elementBits == 32 && (arrangement.lanes == 2 || arrangement.lanes == 4)) ||
		(arrangement.elementBits == 64 && arrangement.lanes == 2)) {
		return true, false, fmt.Errorf("arm64 %s accepts only S2, S4, or D2 arrangements: %q", op, ins.Raw)
	}
	start := 1
	if !zeroForm {
		start = 0
	}
	for i := start; i < len(ins.Args); i++ {
		parsed, ok := parseARM64VectorArrangement(ins.Args[i].Reg)
		if !ok || parsed != arrangement {
			return true, false, fmt.Errorf("arm64 %s arrangements must match: %q", op, ins.Raw)
		}
	}

	return true, false, c.lowerARM64VectorFloatCompareValues(
		predicate,
		false,
		arrangement,
		ins.Args[1].Reg,
		ins.Args[0].Reg,
		zeroForm,
		ins.Args[2].Reg,
	)
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
