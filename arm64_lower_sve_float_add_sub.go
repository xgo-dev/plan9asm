package plan9asm

import (
	"fmt"
	"math"
	"strings"
)

type arm64SVEFloatAddSubSpec struct {
	operation    string
	reverse      bool
	unpredicated bool
}

var arm64SVEFloatAddSubSpecs = map[Op]arm64SVEFloatAddSubSpec{
	"ZFADD":  {operation: "fadd", unpredicated: true},
	"ZFSUB":  {operation: "fsub", unpredicated: true},
	"ZFSUBR": {operation: "fsub", reverse: true},
}

type arm64SVEFloatAddSubForm struct {
	elementBits  int
	first        int
	second       int
	predicate    int
	destination  int
	immediate    float64
	hasImmediate bool
	predicated   bool
}

func arm64SVEFloatElementReg(operand Operand) (index, elementBits int, ok bool) {
	index, elementBits, ok = arm64ParseSVEZElementReg(operand)
	return index, elementBits, ok && elementBits >= 16
}

func (c *arm64Ctx) lowerARM64SVEFloatAddSub(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEFloatAddSubSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}

	form := arm64SVEFloatAddSubForm{}
	if len(ins.Args) == 3 {
		second, secondBits, secondOK := arm64SVEFloatElementReg(ins.Args[0])
		first, firstBits, firstOK := arm64SVEFloatElementReg(ins.Args[1])
		destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[2])
		if !spec.unpredicated || !secondOK || !firstOK || !destinationOK || secondBits != firstBits || firstBits != destinationBits {
			return true, false, fmt.Errorf("arm64 %s does not accept this unpredicated floating vector form: %q", op, ins.Raw)
		}
		form = arm64SVEFloatAddSubForm{elementBits: firstBits, first: first, second: second, destination: destination}
	} else if len(ins.Args) == 4 {
		first, firstBits, firstOK := arm64SVEFloatElementReg(ins.Args[1])
		predicate, predicateOK := arm64ParseSVEPredicateMerge(ins.Args[2])
		destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[3])
		if !firstOK || !predicateOK || !destinationOK || first != destination || firstBits != destinationBits {
			return true, false, fmt.Errorf("arm64 %s requires identical predicated destructive floating registers: %q", op, ins.Raw)
		}
		form = arm64SVEFloatAddSubForm{elementBits: firstBits, first: first, predicate: predicate, destination: destination, predicated: true}
		if ins.Args[0].Kind == OpImm {
			if ins.Args[0].ImmRaw != "" || !ins.Args[0].ImmIsFloat {
				return true, false, fmt.Errorf("arm64 %s immediate requires $(0.5) or $(1.0): %q", op, ins.Raw)
			}
			form.immediate = math.Float64frombits(uint64(ins.Args[0].Imm))
			constants := arm64SVEFloatArithmeticSpecs[op].constants
			if form.immediate != constants[0] && form.immediate != constants[1] {
				return true, false, fmt.Errorf("arm64 %s immediate requires $(0.5) or $(1.0): %q", op, ins.Raw)
			}
			form.hasImmediate = true
		} else {
			second, secondBits, secondOK := arm64SVEFloatElementReg(ins.Args[0])
			if !secondOK || secondBits != firstBits {
				return true, false, fmt.Errorf("arm64 %s predicated source must match the destination element width: %q", op, ins.Raw)
			}
			form.second = second
		}
	} else {
		return true, false, fmt.Errorf("arm64 %s expects one of its Go 1.27 SVE floating forms: %q", op, ins.Raw)
	}
	return true, false, c.lowerARM64SVEFloatAddSubForm(spec, form)
}

func (c *arm64Ctx) lowerARM64SVEFloatAddSubForm(spec arm64SVEFloatAddSubSpec, form arm64SVEFloatAddSubForm) error {
	first, vectorType, err := c.loadRawSVEFloatVector(form.first, form.elementBits)
	if err != nil {
		return err
	}
	second := ""
	if form.hasImmediate {
		integerType, lanes, err := arm64SVEVectorType(form.elementBits)
		if err != nil {
			return err
		}
		var bits uint64
		switch form.elementBits {
		case 16:
			bits = uint64(arm64Float16Bits(form.immediate))
		case 32:
			bits = uint64(math.Float32bits(float32(form.immediate)))
		case 64:
			bits = math.Float64bits(form.immediate)
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s splat (i%d %d) to <vscale x %d x %s>\n", converted, integerType, form.elementBits, bits, lanes, map[int]string{16: "half", 32: "float", 64: "double"}[form.elementBits])
		second = "%" + converted
	} else {
		second, _, err = c.loadRawSVEFloatVector(form.second, form.elementBits)
		if err != nil {
			return err
		}
	}
	left, right := first, second
	if spec.reverse {
		left, right = right, left
	}
	calculated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", calculated, spec.operation, vectorType, left, right)
	result := "%" + calculated
	if form.predicated {
		predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
		if err != nil {
			return err
		}
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %s, %s %s\n", selected, predicateType, predicate, vectorType, result, vectorType, first)
		result = "%" + selected
	}
	return c.storeRawSVEFloatVector(form.destination, form.elementBits, result, vectorType)
}
