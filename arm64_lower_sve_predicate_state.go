package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEPredicateStateKind uint8

const (
	arm64SVEPredicateFalse arm64SVEPredicateStateKind = iota
	arm64SVEPredicateTest
	arm64SVEPredicateReadFFR
	arm64SVEPredicateReadFFRFlags
	arm64SVEPredicateWriteFFR
	arm64SVEPredicateSetFFR
)

var arm64SVEPredicateStateSpecs = map[Op]arm64SVEPredicateStateKind{
	"PPFALSE": arm64SVEPredicateFalse,
	"PPTEST":  arm64SVEPredicateTest,
	"PRDFFR":  arm64SVEPredicateReadFFR,
	"PRDFFRS": arm64SVEPredicateReadFFRFlags,
	"PWRFFR":  arm64SVEPredicateWriteFFR,
	"SETFFR":  arm64SVEPredicateSetFFR,
}

func (c *arm64Ctx) lowerARM64SVEPredicateState(op Op, ins Instr) (ok bool, terminated bool, err error) {
	kind, ok := arm64SVEPredicateStateSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	switch kind {
	case arm64SVEPredicateFalse:
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("arm64 PPFALSE expects Pd.B: %q", ins.Raw)
		}
		destination, elementBits, destinationOK := arm64ParseSVEPredicateElement(ins.Args[0])
		if !destinationOK || elementBits != 8 {
			return true, false, fmt.Errorf("arm64 PPFALSE only accepts P0..P15.B: %q", ins.Raw)
		}
		return true, false, c.storePReg(destination, "zeroinitializer")
	case arm64SVEPredicateTest:
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 PPTEST expects Pn.B, Pg: %q", ins.Raw)
		}
		tested, elementBits, testedOK := arm64ParseSVEPredicateElement(ins.Args[0])
		governing, governingOK := arm64ParseSVEPredicateBare(ins.Args[1], 15)
		if !testedOK || elementBits != 8 || !governingOK {
			return true, false, fmt.Errorf("arm64 PPTEST only accepts P0..P15.B, P0..P15: %q", ins.Raw)
		}
		testedValue, predicateType, err := c.loadPRegElements(tested, 8)
		if err != nil {
			return true, false, err
		}
		governingValue, _, err := c.loadPRegElements(governing, 8)
		if err != nil {
			return true, false, err
		}
		c.setSVEPredicateFlags(governingValue, testedValue, predicateType, 16)
		return true, false, nil
	case arm64SVEPredicateReadFFR, arm64SVEPredicateReadFFRFlags:
		return c.lowerARM64SVEReadFFR(kind, ins)
	case arm64SVEPredicateWriteFFR:
		if len(ins.Args) != 1 {
			return true, false, fmt.Errorf("arm64 PWRFFR expects Pn.B: %q", ins.Raw)
		}
		source, elementBits, sourceOK := arm64ParseSVEPredicateElement(ins.Args[0])
		if !sourceOK || elementBits != 8 {
			return true, false, fmt.Errorf("arm64 PWRFFR only accepts P0..P15.B: %q", ins.Raw)
		}
		value, err := c.loadPReg(source)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  call void @llvm.aarch64.sve.wrffr(<vscale x 16 x i1> %s)\n", value)
		return true, false, nil
	case arm64SVEPredicateSetFFR:
		if len(ins.Args) != 0 {
			return true, false, fmt.Errorf("arm64 SETFFR does not accept operands: %q", ins.Raw)
		}
		fmt.Fprintln(c.b, "  call void @llvm.aarch64.sve.setffr()")
		return true, false, nil
	default:
		return true, false, fmt.Errorf("unsupported ARM64 SVE predicate state kind %d", kind)
	}
}

func (c *arm64Ctx) lowerARM64SVEReadFFR(kind arm64SVEPredicateStateKind, ins Instr) (ok bool, terminated bool, err error) {
	var destination int
	var value string
	if len(ins.Args) == 1 && kind == arm64SVEPredicateReadFFR {
		var elementBits int
		var destinationOK bool
		destination, elementBits, destinationOK = arm64ParseSVEPredicateElement(ins.Args[0])
		if !destinationOK || elementBits != 8 {
			return true, false, fmt.Errorf("arm64 PRDFFR unpredicated form expects Pd.B: %q", ins.Raw)
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i1> @llvm.aarch64.sve.rdffr()\n", result)
		value = "%" + result
	} else if len(ins.Args) == 2 {
		governing, governingOK := arm64ParseSVEPredicateMode(ins.Args[0], "Z", 15)
		var elementBits int
		var destinationOK bool
		destination, elementBits, destinationOK = arm64ParseSVEPredicateElement(ins.Args[1])
		if !governingOK || !destinationOK || elementBits != 8 {
			return true, false, fmt.Errorf("arm64 %s predicated form expects Pg.Z, Pd.B: %q", ins.Op, ins.Raw)
		}
		governingValue, err := c.loadPReg(governing)
		if err != nil {
			return true, false, err
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i1> @llvm.aarch64.sve.rdffr.z(<vscale x 16 x i1> %s)\n", result, governingValue)
		value = "%" + result
		if kind == arm64SVEPredicateReadFFRFlags {
			c.setSVEPredicateFlags(governingValue, value, "<vscale x 16 x i1>", 16)
		}
	} else {
		return true, false, fmt.Errorf("arm64 %s expects its Go 1.27 FFR read form: %q", ins.Op, ins.Raw)
	}
	if err := c.storePReg(destination, value); err != nil {
		return true, false, err
	}
	return true, false, nil
}
