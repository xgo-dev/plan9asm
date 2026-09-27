package plan9asm

import (
	"fmt"
	"strings"
)

// lowerVectorScalarFlagCompare implements the complete Go 1.27 _yvcomisd
// family shared by VCOMISD, VCOMISS, VUCOMISD, and VUCOMISS. The table has
// one VEX X/m,X row and one EVEX X/m,X row; only the EVEX register-source
// encoding accepts .SAE.
func (c *amd64Ctx) lowerVectorScalarFlagCompare(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	elemType := LLVMType("")
	switch baseOp {
	case "VCOMISD", "VUCOMISD":
		elemType = LLVMType("double")
	case "VCOMISS", "VUCOMISS":
		elemType = LLVMType("float")
	default:
		return false, false, nil
	}
	if suffix != "" && suffix != "SAE" {
		return true, false, fmt.Errorf("%s %s suffix is absent from Go 1.27's _yvcomisd table: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("%s %s expects X/m, X: %q", c.goarch, baseOp, ins.Raw)
	}
	src, dst := ins.Args[0], ins.Args[1]
	if !amd64EVEXVectorRegister(dst, 16) {
		return true, false, fmt.Errorf("%s %s destination must be an X0-X31 register: %q", c.goarch, baseOp, ins.Raw)
	}
	if src.Kind == OpReg {
		if !amd64EVEXVectorRegister(src, 16) {
			return true, false, fmt.Errorf("%s %s register source must be an X0-X31 register: %q", c.goarch, baseOp, ins.Raw)
		}
	} else {
		if !isAMD64MemoryOperand(src) {
			return true, false, fmt.Errorf("%s %s source must be X0-X31 or memory: %q", c.goarch, baseOp, ins.Raw)
		}
		if suffix == "SAE" {
			return true, false, fmt.Errorf("%s %s.SAE requires a register source: %q", c.goarch, baseOp, ins.Raw)
		}
	}

	var source, destination string
	if elemType == LLVMType("double") {
		source, err = c.evalF64(src)
		if err == nil {
			destination, err = c.evalF64(dst)
		}
	} else {
		source, err = c.evalF32(src)
		if err == nil {
			destination, err = c.evalF32(dst)
		}
	}
	if err != nil {
		return true, false, err
	}
	c.setScalarFloatCompareFlags(elemType, destination, source)
	return true, false, nil
}

// setScalarFloatCompareFlags models the EFLAGS values written by COMIS*/
// UCOMIS*: ZF/PF/CF describe equal/unordered/below and OF/SF are cleared.
func (c *amd64Ctx) setScalarFloatCompareFlags(elemType LLVMType, destination, source string) {
	z := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fcmp ueq %s %s, %s\n", z, elemType, destination, source)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", z, c.flagsZSlot)
	cf := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fcmp ult %s %s, %s\n", cf, elemType, destination, source)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", cf, c.flagsCFSlot)
	pf := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fcmp uno %s %s, %s\n", pf, elemType, destination, source)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", pf, c.flagsPFSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsSltSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
}
