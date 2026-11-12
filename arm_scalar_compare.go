package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

// Go's CMPF/CMPD are signaling compares followed by VMRS APSR_nzcv,FPSCR.
// The raw architectural family additionally admits quiet VCMP, odd S registers
// and D16..D31, and changes only FPSCR until a separate VMRS instruction.
type armScalarCompareForm struct {
	lhs, rhs  int
	bits      int
	zeroRHS   bool
	signaling bool
	toAPSR    bool
	condition string
}

func parseARMScalarCompare(op string, ins Instr) (armScalarCompareForm, bool, error) {
	if op != "CMPF" && op != "CMPD" {
		return armScalarCompareForm{}, false, nil
	}
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return armScalarCompareForm{}, true, err
	}
	if len(ins.Args) < 1 || len(ins.Args) > 2 {
		return armScalarCompareForm{}, true, fmt.Errorf("arm %s expects Fsrc or Fsrc1,Fsrc2: %q", op, ins.Raw)
	}
	for _, arg := range ins.Args {
		if arg.Kind != OpReg || !isARMFReg(arg.Reg) {
			return armScalarCompareForm{}, true, fmt.Errorf("arm %s accepts only Go floating registers F0..F15: %q", op, ins.Raw)
		}
	}
	form := armScalarCompareForm{bits: 32, signaling: true, toAPSR: true, zeroRHS: len(ins.Args) == 1}
	if op == "CMPD" {
		form.bits = 64
	}
	_, form.condition, _, _ = armDecodeOp(string(ins.Op))
	number := func(arg Operand) int {
		value, _ := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(string(arg.Reg))), "F"))
		if form.bits == 32 {
			value *= 2 // A Go F register's low S half.
		}
		return value
	}
	// Go's From operand is Vm; Reg is Vd. A single operand uses Vd,#0.
	form.lhs = number(ins.Args[len(ins.Args)-1])
	if !form.zeroRHS {
		form.rhs = number(ins.Args[0])
	}
	return form, true, nil
}

func (c *armCtx) lowerARMScalarCompare(form armScalarCompareForm) error {
	if form.condition != "" && form.condition != "AL" {
		condition := form.condition
		form.condition = "AL"
		return c.emitConditionalEffect(condition, func() error {
			return c.lowerARMScalarCompare(form)
		})
	}
	lhs, err := c.loadARMRawVFPRegValue(form.lhs, form.bits)
	if err != nil {
		return err
	}
	rhs := ""
	if !form.zeroRHS {
		rhs, err = c.loadARMRawVFPRegValue(form.rhs, form.bits)
		if err != nil {
			return err
		}
	}
	operation, floatType, suffix := "vcmp", "float", ".f32"
	if form.signaling {
		operation = "vcmpe"
	}
	if form.bits == 64 {
		floatType, suffix = "double", ".f64"
	}
	first := 0
	constraints := "t"
	if form.toAPSR {
		first = 1
		constraints = "=r,t"
	}
	assembly := fmt.Sprintf("%s%s $%d, #0", operation, suffix, first)
	arguments := floatType + " " + lhs
	if !form.zeroRHS {
		assembly = fmt.Sprintf("%s%s $%d, $%d", operation, suffix, first, first+1)
		constraints += ",t"
		arguments += ", " + floatType + " " + rhs
	}
	// LLVM's pure fcmp neither observes FZ/DN nor retains cumulative exceptions
	// for dead flags. One native region performs the compare and, for named Go
	// forms, captures its FPSCR before any following native FP instruction.
	// The memory clobber orders this with native VMSR/VMRS and conversions.
	constraints += ",~{memory}"
	if form.toAPSR {
		status := c.newTmp()
		assembly += "\\0Avmrs $0, fpscr"
		fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect \"%s\", %q(%s)\n", status, assembly, constraints, arguments)
		c.storeFlagsFromStatus("%" + status)
	} else {
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s)\n", assembly, constraints, arguments)
	}
	c.vfpCompareWritten = true
	return nil
}
