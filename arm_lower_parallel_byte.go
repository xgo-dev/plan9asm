package plan9asm

import (
	"fmt"
	"strings"
)

// lowerARMUnsignedParallelByteAddSub implements the complete three-register
// UADD8/USUB8 result family decoded by Go's vendored ARM instruction table.
// The four packed byte lanes deliberately wrap independently, matching the
// architectural data result rather than carrying between adjacent lanes.
func (c *armCtx) lowerARMUnsignedParallelByteAddSub(op, cond string, setFlags bool, ins Instr) error {
	if err := armRequireConditionOnlySuffix(ins); err != nil {
		return err
	}
	if setFlags {
		return fmt.Errorf("arm %s does not accept the .S suffix: %q", op, ins.Raw)
	}
	if len(ins.Args) != 3 {
		return fmt.Errorf("arm %s expects Rm, Rn, Rd: %q", op, ins.Raw)
	}
	for _, operand := range ins.Args {
		if operand.Kind != OpReg || !isARMParallelDataReg(operand.Reg) {
			return fmt.Errorf("arm %s accepts only R0-R14 registers: %q", op, ins.Raw)
		}
	}
	rm, err := c.loadReg(ins.Args[0].Reg)
	if err != nil {
		return err
	}
	rn, err := c.loadReg(ins.Args[1].Reg)
	if err != nil {
		return err
	}
	rmBytes := c.newTmp()
	rnBytes := c.newTmp()
	resultBytes := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i32 %s to <4 x i8>\n", rmBytes, rm)
	fmt.Fprintf(c.b, "  %%%s = bitcast i32 %s to <4 x i8>\n", rnBytes, rn)
	operation := "add"
	if op == "USUB8" {
		operation = "sub"
	}
	fmt.Fprintf(c.b, "  %%%s = %s <4 x i8> %%%s, %%%s\n", resultBytes, operation, rnBytes, rmBytes)
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i8> %%%s to i32\n", result, resultBytes)
	return c.selectRegWrite(ins.Args[2].Reg, cond, "%"+result)
}

func isARMParallelDataReg(reg Reg) bool {
	s := strings.ToUpper(strings.TrimSpace(string(reg)))
	return isARMGeneralReg(reg) && s != "PC" && s != "R15"
}
