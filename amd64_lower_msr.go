package plan9asm

import (
	"fmt"
	"strings"
)

// lowerMSRAccess implements the complete RDMSR/WRMSR instruction family.
// Go 1.27 uses the operand-free ynone optab entry for both instructions on
// amd64 and 386; the architectural operands are ECX and EDX:EAX.
func (c *amd64Ctx) lowerMSRAccess(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	switch baseOp {
	case "RDMSR", "WRMSR":
		// handled below
	default:
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 0 {
		return true, false, fmt.Errorf("%s %s takes no operands: %q", c.goarch, baseOp, ins.Raw)
	}

	cx, err := c.loadReg(CX)
	if err != nil {
		return true, false, err
	}
	cx32 := c.truncI64(cx, I32)
	if baseOp == "RDMSR" {
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call { i32, i32 } asm sideeffect \"rdmsr\", \"={ax},={dx},{cx},~{dirflag},~{fpsr},~{flags}\"(i32 %s)\n", call, cx32)
		for index, reg := range []Reg{AX, DX} {
			part := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractvalue { i32, i32 } %%%s, %d\n", part, call, index)
			if err := c.storeRegSized(reg, I32, "%"+part); err != nil {
				return true, false, err
			}
		}
		return true, false, nil
	}

	ax, err := c.loadReg(AX)
	if err != nil {
		return true, false, err
	}
	dx, err := c.loadReg(DX)
	if err != nil {
		return true, false, err
	}
	ax32 := c.truncI64(ax, I32)
	dx32 := c.truncI64(dx, I32)
	fmt.Fprintf(c.b, "  call void asm sideeffect \"wrmsr\", \"{ax},{dx},{cx},~{dirflag},~{fpsr},~{flags}\"(i32 %s, i32 %s, i32 %s)\n", ax32, dx32, cx32)
	return true, false, nil
}
