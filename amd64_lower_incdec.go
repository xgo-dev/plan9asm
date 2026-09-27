package plan9asm

import (
	"fmt"
	"strings"
)

// lowerScalarIncDec implements the complete Go 1.27 INCB/W/L/Q and
// DECB/W/L/Q tables. INC and DEC preserve CF while updating the modeled
// ZF/SF/PF/OF flags.
func (c *amd64Ctx) lowerScalarIncDec(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	bits := 0
	switch baseOp {
	case "INCB", "DECB":
		bits = 8
	case "INCW", "DECW":
		bits = 16
	case "INCL", "DECL":
		bits = 32
	case "INCQ", "DECQ":
		bits = 64
	default:
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && bits == 64 {
		return true, false, fmt.Errorf("386 %s is illegal in 32-bit mode: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 1 {
		return true, false, fmt.Errorf("%s %s expects one destination: %q", c.goarch, baseOp, ins.Raw)
	}
	dst := ins.Args[0]
	if dst.Kind == OpReg {
		if bits == 8 {
			if !isGoYmbRegisterForArch(dst.Reg, c.goarch) {
				return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's Ymb class: %q", c.goarch, baseOp, ins.Raw)
			}
		} else if !isX86YrlRegisterForArch(dst.Reg, c.goarch) {
			return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's Yml class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(dst) {
		return true, false, fmt.Errorf("%s %s expects a GP register or memory destination: %q", c.goarch, baseOp, ins.Raw)
	}

	ty := amd64IntegerTypeForBits(bits)
	old, err := c.evalIntSized(dst, ty)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	llvmOp := "add"
	if baseOp[:3] == "DEC" {
		llvmOp = "sub"
	}
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, 1\n", result, llvmOp, ty, old)
	value := "%" + result
	if err := c.storeScalarIntegerOperand(dst, ty, value); err != nil {
		return true, false, err
	}

	zero := c.newTmp()
	sign := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, 0\n", zero, ty, value)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, 0\n", sign, ty, value)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sign, c.flagsSltSlot)
	c.setParityFlagSized(ty, value)

	overflowInput := int64(1) << (bits - 1)
	if baseOp[:3] == "INC" {
		overflowInput--
	} else {
		overflowInput = -overflowInput
	}
	overflow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, %d\n", overflow, ty, old, overflowInput)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", overflow, c.flagsOFSlot)
	return true, false, nil
}
