package plan9asm

import (
	"fmt"
	"strings"
)

// lowerAMDSystemManagement implements AMD's fixed no-operand 0F 01 D8-DF
// family. Their architectural operands are implicit: VMRUN/VMLOAD/VMSAVE use
// rAX, SKINIT uses EAX, INVLPGA uses rAX and ECX, and VMMCALL follows the common
// KVM hypercall convention with rAX as the result and rBX/rCX/rDX/rSI as input
// arguments. The remaining instructions have no general-register operands.
func (c *amd64Ctx) lowerAMDSystemManagement(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	switch baseOp {
	case "VMRUN", "VMMCALL", "VMLOAD", "VMSAVE", "STGI", "CLGI", "SKINIT", "INVLPGA":
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

	wordType := I64
	if c.goarch == "386" {
		wordType = I32
	}
	loadWordReg := func(reg Reg) (string, error) {
		return c.evalIntSized(Operand{Kind: OpReg, Reg: reg}, wordType)
	}
	clobbers := "~{dirflag},~{fpsr},~{flags},~{memory}"
	switch baseOp {
	case "STGI", "CLGI":
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", strings.ToLower(baseOp), clobbers)
	case "VMRUN", "VMLOAD", "VMSAVE":
		ax, err := loadWordReg(AX)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s %s)\n", strings.ToLower(baseOp), "{ax},"+clobbers, wordType, ax)
	case "SKINIT":
		ax, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AX}, I32)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  call void asm sideeffect \"skinit\", %q(i32 %s)\n", "{ax},"+clobbers, ax)
	case "INVLPGA":
		ax, err := loadWordReg(AX)
		if err != nil {
			return true, false, err
		}
		cx, err := c.evalIntSized(Operand{Kind: OpReg, Reg: CX}, I32)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  call void asm sideeffect \"invlpga\", %q(%s %s, i32 %s)\n", "{ax},{cx},"+clobbers, wordType, ax, cx)
	case "VMMCALL":
		regs := []Reg{AX, BX, CX, DX, SI}
		args := make([]string, len(regs))
		for i, reg := range regs {
			value, err := loadWordReg(reg)
			if err != nil {
				return true, false, err
			}
			args[i] = value
		}
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect \"vmmcall\", %q(%s %s, %s %s, %s %s, %s %s, %s %s)\n",
			call, wordType, "={ax},0,{bx},{cx},{dx},{si},"+clobbers,
			wordType, args[0], wordType, args[1], wordType, args[2], wordType, args[3], wordType, args[4],
		)
		if err := c.storeRegSized(AX, wordType, "%"+call); err != nil {
			return true, false, err
		}
	}
	return true, false, nil
}
