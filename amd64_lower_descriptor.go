package plan9asm

import (
	"fmt"
	"strings"
)

var x86DescriptorOps = map[string]struct{}{
	"LGDT": {}, "LIDT": {}, "SGDT": {}, "SIDT": {},
	"LLDT": {}, "LTR": {}, "LMSW": {},
	"SLDTW": {}, "SLDTL": {}, "SLDTQ": {},
	"SMSWW": {}, "SMSWL": {}, "SMSWQ": {},
	"STRW": {}, "STRL": {}, "STRQ": {},
}

// lowerDescriptorTable covers Go 1.27's complete x86 descriptor-table and
// system-selector family. These instructions are privileged or may be blocked
// by UMIP, so the lowering preserves them as LLVM inline assembly rather than
// approximating their machine-state effects.
func (c *amd64Ctx) lowerDescriptorTable(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if ok, terminated, err := c.lowerSegmentQuery(op, ins); ok {
		return ok, terminated, err
	}
	if ok, terminated, err := c.lowerFarPointer(op, ins); ok {
		return ok, terminated, err
	}
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	if _, ok := x86DescriptorOps[baseOp]; !ok {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 1 {
		return true, false, fmt.Errorf("%s %s expects one operand: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && strings.HasSuffix(baseOp, "Q") {
		return true, false, fmt.Errorf("386 %s is illegal in 32-bit mode: %q", baseOp, ins.Raw)
	}

	operand := ins.Args[0]
	switch baseOp {
	case "LGDT", "LIDT":
		if !isAMD64MemoryOperand(operand) {
			return true, false, fmt.Errorf("%s %s expects Go 1.27 Ym memory: %q", c.goarch, baseOp, ins.Raw)
		}
		ptr, ptrType, err := c.x86DescriptorMemoryPointer(operand)
		if err != nil {
			return true, false, err
		}
		bytes := 10
		if c.goarch == "386" {
			bytes = 6
		}
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s elementtype([%d x i8]) %s)\n",
			strings.ToLower(baseOp)+" $0", "*m,~{memory},~{dirflag},~{fpsr},~{flags}", ptrType, bytes, ptr)
		return true, false, nil

	case "SGDT", "SIDT":
		if !isAMD64MemoryOperand(operand) {
			return true, false, fmt.Errorf("%s %s expects Go 1.27 Ym memory: %q", c.goarch, baseOp, ins.Raw)
		}
		ptr, ptrType, err := c.x86DescriptorMemoryPointer(operand)
		if err != nil {
			return true, false, err
		}
		bytes := 10
		if c.goarch == "386" {
			bytes = 6
		}
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s elementtype([%d x i8]) %s)\n",
			strings.ToLower(baseOp)+" $0", "=*m,~{memory},~{dirflag},~{fpsr},~{flags}", ptrType, bytes, ptr)
		return true, false, nil

	case "LLDT", "LTR", "LMSW":
		if operand.Kind != OpReg && !isAMD64MemoryOperand(operand) {
			return true, false, fmt.Errorf("%s %s expects Go 1.27 Yml register or memory: %q", c.goarch, baseOp, ins.Raw)
		}
		if operand.Kind == OpReg {
			if !isX86YrlRegisterForArch(operand.Reg, c.goarch) {
				return true, false, fmt.Errorf("%s %s register is outside Go 1.27's Yml class: %q", c.goarch, baseOp, ins.Raw)
			}
			value, err := c.evalIntSized(operand, I16)
			if err != nil {
				return true, false, err
			}
			fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i16 %s)\n",
				strings.ToLower(baseOp)+" $0", "r,~{memory},~{dirflag},~{fpsr},~{flags}", value)
			return true, false, nil
		}
		ptr, ptrType, err := c.x86DescriptorMemoryPointer(operand)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s elementtype(i16) %s)\n",
			strings.ToLower(baseOp)+" $0", "*m,~{memory},~{dirflag},~{fpsr},~{flags}", ptrType, ptr)
		return true, false, nil

	case "SLDTW", "SLDTL", "SLDTQ", "SMSWW", "SMSWL", "SMSWQ", "STRW", "STRL", "STRQ":
		return true, false, c.lowerDescriptorResult(baseOp, operand, ins)
	default:
		panic("descriptor opcode precheck drift")
	}
}

func (c *amd64Ctx) lowerDescriptorResult(op string, destination Operand, ins Instr) error {
	if destination.Kind != OpReg && !isAMD64MemoryOperand(destination) {
		return fmt.Errorf("%s %s expects Go 1.27 Yml register or memory: %q", c.goarch, op, ins.Raw)
	}
	if destination.Kind == OpReg && !isX86YrlRegisterForArch(destination.Reg, c.goarch) {
		return fmt.Errorf("%s %s register is outside Go 1.27's Yml class: %q", c.goarch, op, ins.Raw)
	}
	typ := I16
	switch op[len(op)-1] {
	case 'L':
		typ = I32
	case 'Q':
		typ = I64
	}
	asm := strings.ToLower(op) + " $0"
	if destination.Kind == OpReg {
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q()\n",
			result, typ, asm, "=r,~{memory},~{dirflag},~{fpsr},~{flags}")
		return c.storeRegSized(destination.Reg, typ, "%"+result)
	}
	ptr, ptrType, err := c.x86DescriptorMemoryPointer(destination)
	if err != nil {
		return err
	}
	// Intel defines every memory destination as m16 even when Go selects the
	// L/Q spelling (the operand-size prefix only affects a register target).
	// LLVM's integrated assembler consequently rejects sldtl/sldtq, smswl/q,
	// and strl/q with memory, so emit the architectural unsuffixed m16 form.
	memoryAsm := strings.ToLower(op[:len(op)-1]) + " $0"
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s elementtype(%s) %s)\n",
		memoryAsm, "=*m,~{memory},~{dirflag},~{fpsr},~{flags}", ptrType, I16, ptr)
	return nil
}

func (c *amd64Ctx) x86DescriptorMemoryPointer(operand Operand) (ptr, ptrType string, err error) {
	switch operand.Kind {
	case OpMem:
		return c.ptrFromMem(operand.Mem)
	case OpSym:
		ptr, err := c.ptrFromSB(operand.Sym)
		return ptr, "ptr", err
	case OpFP:
		if c.classicFrame != "" {
			return c.classicFramePtr(operand.FPOffset), "ptr", nil
		}
		if ptr := c.fpParamAlloca[operand.FPOffset]; ptr != "" {
			return ptr, "ptr", nil
		}
		if ptr, _, ok := c.fpResultAlloca(operand.FPOffset); ok {
			return ptr, "ptr", nil
		}
		return "", "", fmt.Errorf("%s descriptor memory operand has no mutable FP slot at +%d(FP)", c.goarch, operand.FPOffset)
	default:
		return "", "", fmt.Errorf("%s descriptor instruction expected memory, got %s", c.goarch, operand.String())
	}
}
