package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerCmpBt(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if ok, terminated, err := c.lowerBitTestFamily(op, ins); ok {
		return ok, terminated, err
	}
	arch := c.goarch
	if arch == "" {
		arch = "amd64"
	}
	form, known, err := x86ScalarCompareProperties(op, ins, arch)
	if !known || err != nil {
		return known, false, err
	}
	for index, operand := range form.args {
		if operand.Kind == OpReg && operand.Reg == SP && ins.Args[index].Reg != SP {
			return true, false, fmt.Errorf("%w: Go REX byte view needs the original physical SP", ErrProbeNeedsContext)
		}
	}
	native := form.memory >= 0 && (x86OrdinaryNativeMemoryOperand(form.args[form.memory], arch) ||
		x86CallerMemoryCertified(ins, form.memory) || c.fixedLocalMemoryCertified(ins, form.memory))
	if native && (ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride) {
		return true, false, fmt.Errorf("%w: scalar comparison needs its original native address size", ErrProbeNeedsContext)
	}
	typ := LLVMType(fmt.Sprintf("i%d", form.bits))
	var values [2]string
	for index, operand := range form.args {
		if index == form.memory && native {
			if source := c.goReadOnlyStorage; source != nil {
				address, named := x86StaticSBSourceAddress(operand, arch)
				if named && source.object(address.symbol).variable != nil &&
					!source.allows(operand, int64(form.bits/8), arch) {
					return true, false, goReadOnlyContext("comparison exceeds the declared numerical span")
				}
			}
			pointer, pointerType, _, pointerErr := c.packedVectorMemoryPointer(operand)
			if pointerErr != nil {
				return true, false, pointerErr
			}
			loaded := c.newTmp()
			// A compare whose flags are dead must still perform the exact
			// native read (and fault). No backing/alignment assumption follows.
			fmt.Fprintf(c.b, "  %%%s = load volatile %s, %s %s, align 1\n", loaded, typ, pointerType, pointer)
			values[index] = "%" + loaded
		} else {
			values[index], err = c.evalIntSized(operand, typ)
			if err != nil {
				return true, false, err
			}
		}
	}
	if form.test {
		c.setTestFlagsSized(typ, values[0], values[1])
	} else {
		c.setCmpFlagsSized(typ, values[0], values[1])
	}
	return true, false, nil
}

func (c *amd64Ctx) setCmpFlagsSized(ty LLVMType, a, b string) {
	// Unlike most Plan 9 x86 instructions, CMP spells its operands in
	// comparison order: CMP a,b sets flags for a-b.
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sub %s %s, %s\n", result, ty, a, b)
	c.setAuxiliaryCarryFlag(ty, a, b, "%"+result)
	zt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %s, %s\n", zt, ty, a, b)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zt, c.flagsZSlot)
	sign := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", sign, ty, result)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", sign, c.flagsSltSlot)
	ult := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult %s %s, %s\n", ult, ty, a, b)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", ult, c.flagsCFSlot)
	xorOperands := c.newTmp()
	xorResult := c.newTmp()
	overflowBits := c.newTmp()
	overflow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", xorOperands, ty, a, b)
	fmt.Fprintf(c.b, "  %%%s = xor %s %s, %%%s\n", xorResult, ty, a, result)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", overflowBits, ty, xorOperands, xorResult)
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", overflow, ty, overflowBits)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", overflow, c.flagsOFSlot)
	c.setParityFlagSized(ty, "%"+result)
}

func (c *amd64Ctx) setTestFlagsSized(ty LLVMType, a, b string) {
	// Z from (a&b)==0, signed-lt from (a&b)<0, CF cleared.
	and := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", and, ty, a, b)
	zt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp eq %s %%%s, 0\n", zt, ty, and)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zt, c.flagsZSlot)
	slt := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp slt %s %%%s, 0\n", slt, ty, and)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", slt, c.flagsSltSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
	fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
	c.setParityFlagSized(ty, "%"+and)
}

func (c *amd64Ctx) evalIntSized(op Operand, ty LLVMType) (string, error) {
	if err := unresolvedSymbolicImmediateErrorForArch(op, ArchAMD64); err != nil {
		return "", err
	}
	if read := c.goReadOnlyOperand; read != nil && ty == LLVMType(fmt.Sprintf("i%d", read.width*8)) && read.allows(op, read.width) {
		pointer, pointerType, _, err := c.packedVectorMemoryPointer(op)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load volatile %s, %s %s, align 1\n", value, ty, pointerType, pointer)
		return "%" + value, nil
	}
	switch op.Kind {
	case OpImm:
		// LLVM will interpret the literal in the destination integer width.
		return fmt.Sprintf("%d", op.Imm), nil
	case OpReg:
		v64, err := c.loadReg(op.Reg)
		if err != nil {
			return "", err
		}
		if ty == I64 {
			return v64, nil
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, ty)
		return "%" + t, nil
	case OpFP:
		v64, err := c.evalFPToI64(op.FPOffset)
		if err != nil {
			return "", err
		}
		if ty == I64 {
			return v64, nil
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", t, v64, ty)
		return "%" + t, nil
	case OpMem:
		p, ptrType, err := c.ptrFromMem(op.Mem)
		if err != nil {
			return "", err
		}
		t := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, %s %s, align 1\n", t, ty, ptrType, p)
		return "%" + t, nil
	case OpSym:
		s := strings.TrimSpace(op.Sym)
		if strings.HasPrefix(s, "$") {
			address := strings.TrimSpace(strings.TrimPrefix(s, "$"))
			if memory, matched, err := parseX86SymbolIndexedMemory(address); matched {
				if err != nil {
					return "", err
				}
				wide, err := c.addrFromSymbolIndexedAddress(memory)
				if err != nil || ty == I64 {
					return wide, err
				}
				value := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to %s\n", value, wide, ty)
				return "%" + value, nil
			}
			if strings.HasSuffix(address, "(SB)") {
				p, err := c.ptrFromSB(address)
				if err != nil {
					return "", err
				}
				wide := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", wide, p)
				if ty == I64 {
					return "%" + wide, nil
				}
				value := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to %s\n", value, wide, ty)
				return "%" + value, nil
			}
			return "", fmt.Errorf("unresolved symbolic immediate %q", op.Sym)
		}
		// Go's x86 syntax treats a bare integer as absolute memory. Keep
		// this distinct from the '$' immediate spelling above.
		if address, parseErr := parseInt(s); parseErr == nil {
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", t, ty, c.ptrFromAddrI64(fmt.Sprintf("%d", address)))
			return "%" + t, nil
		}
		if strings.HasSuffix(s, "(SB)") {
			p, err := c.ptrFromSB(s)
			if err != nil {
				return "", err
			}
			t := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", t, ty, p)
			return "%" + t, nil
		}
		return "", fmt.Errorf("amd64: unsupported sym int operand: %s", op.String())
	default:
		return "", fmt.Errorf("amd64: unsupported int operand: %s", op.String())
	}
}
