package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerNativePackedReduction(op Op, ins Instr) (bool, bool, error) {
	local := ins
	local.Op = op
	form, known, err := x86PackedReductionProperties(local, c.goarch)
	if !known {
		return false, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return true, false, fmt.Errorf("reduction dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	ins = local
	if err != nil {
		return known, false, err
	}
	first := ins.Args[form.first]
	if first.Kind == OpFP {
		if form.legacy {
			return true, false, fmt.Errorf("%w: %s m128 needs original native FP alignment/backing", ErrProbeNeedsContext, op)
		}
		if err := c.validateFPVectorSpan(first.FPOffset, form.byteWidth); err != nil {
			return true, false, err
		}
	}
	if form.memory >= 0 && (ins.x86AddressBits != 0 || first.Kind == OpMem &&
		!x86OrdinaryNativeMemoryOperand(first, c.goarch) && !x86CallerMemoryCertified(ins, form.first) && !c.fixedLocalMemoryCertified(ins, form.first)) {
		return true, false, fmt.Errorf("%w: %s needs original native source backing", ErrProbeNeedsContext, op)
	}
	// Float carriers are bitcasts only. The exact original packed instruction
	// performs every arithmetic operation, including MXCSR and NaN priority;
	// no pure intrinsic, scalar expansion or load-folding assumption replaces it.
	typ := amd64FloatingVectorType(form.byteWidth/4, 32)
	load := func(operand Operand) (string, error) {
		bytes, err := c.loadPackedCompareBytes(operand, form.byteWidth)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", value, form.byteWidth, bytes, typ)
		return "%" + value, nil
	}
	second, err := load(ins.Args[form.second])
	if err != nil {
		return true, false, err
	}
	args, constraints := typ+" "+second, "=x,x"
	if form.legacy {
		constraints = "=x,0"
	}
	inputTemplate := "$2"
	if form.memory >= 0 && first.Kind != OpFP {
		pointer, pointerType, _, err := c.packedVectorMemoryPointer(first)
		if err != nil {
			return true, false, err
		}
		segment := ""
		if pointerType == "ptr addrspace(256)" {
			segment = "%gs:"
		} else if pointerType == "ptr addrspace(257)" {
			segment = "%fs:"
		}
		inputTemplate = segment + "($2)"
		args += ", " + pointerType + " " + pointer
		constraints += ",r"
	} else {
		input, err := load(first)
		if err != nil {
			return true, false, err
		}
		args += ", " + typ + " " + input
		constraints += ",x"
	}
	assembly := strings.ToLower(string(ins.Op)) + " "
	if form.dot {
		assembly += fmt.Sprintf("$$%d, ", form.immediate)
	}
	assembly += inputTemplate
	if !form.legacy {
		assembly += ", $1"
	}
	assembly += ", $0"
	result, bytes := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s)\n", result, typ, assembly, constraints+",~{memory},~{fpsr}", args)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <%d x i8>\n", bytes, typ, result, form.byteWidth)
	if form.legacy {
		return true, false, c.storeLegacyPackedLogical(ins.Args[form.destination], "%"+bytes)
	}
	return true, false, c.storePackedMoveOperand(ins.Args[form.destination], form.byteWidth, "%"+bytes)
}
