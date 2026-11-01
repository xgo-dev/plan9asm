package plan9asm

import (
	"fmt"
	"strings"
)

func x86LegacyPackedFloatingNativeMemoryBits(ins Instr, goarch string) int {
	parsed, known, err := x86FloatArithmeticProperties(ins, goarch, "")
	form := parsed.x86FloatBinaryForm
	if !known || err != nil || !form.legacy || form.scalar || form.memory < 0 || ins.Args[form.memory].Kind == OpFP {
		return 0
	}
	return form.bits
}

// Legacy packed SSE arithmetic consumes one complete native m128 operand.
// An align-1 LLVM load followed by floating arithmetic can select a different
// load/instruction sequence, losing the original alignment and fault contract.
// Execute the exact validated opcode, including its source-order NaNs, MXCSR
// exceptions/rounding/DAZ/FTZ, and observable read even when the result is dead.
func (c *amd64Ctx) lowerLegacyPackedFloatingMemory(ins Instr, form x86FloatBinaryForm) error {
	source := ins.Args[form.first]
	if source.Kind == OpFP {
		// ABI0 virtual fields are independently allocated. Even a logical
		// contiguous field span is not original native stack alignment.
		return fmt.Errorf("%w: %s m128 needs contiguous original FP storage and native alignment context, not virtual ABI0 fields", ErrProbeNeedsContext, ins.Op)
	}
	if ins.x86AddressBits != 0 {
		return fmt.Errorf("%w: %s m128 lacks its original native address-size binding", ErrProbeNeedsContext, ins.Op)
	}
	if source.Kind == OpMem && !x86CallerMemoryCertified(ins, form.first) {
		if !x86OrdinaryNativeMemoryOperand(source, c.goarch) {
			return fmt.Errorf("%w: %s m128 needs original native stack backing, not virtual SP/BP", ErrProbeNeedsContext, ins.Op)
		}
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return err
	}
	left, err := c.loadX(ins.Args[form.second].Reg)
	if err != nil {
		return err
	}
	segment := ""
	if pointerType == "ptr addrspace(256)" {
		segment = "%gs:"
	} else if pointerType == "ptr addrspace(257)" {
		segment = "%fs:"
	}
	carrierType := amd64FMA3LLVMType(128/form.bits, form.bits)
	carrier, result, bytes := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", carrier, left, carrierType)
	assembly := strings.ToLower(string(ins.Op)) + " " + segment + "($2), $0"
	// The tied private XMM value is read before its output is written. No
	// original GP, flags, upper SIMD bytes, or additional pointer permission
	// is created. Segment-aware pointers retain the original FS/GS prefix.
	// SSE1 admits a <4 x float> XMM carrier on physical i386; a byte-vector
	// constraint there requires SSE2 and fails LLVM legalization. These are
	// only bitcasts, not extra arithmetic or an x87 transport ABI.
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %%%s, %s %s)\n", result, carrierType, assembly, "=x,0,r,~{memory},~{fpsr}", carrierType, carrier, pointerType, pointer)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bytes, carrierType, result)
	return c.storeLegacyPackedLogical(ins.Args[form.destination], "%"+bytes)
}
