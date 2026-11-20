package plan9asm

import "strings"

// This is only a whole-function proof selector. An effect describes an access;
// it cannot provide its address, numerical inputs, raw identity or native entry.
// Keep the general effect directory's caller/frame admission domains unchanged.
func x86GPFaultingReadNeedsProof(ins Instr, arch string) bool {
	// Ordinary MOV and native atomics have complete existing grammars, but no
	// general GP effect registration. Project only their memory-read obligation;
	// do not register unconditional numerical writes for conditional exchanges.
	if _, known, err := x86ScalarNativeLoadProperties(ins.Op, ins, arch); known {
		return err == nil
	}
	if spec, known := amd64ExchangeSpecs[Op(strings.ToUpper(string(ins.Op)))]; known {
		form, err := parseAMD64ExchangeForm(arch, ins.Op, spec, ins)
		return err == nil && x86FaultingReadMemoryOperand(form.other)
	}
	if form, known, err := x86CompareExchangeProperties(ins.Op, ins, arch); known {
		return err == nil && !form.spec.pair && x86FaultingReadMemoryOperand(form.destination)
	}
	return false
}

func x86GPByteEffectReadsMemory(effect x86TypedByteEffect) bool {
	for _, operand := range effect.operands {
		if operand.read && x86FaultingReadMemoryOperand(operand.operand) {
			return true // Dynamic bit strings still read; this grants no fixed span.
		}
	}
	return false
}

func x86FaultingReadMemoryOperand(operand Operand) bool {
	// FP is a logical byte view, while a symbol address literal is not a load.
	// Native/virtual SP, segments and source ownership remain separate consumers.
	return operand.Kind != OpFP && isAMD64MemoryOperand(operand)
}
