package plan9asm

import (
	"fmt"
	"strings"
)

// The paired native emitter preserves the exact whole128 opcode, including
// alignment faults. Continuation defines the vector bytes but grants no
// initialized pointee, native store or virtual-frame permission. Callers must
// separately close the original source/physical-mode identity.
func x86LoweredLegacyPackedMoveRead(ins Instr, state *x86ResultState, owned []bool,
	resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86LegacyPackedMoveProperties(ins.Op, ins, arch)
	if !known || err != nil || form.memory != 0 || form.source.Kind != OpMem ||
		form.source.Mem.Sym != "" || !x86OrdinaryNativeMemoryOperand(form.source, arch) {
		return false, false
	}
	return x86ResultIncomingPointerReadAddressIdentity(form.source, state, arch) &&
		x86ResultStore(form.destination, 16, state, owned, resultOffset, arch), true
}

// Both floating and integer dispatch use the same whole-128-bit yxmov grammar.
// Native operands keep the original opcode: align-1 loads lose aligned faults,
// and ordinary LLVM loads disappear when the source result is dead.
func (c *amd64Ctx) lowerLegacyPackedMove(op Op, ins Instr) (bool, bool, error) {
	known, err := c.validateLegacyPackedMove(op, ins)
	if !known || err != nil {
		return known, false, err
	}
	arch := c.goarch
	if arch == "" {
		arch = "amd64"
	}
	form, _, err := x86LegacyPackedMoveProperties(op, ins, arch)
	if err != nil {
		return true, false, err
	}
	if form.memory >= 0 {
		memory := ins.Args[form.memory]
		if memory.Kind == OpFP && form.aligned {
			return true, false, fmt.Errorf("%w: %s FP operand needs its original native alignment", ErrProbeNeedsContext, op)
		}
		// Existing checked virtual FP/AUTO views are not native addresses.
		// They keep their independent layout handling; this rule gives them
		// neither native alignment nor permission to read adjacent storage.
		virtual := !x86OrdinaryNativeMemoryOperand(memory, arch)
		if memory.Kind == OpMem && (x86CallerMemoryCertified(ins, form.memory) || c.fixedLocalMemoryCertified(ins, form.memory)) {
			virtual = false
		}
		if !virtual {
			if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
				return true, false, fmt.Errorf("%w: legacy packed move needs its original native address size", ErrProbeNeedsContext)
			}
			return true, false, c.lowerLegacyPackedMoveNative(op, form)
		}
	}
	value, err := c.loadXVecOperand(form.source)
	if err != nil {
		return true, false, err
	}
	if form.destination.Kind == OpReg {
		return true, false, c.storeX(form.destination.Reg, value)
	}
	return true, false, c.storeXVecOperand(form.destination, value)
}

func (c *amd64Ctx) lowerLegacyPackedMoveNative(op Op, form x86LegacyPackedMoveForm) error {
	memory := form.source
	if form.memoryWrite {
		memory = form.destination
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(memory)
	if err != nil {
		return err
	}
	segment := ""
	if pointerType == "ptr addrspace(256)" {
		segment = "%gs:"
	} else if pointerType == "ptr addrspace(257)" {
		segment = "%fs:"
	}
	mnemonic := strings.ToLower(string(op))
	switch strings.ToUpper(string(op)) {
	case "MOVOU":
		mnemonic = "movdqu"
	case "MOVO", "MOVOA":
		mnemonic = "movdqa"
	}
	if form.memoryWrite {
		value, err := c.loadX(form.source.Reg)
		if err != nil {
			return err
		}
		carrier := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x float>\n", carrier, value)
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(<4 x float> %%%s, %s %s)\n",
			mnemonic+" $0, "+segment+"($1)", "x,r,~{memory}", carrier, pointerType, pointer)
		return nil
	}
	// A float carrier preserves SSE1's XMM class even on 386. It is a bit
	// transport only, with no floating arithmetic or change to MXCSR/FLAGS.
	loaded, bytes := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <4 x float> asm sideeffect %q, %q(%s %s)\n",
		loaded, mnemonic+" "+segment+"($1), $0", "=x,r,~{memory}", pointerType, pointer)
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x float> %%%s to <16 x i8>\n", bytes, loaded)
	return c.storeX(form.destination.Reg, "%"+bytes)
}
