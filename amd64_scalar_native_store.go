package plan9asm

import (
	"fmt"
	"strings"
)

// Go's GP stores share their address classes with Zm_r loads. Yi32 immediate
// rows retain their own encoded width, including sign extension for MOVQ.
// FP/AUTO, static symbols, segments and SIMD/MMX keep their separate roles.
type x86ScalarNativeStoreForm struct {
	source      Operand
	destination Operand
	bytes       int64
}

func x86ScalarNativeStoreProperties(op Op, ins Instr, arch string) (x86ScalarNativeStoreForm, bool, error) {
	if len(ins.Args) != 2 || !x86OrdinaryNativeMemoryOperand(ins.Args[1], arch) {
		return x86ScalarNativeStoreForm{}, false, nil
	}
	return x86ScalarRegisterStoreProperties(op, ins, arch)
}

func x86ScalarRegisterStoreProperties(op Op, ins Instr, arch string) (x86ScalarNativeStoreForm, bool, error) {
	if form, known, err := x86ScalarMoveAliasProperties(op, ins, arch); known {
		if err != nil {
			return x86ScalarNativeStoreForm{}, true, err
		}
		op = form.spec.canonical
	}
	if len(ins.Args) != 2 || (ins.Args[0].Kind != OpReg && ins.Args[0].Kind != OpImm) || ins.Args[1].Kind != OpMem ||
		ins.Args[1].Mem.Sym != "" || ins.Args[1].Mem.Segment != "" ||
		ins.Args[1].Mem.Index == FS || ins.Args[1].Mem.Index == GS {
		return x86ScalarNativeStoreForm{}, false, nil
	}
	projected := ins
	projected.Op = op
	source := ins.Args[0]
	register := source
	if source.Kind == OpImm {
		register = Operand{Kind: OpReg, Reg: AX} // Validate only the shared native address/width row.
	}
	projected.Args = []Operand{ins.Args[1], register}
	form, known, err := x86ScalarRegisterLoadProperties(op, projected, arch)
	if !known || err != nil {
		return x86ScalarNativeStoreForm{}, known, err
	}
	if source.Kind == OpImm {
		if source.ImmRaw != "" || source.ImmIsFloat ||
			arch != "386" && (source.Imm < -2147483648 || source.Imm > 4294967295) {
			return x86ScalarNativeStoreForm{}, true, fmt.Errorf("%s %s native store needs Go's resolved Yi32 immediate: %q", arch, op, ins.Raw)
		}
		source.Imm = amd64ScalarAddSubImmediateInt64(source.Imm, int(form.bytes*8))
	} else {
		source.Reg = form.destination // Preserve the actual Go byte/REX interpretation.
	}
	return x86ScalarNativeStoreForm{source, form.source, form.bytes}, true, nil
}

func (c *amd64Ctx) scalarNativeStoreProperties(op Op, ins Instr) (x86ScalarNativeStoreForm, bool, error) {
	if c.fixedLocal != nil {
		if access, valid := c.fixedLocalMemoryAccess(ins, 1); valid && access.nativeInput {
			return x86ScalarRegisterStoreProperties(op, ins, c.goarch)
		}
	}
	return x86ScalarNativeStoreProperties(op, ins, c.goarch)
}

func (c *amd64Ctx) lowerScalarNativeStore(form x86ScalarNativeStoreForm, ins Instr) error {
	if form.source.Kind == OpReg && form.source.Reg != ins.Args[0].Reg && (form.source.Reg == SP || form.source.Reg == BP) {
		return fmt.Errorf("%w: REX byte alias needs its physical SP/BP read contract", ErrProbeNeedsContext)
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
		return fmt.Errorf("%w: scalar MOV needs its original native address size", ErrProbeNeedsContext)
	}
	typ := amd64IntegerTypeForBits(int(form.bytes * 8))
	value, err := c.evalIntSized(form.source, typ)
	if err != nil {
		return err
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(form.destination)
	if err != nil {
		return err
	}
	// Preserve even a dead write/fault, with no alignment, extent or alias
	// assumptions. Continuing this one effect grants no reusable memory fact.
	fmt.Fprintf(c.b, "  store volatile %s %s, %s %s, align 1\n", typ, value, pointerType, pointer)
	return nil
}

func x86LoweredScalarNativeStore(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	return x86LoweredScalarNativeStoreWithAddressBits(ins, state, owned, arch, false)
}

// This scope is not an initialized-value or memory certificate. The complete
// source flow must separately establish the actual typed address-bit input and
// native destination. Calls, physical entries and other storage owners cannot
// borrow this leaf-only bit-copy continuation or its lack of Go safepoints.
func x86LeafNativeAddressBitStoreScope(fn Func, sig FuncSig, arch string) bool {
	if arch != "386" && arch != "amd64" || fn.FrameSize != 0 || strings.Contains(fn.Sym, "<") ||
		len(sig.ArgRegs) != 0 || len(fn.X86RawText) != 0 || fn.x86SourceStack != nil || fn.x86FixedLocal != nil ||
		fn.x86ContinuationFlow != nil || fn.x86DirectTailRoot != nil || sig.x86CallerRegions != nil {
		return false
	}
	for _, ins := range fn.Instrs {
		if ins.Op == OpCALL || !x86ResultNamedPredicateInstruction(ins) {
			return false
		}
	}
	for _, slot := range sig.Frame.Params {
		if slot.Type == Ptr && slot.Index >= 0 && slot.Index < len(sig.Args) && sig.Args[slot.Index] == Ptr {
			return true
		}
	}
	return false
}

func x86LoweredScalarNativeStoreWithAddressBits(ins Instr, state *x86ResultState, owned []bool,
	arch string, addressBits bool) (bool, bool) {
	form, known, err := x86ScalarNativeStoreProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil ||
		(form.source.Kind == OpReg && x86LogicalSourceFrameRegister(form.source.Reg, arch)) ||
		!x86ResultIncomingPointerAddressIdentity(form.destination, state, arch) {
		return false, true
	}
	if addressBits && form.bytes == x86ResultPointerWord(arch) && form.source.Kind == OpReg {
		if root, _, valid := x86ResultGP(form.source.Reg, form.bytes, arch); valid && state.callerAddressGP[root] {
			// Copy exactly one complete word of actual caller-address bits.
			// No NUM, pointee, GC-root, escape-safety or reusable address fact
			// follows from this original volatile effect, even when it succeeds.
			return true, true
		}
	}
	if addressBits && form.source.Kind == OpReg {
		if register, mask, valid := x86ResultGP(form.source.Reg, form.bytes, arch); valid &&
			int(state.nativeLEAAddressBits.register) == register && state.nativeLEAAddressBits.bytes != 0 &&
			(state.gp[register]|state.nativeLEAAddressBits.bytes)&mask == mask {
			return true, true // Observe exact adjacent LEA bits without granting numerical initialization.
		}
	}
	// A native NUM store likewise changes no logical bytes or register facts.
	// Standalone, caller and physical-frame observers have no paired emitter.
	return x86ResultRead(form.source, form.bytes, state, owned, arch), true
}
