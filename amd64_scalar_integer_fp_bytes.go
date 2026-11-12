package plan9asm

import (
	"fmt"
	"math"
	"strings"
)

// A named GP move's FP operand describes instruction bytes, not a coercion to
// the first logical field. Keep exact natural scalar transfers on their old
// routes (in particular, opaque pointers). A new partial/interior/cross-field
// view must be handled here, including a failed proof; it cannot fall back to
// the legacy first-slot conversion or an unresolved-offset zero.
func (c *amd64Ctx) integerFPByteView(off, width int64, write bool) (bool, error) {
	return c.integerFPByteViewMode(off, width, write, false)
}

func (c *amd64Ctx) integerFPByteViewMode(off, width int64, write, exactBits bool) (bool, error) {
	if c.goarch == "386" && width == 8 {
		return true, fmt.Errorf("%w: mode32 has no GP qword FP move; X/m64 retains its separate typed consumer", ErrProbeNeedsContext)
	}
	if c.fpScalarSource.x86SourceStack != nil || c.fpScalarSource.x86FixedLocal != nil ||
		len(c.sig.Frame.Params)+len(c.fpResults) == 0 {
		return false, nil // Independently bound physical storage retains its consumer.
	}
	if !exactBits && x86IntegerFPNaturalTransfer(c.sig.Frame.Params, c.fpResults, off, width, write, c.goarch) {
		return false, nil
	}
	fail := func(reason string) (bool, error) {
		return true, fmt.Errorf("%w: integer FP byte view +%d/%d: %s", ErrProbeNeedsContext, off, width, reason)
	}
	if width != 1 && width != 2 && width != 4 && width != 8 || off < 0 || off > math.MaxInt64-width {
		return fail("invalid or overflowing span")
	}
	for current := off; current < off+width; current++ {
		matches := 0
		for _, group := range []struct {
			slots  []FrameSlot
			result bool
		}{{c.sig.Frame.Params, false}, {c.fpResults, true}} {
			for _, slot := range group.slots {
				size := x86FrameScalarBytes(slot.Type, c.goarch)
				if size <= 0 || slot.Offset < 0 || slot.Offset > math.MaxInt64-size {
					return fail("invalid scalar field extent")
				}
				if current < slot.Offset || current >= slot.Offset+size {
					continue
				}
				if slot.Type == Ptr {
					return fail("pointer bits retain their independent role")
				}
				if write && !group.result {
					if slot.Type == I1 {
						return fail("bool parameter writes retain their independent role")
					}
					if err := c.scalarFPResultInitialized(); err != nil {
						return true, err
					}
					if !c.fpScalarTrapOnly {
						return fail("parameter write needs its complete trap-only shadow role")
					}
				}
				matches++
			}
		}
		if matches != 1 {
			return fail(fmt.Sprintf("byte %d has %d scalar fields", current, matches))
		}
	}
	// Numerical definedness, canonical bool bytes and all source/native roles
	// are checked once for the complete original function, not inferred from the
	// layout or from zero-initialized implementation allocas.
	if err := c.scalarFPResultInitialized(); err != nil {
		return true, err
	}
	for current := off; current < off+width; current++ {
		slot, _, _ := c.fpVectorSlot(current)
		if slot.Type == I1 && !c.abi0BoolResultByteStorage() {
			return fail("physical bool bytes lack a checked canonical role")
		}
	}
	return true, nil
}

func x86IntegerFPNaturalTransfer(params, results []FrameSlot, off, width int64, write bool, arch string) bool {
	for group, slots := range [][]FrameSlot{params, results} {
		for _, slot := range slots {
			if slot.Offset == off && x86FrameScalarBytes(slot.Type, arch) == width {
				// Legacy evalFPToI64 handles floating parameters, but its
				// result branch has no floating bit view. Reuse the checked
				// byte engine rather than its unresolved-result zero.
				if group == 1 && !write && (slot.Type == "float" || slot.Type == "double") {
					return false
				}
				return true
			}
		}
	}
	return false
}

// The linear emitter also coerces the first FP field. Select the shared byte
// emitter/proof for new views on every public API, not only for functions that
// independently need CFG lowering (for example, mixed canonical bool tuples).
// This is solely a routing decision; the selected consumer must prove the role.
func x86IntegerFPByteMovesNeedCFG(fn Func, sig FuncSig, arch string) bool {
	if x86OrdinaryIntegerFPStoreNeedsProof(fn, sig, arch) {
		return true
	}
	if fn.x86SourceStack != nil || fn.x86FixedLocal != nil || len(sig.Frame.Params)+len(sig.Frame.Results) == 0 {
		return false
	}
	for _, ins := range fn.Instrs {
		width := x86IntegerFPMoveWidth(ins, arch)
		if width == 0 || len(ins.Args) != 2 {
			continue
		}
		for index, operand := range ins.Args {
			if operand.Kind == OpFP && !x86IntegerFPNaturalTransfer(sig.Frame.Params, sig.Frame.Results, operand.FPOffset, width, index == 1, arch) {
				return true
			}
		}
	}
	return false
}

// Ordinary declared integer results cannot publish unknown bytes simply
// because the final FP store is an exact natural field. This is a cost gate
// for the existing complete proof, not another ABI/state/alias producer.
// Logical bool-input aliases, existing virtual-SP/mutable FP storage and bound
// native/custom entry roles retain their independent consumers. This direct
// GP/FP admission class does not model those storage domains; a new byte view
// still goes through integerFPByteView and cannot borrow this separation.
func x86OrdinaryIntegerFPStoreNeedsProof(fn Func, sig FuncSig, arch string) bool {
	if (sig.Ret != I8 && sig.Ret != I16 && sig.Ret != I32 && sig.Ret != I64) ||
		len(sig.Frame.Results) != 1 || !x86DirectGPFPResultSourceRole(fn, sig, arch) {
		return false
	}
	for _, ins := range fn.Instrs {
		if x86IntegerFPMoveWidth(ins, arch) != 0 && len(ins.Args) == 2 && ins.Args[1].Kind == OpFP {
			return true
		}
	}
	return false
}

func x86DirectGPFPResultSourceRole(fn Func, sig FuncSig, arch string) bool {
	if arch != "386" && arch != "amd64" || sig.Ret == Void || len(sig.Frame.Results) == 0 ||
		fn.FrameSize != 0 || strings.Contains(fn.Sym, "<") || len(sig.ArgRegs) != 0 ||
		sig.ARMEntry != nil || sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil || sig.WASMContext != "" || sig.WASMNative ||
		sig.amd64GoArguments != nil || sig.x86FixedLocal != nil || sig.x86CallerRegions != nil || sig.x86BorrowedBoolTail ||
		len(fn.X86RawText) != 0 || fn.x86SourceStack != nil || fn.x86FixedLocal != nil || fn.x86RawReplay != nil ||
		fn.x86DirectTailRoot != nil || fn.x86ContinuationFlow != nil || len(fn.x86ContinuationAddresses) != 0 ||
		len(fn.x86IndirectLabels) != 0 || fn.x86BoolCalls != nil || fn.x86BoolReadonlyInputs {
		return false
	}
	for _, slot := range sig.Frame.Params {
		if slot.Type == I1 {
			return false // No new readonly logical-bool input/address role is inferred.
		}
	}
	for _, ins := range fn.Instrs {
		if ins.Op == "CALL" || isX86RawDirective(ins) || ins.x86Encoded || ins.x86SourceRaw != nil ||
			ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
			return false
		}
		if _, stack, err := x86StackWidthProperties(ins, arch); stack && err == nil {
			return false // Implicit value/FLAGS stack storage retains the same independent role.
		}
		for _, operand := range ins.Args {
			if operand.Kind == OpFPAddr || operand.Kind == OpMem && (operand.Mem.Base == SP || operand.Mem.Index == SP) {
				return false // Existing logical address/storage consumer, not native AUTO authority.
			}
		}
		if _, _, _, address := x86LogicalFPLEAWriteShape(ins, arch); address {
			return false
		}
		if x86IntegerFPMoveWidth(ins, arch) != 0 && len(ins.Args) == 2 && ins.Args[1].Kind == OpFP {
			width, offset := x86IntegerFPMoveWidth(ins, arch), ins.Args[1].FPOffset
			for _, slot := range sig.Frame.Params {
				if slot.Offset == offset && x86FrameScalarBytes(slot.Type, arch) == width {
					return false // Preserve the old exact-natural writable input shadow.
				}
			}
		}
	}
	return true
}

// This dispatch is only a cost/transport selector for the existing named GP
// move lowerer. Vector/MMX forms keep their own grammar and permissions; Go's
// MOVD/MOVDQ2Q aliases retain their original instruction identity.
func x86IntegerFPMoveWidth(original Instr, arch string) int64 {
	ins := x86SourceMoveInstruction(original, arch)
	for _, operand := range ins.Args {
		if operand.Kind != OpReg {
			continue
		}
		if _, ok := amd64ParseXReg(operand.Reg); ok {
			return 0
		}
		if _, ok := amd64ParseYReg(operand.Reg); ok {
			return 0
		}
		if _, ok := amd64ParseZReg(operand.Reg); ok {
			return 0
		}
		if _, ok := amd64ParseMReg(operand.Reg); ok {
			return 0
		}
	}
	switch ins.Op {
	case "MOVB":
		return 1
	case "MOVW":
		return 2
	case "MOVL":
		return 4
	case "MOVQ":
		if arch != "386" {
			return 8
		}
	}
	return 0
}

func (c *amd64Ctx) loadIntegerFPBytes(off int64, typ LLVMType) (string, bool, error) {
	return c.loadIntegerFPBytesMode(off, typ, false)
}

func (c *amd64Ctx) loadIntegerFPBytesMode(off int64, typ LLVMType, exactBits bool) (string, bool, error) {
	bits, _ := amd64IntegerTypeBits(typ)
	handled, err := c.integerFPByteViewMode(off, int64(bits/8), false, exactBits)
	if !handled || err != nil {
		return "", handled, err
	}
	bytes, err := c.loadFPVectorBytesMode(off, bits/8, true)
	if err != nil {
		return "", true, err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", value, bits/8, bytes, typ)
	return "%" + value, true, nil
}

func (c *amd64Ctx) storeIntegerFPBytes(off int64, typ LLVMType, value string) (bool, error) {
	bits, _ := amd64IntegerTypeBits(typ)
	handled, err := c.integerFPByteView(off, int64(bits/8), true)
	if !handled || err != nil {
		return handled, err
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", bytes, typ, value, bits/8)
	return true, c.storeFPVectorBytesMode(off, bits/8, "%"+bytes, "", true)
}
