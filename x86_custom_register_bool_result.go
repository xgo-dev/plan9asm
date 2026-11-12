package plan9asm

import (
	"fmt"
	"strings"
)

// Explicit ArgRegs is a logical translator transport, not Go ABIInternal or
// ABI0. It supplies only the declared register bytes and an opaque pointer
// identity; no FP/AUTO, native entry, caller backing or spill storage exists.
func checkX86CustomRegisterBoolResultInitialization(fn Func, sig FuncSig, arch string, transfer x86ResultSourceTransfer) error {
	return checkX86LogicalRegisterResultInitialization(fn, sig, arch, transfer, true, false)
}

// This selector routes the existing no-argument AX return transport to its
// proof. It supplies no ABI layout, incoming register bytes or frame storage.
func x86LogicalScalarResultNeedsProof(sig FuncSig, arch string) bool {
	return arch == "386" && (sig.Ret == I8 || sig.Ret == I16 || sig.Ret == I32) &&
		len(sig.Args) == 0 && len(sig.ArgRegs) == 0 &&
		len(sig.Frame.Params) == 0 && len(sig.Frame.Results) == 0
}

func checkX86LogicalRegisterResultInitialization(fn Func, sig FuncSig, arch string,
	transfer x86ResultSourceTransfer, canonicalBool, privateStack bool) error {
	role := "logical scalar register result"
	validRole := x86LogicalScalarResultNeedsProof(sig, arch)
	width := x86ResultScalarBytes(sig.Ret, arch)
	if canonicalBool {
		role = "custom register bool result"
		validRole = arch == "386" && sig.Ret == I1 && len(sig.ArgRegs) != 0 &&
			len(sig.ArgRegs) == len(sig.Args) && len(sig.Args) <= 6
		width = 1
	}
	fail := func(reason string) error {
		return fmt.Errorf("%w: %s: %s", ErrProbeNeedsContext, role, reason)
	}
	if !validRole ||
		len(sig.Frame.Params) != 0 || len(sig.Frame.Results) != 0 || fn.FrameSize != 0 || fn.ArgSize != 0 ||
		sig.ARMEntry != nil || sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil || sig.WASMContext != "" || sig.WASMNative ||
		strings.Contains(fn.Sym, "<") || len(fn.X86RawText) != 0 || fn.x86SourceStack != nil || fn.x86FixedLocal != nil ||
		fn.x86DirectTailRoot != nil || fn.x86BoolCalls != nil || sig.x86BorrowedBoolTail {
		return fail("requires a complete distinct ordinary mode32 logical register transport")
	}
	for _, ins := range fn.Instrs {
		if ins.x86Encoded || ins.x86SourceRaw != nil || ins.x86RawNearReturn != nil ||
			ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
			return fail("raw/native source requires its separate contract")
		}
	}
	initial := x86ResultState{}
	if privateStack {
		stack, err := x86ResultPrivateFlagsSource(fn, arch)
		if err != nil {
			return err
		}
		initial.valueStack = stack
	}
	occupied := [16]bool{}
	for index, typ := range sig.Args {
		width := int64(0)
		switch typ {
		case I1, I8:
			width = 1
		case I16:
			width = 2
		case I32, Ptr:
			width = 4
		}
		reg := sig.ArgRegs[index]
		root, _, valid := x86ResultGP(reg, 4, arch)
		if !valid || occupied[root] || width == 0 {
			return fail("arguments require unique whole-word register assignments and scalar types")
		}
		occupied[root] = true
		if typ == Ptr {
			initial.pointerGP[root], initial.callerAddressGP[root] = true, true
			continue
		}
		_, mask, valid := x86ResultGP(reg, width, arch)
		if !valid {
			return fail("narrow argument has no registered physical byte view")
		}
		initial.gp[root] = mask // No unspecified upper byte becomes initialized.
		if typ == I1 {
			initial.canonicalGP[root] = mask
		}
	}
	if canonicalBool {
		original := transfer
		transfer = func(pc int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
			before := state.canonicalGP
			if !original(pc, ins, state, owned, resultOffset, arch) {
				return false
			}
			state.canonicalGP = x86RegisterCanonicalBytesAfter(ins, before, arch)
			for index := range state.gp {
				state.canonicalGP[index] &= state.gp[index]
			}
			return true
		}
	}
	return checkX86ResultSourceFlow(fn, initial, nil, 0, arch, transfer,
		func(state x86ResultState, pc int) error {
			root, mask, _ := x86ResultGP(AX, width, arch)
			if state.gp[root]&mask != mask {
				return fail(fmt.Sprintf("AX low %d result bytes are not initialized on every path to RET %d", width, pc))
			}
			if canonicalBool && state.canonicalGP[root]&mask != mask {
				return fail(fmt.Sprintf("AX low result byte is not initialized and canonical on every path to RET %d", pc))
			}
			return nil
		})
}
