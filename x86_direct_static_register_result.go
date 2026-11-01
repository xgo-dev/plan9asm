package plan9asm

import (
	"fmt"
	"strings"
)

// A zero-argument direct integer result is returned in AX, not in a fictional
// ABI0 FP slot. This only selects its complete numerical check. Static extents
// still come from the actual emitted module; raw RET retains its separate
// original-source, stack and continuation validation.
func x86DirectStaticRegisterResultCandidate(fn Func, sig FuncSig, arch string) bool {
	return len(sig.Frame.Results) == 0 && fn.ArgSize == 0 && x86StaticIntegerResultSourceCandidate(fn, sig, arch)
}

func x86StaticIntegerResultSourceCandidate(fn Func, sig FuncSig, arch string) bool {
	width := x86ResultScalarBytes(sig.Ret, arch)
	integer := sig.Ret == I8 || sig.Ret == I16 || sig.Ret == I32 || sig.Ret == I64
	if arch != "386" && arch != "amd64" || !integer || width <= 0 || width > x86ResultPointerWord(arch) ||
		len(sig.Args) != 0 || len(sig.Frame.Params) != 0 ||
		len(sig.ArgRegs) != 0 || sig.ARMEntry != nil || sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil ||
		sig.WASMContext != "" || sig.WASMNative || sig.amd64GoArguments != nil || sig.x86FixedLocal != nil ||
		sig.x86CallerRegions != nil || sig.x86BorrowedBoolTail ||
		fn.FrameSize != 0 || strings.Contains(fn.Sym, "<") || len(fn.X86RawText) != 0 ||
		fn.x86SourceStack != nil || fn.x86FixedLocal != nil || fn.x86ContinuationFlow != nil ||
		fn.x86DirectTailRoot != nil || fn.x86BoolCalls != nil {
		return false
	}
	for _, ins := range fn.Instrs {
		if len(ins.Args) == 2 && x86StaticIntegerResultMoveBytes(ins, arch) != 0 {
			for _, operand := range ins.Args {
				if _, static := x86StaticSBReadAddress(operand, arch); static {
					return true
				}
			}
		}
	}
	return false
}

// Select the existing scalar or GP/X memory grammar, including Go's qword
// aliases and VEX memory widths. A format supplies no initialized source,
// static extent, caller-memory or raw-entry permission.
func x86StaticIntegerResultMoveBytes(ins Instr, arch string) int64 {
	if form, known, err := x86GPSIMDTransferProperties(ins, arch); known {
		if err != nil || form.mmx || form.spec.rawOnly || form.memory < 0 {
			return 0
		}
		return int64(form.bits / 8)
	}
	return x86RawReturnScalarMoveBytes(x86SourceMoveInstruction(ins, arch).Op)
}

func (c *amd64Ctx) checkStaticIntegerResultInitialization() error {
	fn, sig, arch := c.fpScalarSource, c.sig, c.goarch
	fail := func(reason string) error {
		return fmt.Errorf("%w: direct static integer result: %s", ErrProbeNeedsContext, reason)
	}
	if !x86StaticIntegerResultSourceCandidate(fn, sig, arch) {
		return fail("requires the complete zero-argument scalar/static role")
	}
	if fn.x86RawReplay != nil {
		if err := fn.x86RawReplay.validate(fn, arch); err != nil {
			return err
		}
	}
	for _, ins := range fn.Instrs {
		if form := ins.x86RawNearReturn; form != nil {
			if fn.x86RawReplay == nil || ins.Op != OpRET || !form.nativeWidth || form.cleanup != 0 {
				return fail("raw return lost its independent native-width source role")
			}
			continue
		}
		if fn.x86RawReplay != nil {
			if _, bound := x86StaticIntegerResultRawView(ins, arch); bound {
				continue // The complete replay and independent raw memory guard remain required.
			}
		}
		if !x86ResultNamedPredicateInstruction(ins) || isX86RawDirective(ins) {
			return fail("another raw/native instruction needs its own complete effect")
		}
	}
	transfer := func(_ int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
		state.loweredStaticReads = c.fpScalarData
		state.goReadOnlyRead = c.goReadOnlyStorage.readFor(ins, arch)
		defer func() { state.loweredStaticReads, state.goReadOnlyRead = nil, nil }()
		if view, bound := x86StaticIntegerResultRawView(ins, arch); bound {
			ins = view // Local effect dispatch only; never rewrite either sealed source snapshot.
			if accepted, known := x86ResultUnknownSBAddressStep(ins, state, arch); known {
				return accepted // A materialized native address does not define numerical bytes.
			}
		}
		if accepted, known := c.scalarStaticAddressValueTransfer(ins, state, owned, arch); known {
			return accepted // Preserve the independently bound relocation-value producer.
		}
		if accepted, known := c.scalarStaticRMWTransfer(ins, state, owned, arch); known {
			return accepted
		}
		if accepted, known := x86ResultUnknownSBAddressStep(ins, state, arch); known {
			return accepted // Discarded source addresses never become numerical bytes.
		}
		width := x86StaticIntegerResultMoveBytes(ins, arch)
		if width != 0 && len(ins.Args) == 2 {
			if address, static := x86StaticSBReadAddress(ins.Args[1], arch); static {
				// Keep the same independently emitted static extent for every
				// scalar store. A typed X source needs its actual low bytes,
				// not a GP-register interpretation of the same source operand.
				if c.fpScalarData[address] < width {
					return false
				}
				if form, known, err := x86GPSIMDTransferProperties(ins, arch); known {
					return err == nil && form.memoryWrite &&
						x86ResultGPSIMDTransfer(ins, form, state, owned, resultOffset, arch)
				}
				return x86ResultRead(ins.Args[0], width, state, owned, arch)
			}
		}
		return x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch)
	}
	if !x86DirectStaticRegisterResultCandidate(fn, sig, arch) {
		// The same exact scalar/static MOV effects compose with the actual
		// ABI0 declaration. No fabricated FP field supplies a register result,
		// and no direct-register result can satisfy an unwritten FP result.
		return checkX86ABI0ResultInitializationAtSource(fn, sig, arch, transfer, true)
	}
	return checkX86ResultSourceFlow(fn, x86ResultState{}, nil, 0, arch, transfer,
		func(state x86ResultState, _ int) error {
			index, mask, valid := x86ResultGP(AX, x86ResultScalarBytes(sig.Ret, arch), arch)
			if !valid || state.gp[index]&mask != mask {
				return fail("AX result bytes are not initialized on every return path")
			}
			return nil
		})
}

// Only a complete replay-bound scalar RIP read or source-local LEAQ may use
// the existing named byte effects. The whole-file raw guard separately checks
// the actual DATA bytes/extent and every native return; this view grants none
// of those contracts and is never used by standalone declaration queries.
func x86StaticIntegerResultRawView(ins Instr, arch string) (Instr, bool) {
	if arch != "amd64" || ins.x86SourceRaw == nil || ins.x86RawNearReturn != nil ||
		ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return Instr{}, false
	}
	width := x86RawReturnScalarMoveBytes(ins.Op)
	read := width != 0 && x86RawReturnDecodedReadIdentity(ins) &&
		ins.x86RIPMemoryRead.source == 0 && ins.x86RIPMemoryRead.width == width &&
		len(ins.Args) == 2 && ins.Args[1].Kind == OpReg
	address := ins.Op == "LEAQ" && len(ins.x86RIPAddressData) != 0
	if !read && !address {
		return Instr{}, false
	}
	view := ins
	view.x86Encoded, view.x86SourceRaw = false, nil
	if address {
		_, _, _, _, address = x86SBLEAWriteShape(view, arch)
		if !address {
			return Instr{}, false
		}
	}
	return view, true
}
