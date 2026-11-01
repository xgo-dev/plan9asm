package plan9asm

import (
	"fmt"
	"strings"
)

// This lowering-only query observes the already modeled scalar register entry,
// not ABI0 FP fields. The source must explicitly select ABIInternal. It grants
// neither physical Go entry/closure/TLS state nor incoming spill-frame backing.
// See Go's cmd/compile/abi-internal.md, amd64 integer register assignment.
func checkAMD64RegisterResultInitialization(fn Func, sig FuncSig, transfer x86ResultSourceTransfer) error {
	fail := func(reason string) error {
		return fmt.Errorf("%w: amd64 register result initialization: %s", ErrProbeNeedsContext, reason)
	}
	registers := [...]Reg{AX, BX, CX, DI, SI, "R8", "R9", "R10", "R11"}
	if !strings.HasSuffix(fn.Sym, "<ABIInternal>") || len(sig.ArgRegs) != 0 ||
		sig.ARMEntry != nil || sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil ||
		sig.WASMContext != "" || sig.WASMNative || sig.amd64GoArguments == nil && len(sig.Args) > len(registers) ||
		len(fn.X86RawText) != 0 || fn.x86SourceStack != nil || fn.x86FixedLocal != nil {
		return fail("requires a complete ordinary scalar register entry")
	}
	for _, ins := range fn.Instrs {
		if ins.x86Encoded || ins.x86SourceRaw != nil || ins.x86RawNearReturn != nil ||
			ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
			return fail("raw/native source needs its separate entry contract")
		}
	}
	width := func(typ LLVMType) int64 {
		switch typ {
		case I8:
			return 1
		case I16:
			return 2
		case I32:
			return 4
		case I64:
			return 8
		}
		return 0
	}
	resultWidth := width(sig.Ret)
	if sig.Ret == I1 {
		resultWidth = 1
	}
	if sig.Ret == Void {
		if len(sig.Frame.Results) != 0 {
			return fail("Void entry cannot declare a result transport")
		}
	} else {
		if resultWidth == 0 || len(sig.Frame.Results) != 1 {
			return fail("requires one complete integer register result")
		}
		result := sig.Frame.Results[0]
		if result.Type != sig.Ret || result.Index != 0 || result.Field != -1 || len(result.Fields) != 0 {
			return fail("result transport differs from the scalar signature")
		}
	}
	initial := x86ResultState{}
	if entry := sig.amd64GoArguments; entry != nil {
		if !entry.valid(fn, sig, "amd64") {
			return fail("typed argument carrier lost its live original compiler/source binding")
		}
		var valid bool
		initial, valid = amd64GoArgumentInitialState(entry.plan)
		if !valid {
			return fail("invalid declared typed argument carrier bytes")
		}
	} else {
		for index, typ := range sig.Args {
			bytes := width(typ)
			if typ == Ptr {
				bytes = 8
			}
			if bytes == 0 {
				return fail("aggregate, floating, boolean or spilled argument needs its own register contract")
			}
			reg, mask, valid := x86ResultGP(registers[index], bytes, "amd64")
			if !valid {
				return fail("invalid integer register assignment")
			}
			if typ == Ptr {
				initial.pointerGP[reg] = true // Opaque identity, not numerical bytes or bounds.
				initial.callerAddressGP[reg] = true
			} else {
				initial.gp[reg] = mask // Narrow inputs do not initialize the unspecified upper bytes.
			}
		}
	}
	// No FP/AUTO ownership is imported from a classic signature or TEXT size.
	// The register role must close separately before gaining any stack storage.
	if sig.Ret == I1 {
		original := transfer
		transfer = func(pc int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
			if isX86RawDirective(ins) {
				return false
			}
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
	return checkX86ResultSourceFlow(fn, initial, nil, 0, "amd64", transfer,
		func(state x86ResultState, pc int) error {
			// The complete source flow still runs; only the result at RET is optional.
			if sig.Ret == Void {
				return nil
			}
			reg, mask, _ := x86ResultGP(AX, resultWidth, "amd64")
			if state.gp[reg]&mask != mask {
				return fail(fmt.Sprintf("AX result bytes are not initialized on every path to RET %d", pc))
			}
			if sig.Ret == I1 && state.canonicalGP[reg]&mask != mask {
				return fail(fmt.Sprintf("AX bool result byte is not canonical zero/one on every path to RET %d", pc))
			}
			return nil
		})
}
