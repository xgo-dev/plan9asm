package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"unicode"
)

// Initialized physical bytes are not a canonical bool witness. The existing
// scalar-I1 consumers retain their own entry/result proofs; an aggregate or
// contradictory result layout needs an independent complete canonical role.
// Inspect both declaration and modeled slots so dropping a bool field cannot
// turn an unregistered role into an ordinary numerical result.
func x86MixedBoolResultNeedsCanonicalRole(sig FuncSig, modeled []FrameSlot) bool {
	if sig.Ret == Void {
		return false
	}
	containsBool := func(typ LLVMType) bool {
		for _, token := range strings.FieldsFunc(string(typ), func(r rune) bool {
			return unicode.IsSpace(r) || strings.ContainsRune("{}[]<>,", r)
		}) {
			if token == string(I1) {
				return true
			}
		}
		return false
	}
	hasBool := containsBool(sig.Ret)
	for _, slots := range [][]FrameSlot{sig.Frame.Results, modeled} {
		for _, slot := range slots {
			hasBool = hasBool || containsBool(slot.Type)
		}
	}
	if !hasBool {
		return false
	}
	if sig.Ret != I1 || len(sig.Frame.Results) > 1 || len(modeled) > 1 {
		return true
	}
	if len(sig.Frame.Results) == 0 && len(modeled) == 0 {
		return false // A scalar register-result role has no logical FP slots.
	}
	return !reflect.DeepEqual(sig.Frame.Results, modeled) || sig.Frame.Results[0].Type != I1
}

func (c *amd64Ctx) validateMixedBoolResultRole() error {
	if !x86MixedBoolResultNeedsCanonicalRole(c.sig, c.fpResults) {
		return nil
	}
	if !reflect.DeepEqual(c.sig.Frame.Results, c.fpResults) {
		return fmt.Errorf("%w: mixed bool result requires an independent canonical result role", ErrProbeNeedsContext)
	}
	if c.fpScalarSource.x86FixedLocal == nil {
		if !x86OrdinaryMixedBoolResultRole(c.fpScalarSource, c.sig, c.goarch) {
			return fmt.Errorf("%w: mixed bool result requires an ordinary bounded ABI0 declaration", ErrProbeNeedsContext)
		}
		if err := c.scalarFPResultInitialized(); err != nil {
			return err
		}
		c.fpMixedBoolBytes = true
		return nil
	}
	// This consumer rechecks the actual declaration, original/normalized source,
	// all field writes and before/final live binding guards. A pointer alone is
	// not authority, nor does this add a new aggregate or native-frame producer.
	return c.scalarFPResultInitialized()
}

// This is a lowering-only logical frame shape, never a native entry, caller
// extent or source authentication. The complete NUM/canonical flow checker
// independently validates every typed slot, instruction and path to RET.
func x86OrdinaryMixedBoolResultRole(fn Func, sig FuncSig, arch string) bool {
	if arch != "amd64" && arch != "386" || fn.FrameSize != 0 || strings.Contains(fn.Sym, "<") ||
		len(sig.ArgRegs) != 0 || sig.ARMEntry != nil || sig.ARM64GoRegisterABI != nil || sig.ARM64ClosureABI != nil ||
		sig.WASMContext != "" || sig.WASMNative || sig.x86BorrowedBoolTail || sig.amd64GoArguments != nil ||
		sig.x86FixedLocal != nil || sig.x86CallerRegions != nil || len(fn.X86RawText) != 0 || fn.x86SourceStack != nil ||
		fn.x86FixedLocal != nil || fn.x86DirectTailRoot != nil || fn.x86ContinuationFlow != nil || fn.x86RawReplay != nil ||
		len(fn.x86ContinuationAddresses) != 0 || len(fn.x86IndirectLabels) != 0 || fn.x86BoolCalls != nil || fn.x86BoolReadonlyInputs {
		return false
	}
	fields, valid := parseLiteralStructFields(sig.Ret)
	if !valid || len(fields) < 2 || len(fields) != len(sig.Frame.Results) {
		return false
	}
	end, hasBool := int64(0), false
	for index, slot := range sig.Frame.Results {
		width := x86ResultScalarBytes(slot.Type, arch)
		if width <= 0 || slot.Type != fields[index] || slot.Index != index || slot.Field != -1 || len(slot.Fields) != 0 ||
			slot.Offset < end || slot.Offset > 4096-width {
			return false
		}
		end, hasBool = slot.Offset+width, hasBool || slot.Type == I1
	}
	// Omitted TEXT argument size is Go's unknown-size spelling, not an
	// explicit zero-byte frame. The typed declaration still bounds every
	// input/result, and an explicit conflicting extent remains invalid.
	if !hasBool || fn.ArgSize != end && !x86TEXTArgumentsUnspecified(fn) ||
		len(sig.Frame.Params) > 4096 || len(sig.Args) > 4096 {
		return false
	}
	represented := make(map[int]bool)
	for _, slot := range sig.Frame.Params {
		// Parameters include opaque pointer leaves, including slice/string
		// data. Occupancy is a frame role, not numerical result authority;
		// the complete flow checker keeps pointer and NUM bytes separate.
		if _, valid := x86ResultParameterRole(sig.Args, slot); !valid || x86FrameScalarBytes(slot.Type, arch) == 0 {
			return false
		}
		represented[slot.Index] = true
	}
	if len(represented) != len(sig.Args) {
		return false
	}
	for _, ins := range fn.Instrs {
		if ins.Op == "CALL" || isX86RawDirective(ins) || ins.x86Encoded || ins.x86SourceRaw != nil ||
			ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
			return false
		}
	}
	return true
}

func x86MixedBoolCanonicalTransfer(transfer x86ResultSourceTransfer) x86ResultSourceTransfer {
	return func(ordinal int, ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
		beforeFP, beforeGP := append([]bool(nil), state.canonicalFP...), state.canonicalGP
		if !transfer(ordinal, ins, state, owned, resultOffset, arch) {
			return false
		}
		state.canonicalFP, state.canonicalGP = x86ABI0CanonicalBytesAfter(ins, beforeFP, beforeGP, arch)
		for offset := range state.canonicalFP {
			state.canonicalFP[offset] = state.canonicalFP[offset] && state.fp[offset]
		}
		for root := range state.canonicalGP {
			state.canonicalGP[root] &= state.gp[root]
		}
		return true
	}
}
