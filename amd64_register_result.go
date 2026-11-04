package plan9asm

import (
	"fmt"
	"go/types"
	"strings"
)

func amd64IntegerRegisterResultBytes(typ LLVMType) int64 {
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

// This restriction-only selector reads the declared return type, never Frame
// validity or the instruction stream. A missing/malformed layout must still
// reach the same cached complete-source check as an ordinary valid tuple.
func amd64RegisterTupleResultNeedsProof(fn Func, sig FuncSig, arch string) bool {
	if arch != "amd64" || !strings.HasSuffix(fn.Sym, "<ABIInternal>") {
		return false
	}
	fields, tuple := parseLiteralStructFields(sig.Ret)
	if !tuple || len(fields) < 2 {
		return false
	}
	for _, field := range fields {
		if amd64IntegerRegisterResultBytes(field) == 0 {
			return false
		}
	}
	return true
}

// A flattened LLVM return does not retain Go's whole-value assignment rule.
// Consume the already selected declaration once: structs recurse, arrays with
// more than one element need stack transport, and every complete result must
// fit the remaining numerical register bank. This grants no storage access.
func goAMD64NumericalRegisterResults(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() != nil || sig.Variadic() {
		return false
	}
	var leaves func(types.Type) (int, bool)
	leaves = func(typ types.Type) (int, bool) {
		switch typ := typ.Underlying().(type) {
		case *types.Basic:
			return 1, typ.Info()&types.IsInteger != 0
		case *types.Array:
			if typ.Len() == 0 {
				return 0, true
			}
			if typ.Len() == 1 {
				return leaves(typ.Elem())
			}
		case *types.Struct:
			count := 0
			for index := 0; index < typ.NumFields(); index++ {
				n, valid := leaves(typ.Field(index).Type())
				if !valid || n > 9-count {
					return 0, false
				}
				count += n
			}
			return count, true
		}
		return 0, false
	}
	used := 0
	for index := 0; index < sig.Results().Len(); index++ {
		n, valid := leaves(sig.Results().At(index).Type())
		if !valid || n > 9-used {
			return false // Do not partially assign a result that belongs on the stack.
		}
		used += n
	}
	return true
}

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
	resultWidth := amd64IntegerRegisterResultBytes(sig.Ret)
	if sig.Ret == I1 {
		resultWidth = 1
	}
	var resultWidths []int64
	if sig.Ret == Void {
		if len(sig.Frame.Results) != 0 {
			return fail("Void entry cannot declare a result transport")
		}
	} else if fields, tuple := parseLiteralStructFields(sig.Ret); tuple {
		if len(fields) < 2 || len(fields) > len(registers) || len(sig.Frame.Results) != len(fields) {
			return fail("requires one complete flat integer register tuple")
		}
		resultWidths = make([]int64, len(fields))
		for index, typ := range fields {
			result := sig.Frame.Results[index]
			bytes := amd64IntegerRegisterResultBytes(typ)
			if bytes == 0 || result.Type != typ || result.Index != index || result.Field != -1 || len(result.Fields) != 0 {
				return fail("tuple result transport differs from its integer signature")
			}
			resultWidths[index] = bytes
		}
	} else {
		if resultWidth == 0 || len(sig.Frame.Results) != 1 {
			return fail("requires one complete integer register result")
		}
		result := sig.Frame.Results[0]
		if result.Type != sig.Ret || result.Index != 0 || result.Field != -1 || len(result.Fields) != 0 {
			return fail("result transport differs from the scalar signature")
		}
		resultWidths = []int64{resultWidth}
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
			bytes := amd64IntegerRegisterResultBytes(typ)
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
			for index, bytes := range resultWidths {
				reg, mask, _ := x86ResultGP(registers[index], bytes, "amd64")
				if state.gp[reg]&mask != mask {
					return fail(fmt.Sprintf("%s result bytes are not initialized on every path to RET %d", registers[index], pc))
				}
				if sig.Ret == I1 && state.canonicalGP[reg]&mask != mask {
					return fail(fmt.Sprintf("AX bool result byte is not canonical zero/one on every path to RET %d", pc))
				}
			}
			return nil
		})
}
