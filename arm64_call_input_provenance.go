package plan9asm

import (
	"strconv"
	"strings"
)

// Read the same leaves that callSym transports through an ordinary LLVM call.
// A callee cannot implicitly read the caller's virtual register allocas. This
// describes transport only: it proves neither caller-save preservation nor
// incoming pointer ownership. Unmodeled hidden inputs keep the legacy fallback.
func arm64ControlCallInputs(state *arm64ControlState, sig FuncSig, internal bool) ([]arm64ControlValue, bool) {
	if sig.ARM64ClosureABI != nil {
		return nil, false
	}
	var inputs []arm64ControlValue
	if internal && sig.ARM64GoRegisterABI != nil {
		if arm64ValidateGoRegisterABI(sig) != nil {
			return nil, false
		}
		for _, param := range sig.ARM64GoRegisterABI.Params {
			inputs = append(inputs, arm64ControlRead(state.regs, param.Register))
		}
		return inputs, true
	}
	if internal && len(sig.ArgRegs) == 0 {
		return nil, false
	}
	if !internal && len(sig.ArgRegs) == 0 && len(sig.Frame.Params) != 0 {
		seen := make([]bool, len(sig.Args))
		for _, param := range sig.Frame.Params {
			width := arm64MachineScalarWidth(param.Type)
			if param.Index < 0 || param.Index >= len(seen) || width == 0 || param.Offset > 1<<63-1-8 {
				return nil, false
			}
			seen[param.Index] = true
			inputs = append(inputs, arm64ControlCallFrameRead(state, param.Offset+8, width))
		}
		for _, present := range seen {
			if !present {
				return nil, false
			}
		}
		return inputs, true
	}
	if len(sig.ArgRegs) != 0 {
		if len(sig.ArgRegs) != len(sig.Args) {
			return nil, false
		}
		for index, typ := range sig.Args {
			if !isARM64ABIIntegerType(typ) && !isARM64ABIFloatingType(typ) {
				return nil, false
			}
			reg := sig.ArgRegs[index]
			_, floating := arm64ParseFReg(reg)
			if !isARM64GeneralOrZeroReg(reg) && !arm64StackReg(reg) && !floating {
				return nil, false
			}
			inputs = append(inputs, arm64ControlRead(state.regs, reg))
		}
		return inputs, true
	}
	// Match abiRegisterCallArgs' independent GP/FP cursors and flat aggregate
	// fields. Nested aggregates/arrays are not silently treated as one GP.
	var cursor arm64ABIRegisterCursor
	for _, typ := range sig.Args {
		fields, aggregate := parseLiteralStructFields(typ)
		if !aggregate {
			fields = []LLVMType{typ}
		}
		for _, field := range fields {
			reg, err := cursor.next(field)
			if err != nil {
				return nil, false
			}
			inputs = append(inputs, arm64ControlRead(state.regs, reg))
		}
	}
	return inputs, true
}

// Control cells conservatively describe eight bytes. An unaligned/narrow
// transport must include overlapping address witnesses, not only its exact
// memory key. Unsigned differences avoid signed subtraction overflow.
func arm64ControlCallFrameRead(state *arm64ControlState, offset int64, width int) arm64ControlValue {
	value := state.source(Operand{Kind: OpMem, Mem: MemRef{Base: SP, Off: offset}}, false)
	for key, cell := range state.memory {
		if !strings.HasPrefix(key, "sp:") {
			continue
		}
		start, err := strconv.ParseInt(key[3:], 10, 64)
		if err == nil && ((start <= offset && uint64(offset)-uint64(start) < 8) ||
			(start > offset && uint64(start)-uint64(offset) < uint64((width+7)/8))) {
			value = arm64ControlUnion(value, arm64ControlAddressTaint(cell))
		}
	}
	return value
}
