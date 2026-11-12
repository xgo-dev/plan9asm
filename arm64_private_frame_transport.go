package plan9asm

import (
	"strconv"
	"strings"
)

// Absent by default. This is the same explicit typed transport consumed by
// callSym/lowerRET, not a register preservation or pointer ownership promise.
type arm64PrivateFrameTransport struct {
	entry     FuncSig
	resolve   func(string) string
	sigs      map[string]FuncSig
	nanosleep *arm64NanosleepInputProof
}

func (transport *arm64PrivateFrameTransport) consume(ins Instr, addresses arm64PrivateFrameAddresses, entryInternal bool) bool {
	state := &arm64ControlState{
		regs:   map[Reg]arm64ControlValue{SP: arm64ControlFromMap(map[string]bool{"sp:0": true})},
		memory: make(map[string]arm64ControlValue),
	}
	for reg, address := range addresses {
		offset := "unknown"
		if address.exact {
			offset = strconv.FormatInt(address.offset, 10)
		}
		state.regs[reg] = arm64ControlFromMap(map[string]bool{"sp:" + offset: true})
	}
	if arm64ControlOp(ins) == OpRET {
		if len(ins.Args) != 0 {
			return false // Native/symbol return transport remains unproved here.
		}
		sig := transport.entry
		if sig.ARM64ClosureABI != nil || entryInternal && sig.ARM64GoRegisterABI == nil {
			return false
		}
		// FP result stores already reject frame addresses in transfer. Include
		// the register fallback as well, even when a source FP result is written.
		sig.Frame = FrameLayout{}
		result := &arm64ControlState{regs: make(map[Reg]arm64ControlValue), memory: make(map[string]arm64ControlValue)}
		arm64ControlWriteCallResults(result, sig, entryInternal, arm64ControlExternal())
		if sig.Ret != Void && len(result.regs) == 0 {
			return false
		}
		for reg := range result.regs {
			if _, frame := addresses.address(reg); frame {
				return false
			}
		}
		return true
	}
	if len(ins.Args) != 1 || ins.Args[0].Kind != OpSym {
		return false // Local register helpers and unknown/native calls stay strict.
	}
	symbol := strings.TrimSuffix(ins.Args[0].Sym, "(SB)")
	name := symbol
	if transport.resolve != nil {
		name = transport.resolve(name)
	}
	sig, present := transport.sigs[name]
	if !present {
		return false
	}
	internal := strings.HasSuffix(symbol, "<ABIInternal>")
	inputs, known := arm64ControlCallInputs(state, sig, internal)
	if !known {
		return false
	}
	for _, input := range inputs {
		for _, token := range arm64ControlKeys(input) {
			if strings.HasPrefix(token, "sp:") || strings.HasPrefix(token, "fp:") || strings.HasPrefix(token, "fpa:") {
				return false
			}
		}
	}
	// A declared result overwrites only its actual GP/FP transport. Untouched
	// scratch addresses remain private; ordinary source must redefine them
	// before a caller-save use, independently of this non-escape proof.
	arm64ControlWriteCallResults(state, sig, internal, arm64ControlExternal())
	for reg := range addresses {
		value := arm64ControlRead(state.regs, reg)
		frame := false
		for _, token := range arm64ControlKeys(value) {
			frame = frame || strings.HasPrefix(token, "sp:")
		}
		if !frame {
			delete(addresses, reg)
		}
	}
	return true
}
