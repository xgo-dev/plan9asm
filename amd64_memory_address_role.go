package plan9asm

import (
	"math"
	"strings"
)

// NAME_EXTERN/NAME_STATIC in the non-shared Go 386 encoder discards Reg,
// including a nonscaled SP/BP annotation. Index remains an actual address
// input. AMD64 uses RIP and rejects either annotation. This describes address
// roles, not backing, initialized bytes, alignment or caller permissions.
func x86SBMemoryAddressRole(operand Operand, arch string) (MemRef, bool) {
	var memory MemRef
	switch operand.Kind {
	case OpSym:
		memory.Sym = operand.Sym
	case OpMem:
		memory = operand.Mem
		if x86SymbolIndexedMemoryError(memory, arch) != nil {
			return MemRef{}, false
		}
	default:
		return MemRef{}, false
	}
	if arch != "386" && arch != "amd64" ||
		!strings.HasSuffix(strings.TrimSpace(memory.Sym), "(SB)") {
		return MemRef{}, false
	}
	if arch == "386" {
		memory.Base = ""
	}
	return memory, true
}

// Native emitters may additionally possess a checked physical frame token.
// This ordinary branch does not create one, including for an effective Index.
// BP is an ordinary GP in mode32, not an implicit physical frame binding.
// It classifies already validated operands; the typed instruction grammar must
// first reject a bare name or malformed address instead of inventing storage.
func x86OrdinaryNativeMemoryOperand(operand Operand, arch string) bool {
	if operand.Kind == OpSym {
		return true
	}
	if operand.Kind != OpMem {
		return false
	}
	memory := operand.Mem
	if named, valid := x86SBMemoryAddressRole(operand, arch); valid {
		memory = named
	}
	return !x86LogicalSourceFrameRegister(memory.Base, arch) && !x86LogicalSourceFrameRegister(memory.Index, arch)
}

func x86RegisterAddressedNativeMemoryOperand(operand Operand, arch string) bool {
	return operand.Kind == OpMem && operand.Mem.Sym == "" && x86OrdinaryNativeMemoryOperand(operand, arch)
}

// The key includes the complete effective displacement, not Operand.String:
// raw AST memory can hold a displacement in addition to its symbolic offset.
type x86StaticSBAddress struct {
	symbol string
	offset int64
}

func x86StaticSBReadAddress(operand Operand, arch string) (x86StaticSBAddress, bool) {
	address, valid := x86StaticSBSourceAddress(operand, arch)
	return address, valid && address.offset >= 0
}

// Address formation permits signed addends. Only a read additionally needs
// a nonnegative offset and an independently checked complete storage extent.
func x86StaticSBSourceAddress(operand Operand, arch string) (x86StaticSBAddress, bool) {
	memory, valid := x86SBMemoryAddressRole(operand, arch)
	if !valid || memory.Index != "" || memory.Scale != 0 || memory.IndexExt != "" ||
		memory.OffRaw != "" || memory.Segment != "" {
		return x86StaticSBAddress{}, false
	}
	base, offset, valid := parseSBRef(memory.Sym)
	if !valid || base == "" || strings.IndexAny(base, "$+(),[] \t") >= 0 ||
		memory.Off > 0 && offset > math.MaxInt64-memory.Off ||
		memory.Off < 0 && offset < math.MinInt64-memory.Off {
		return x86StaticSBAddress{}, false
	}
	offset += memory.Off
	return x86StaticSBAddress{symbol: base, offset: offset}, true
}
