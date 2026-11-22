package plan9asm

import (
	"fmt"
	"strings"
)

var x86CacheLineWritebackOps = map[string]struct{}{
	"CLFLUSH":    {},
	"CLFLUSHOPT": {},
	"CLWB":       {},
}

// All three Go yclflush rows consume a memory address without reading or
// writing its scalar value.
func x86CacheLineWritebackProperties(op Op, ins Instr, arch string) (string, bool, error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, _, suffix := strings.Cut(rawOp, ".")
	if _, ok := x86CacheLineWritebackOps[baseOp]; !ok {
		return "", false, nil
	}
	if suffix {
		return "", true, fmt.Errorf("%s %s does not accept instruction suffixes: %q", arch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 1 || !isAMD64MemoryOperand(ins.Args[0]) {
		return "", true, fmt.Errorf("%s %s expects one Go Ym memory operand: %q", arch, baseOp, ins.Raw)
	}
	return baseOp, true, nil
}

func x86TypedCacheLineWritebackByteEffect(ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	_, known, err := x86CacheLineWritebackProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	return x86TypedByteEffect{operands: []x86TypedByteOperand{
		{index: 0, operand: ins.Args[0], width: 1, read: true, addressOnly: true},
	}}, true, nil
}

func x86LoweredCacheLineWritebackStep(ins Instr, state *x86ResultState, owned []bool, arch, triple string) (bool, bool) {
	_, known, err := x86CacheLineWritebackProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ScalarFloatIntegerNativeTarget(arch, triple) || !x86ResultNamedPredicateInstruction(ins) {
		return false, true
	}
	address := ins.Args[0]
	if address.Kind == OpFP {
		offset := address.FPOffset
		return offset >= 0 && offset < int64(len(owned)) && owned[offset], true
	}
	if _, local := state.localOffset(address, 1); local {
		return true, true
	}
	if _, symbol := x86StaticSBReadAddress(address, arch); symbol {
		return true, true
	}
	return x86ResultIncomingPointerAddressIdentity(address, state, arch) ||
		x86ResultNativeNumericAddress(address, state, arch), true
}

// Retain the architectural cache operation and its ordering and persistence
// semantics through inline assembly.
func (c *amd64Ctx) lowerCacheLineWriteback(op Op, ins Instr) (ok bool, terminated bool, err error) {
	baseOp, known, err := x86CacheLineWritebackProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}

	ptr, ptrType, err := c.x86DescriptorMemoryPointer(ins.Args[0])
	if err != nil {
		return true, false, err
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s elementtype(i8) %s)\n",
		strings.ToLower(baseOp)+" $0", "*m,~{memory},~{dirflag},~{fpsr},~{flags}", ptrType, ptr)
	return true, false, nil
}
