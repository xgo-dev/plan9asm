package plan9asm

import (
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

// decodedX86FarReturn preserves the actual operand-size attribute before
// x86asm.GoSyntax erases LRET's width or emits Intel's IRET/IRETD aliases.
// In both 32- and 64-bit modes a bare far return has a 32-bit operand size;
// only an effective REX.W promotes it to 64 bits. See Intel SDM volume 2,
// RET and IRET/IRETD/IRETQ, and Go's shared x86 ynone/yret encoder rows.
func decodedX86FarReturn(inst x86asm.Inst) (syntax string, recognized bool, err error) {
	kind := amd64InterruptReturn
	switch inst.Op {
	case x86asm.LRET:
		kind = amd64FarReturn
	case x86asm.IRET:
		if inst.DataSize != 16 {
			return "", true, fmt.Errorf("raw IRET has inconsistent operand size %d", inst.DataSize)
		}
	case x86asm.IRETD:
		if inst.DataSize != 32 {
			return "", true, fmt.Errorf("raw IRETD has inconsistent operand size %d", inst.DataSize)
		}
	case x86asm.IRETQ:
		if inst.DataSize != 64 {
			return "", true, fmt.Errorf("raw IRETQ has inconsistent operand size %d", inst.DataSize)
		}
	default:
		return "", false, nil
	}
	if (inst.Mode != 32 && inst.Mode != 64) || (inst.Mode == 32 && inst.DataSize == 64) {
		return "", true, fmt.Errorf("raw %s operand size %d is not supported in mode %d", inst.Op, inst.DataSize, inst.Mode)
	}
	for _, prefix := range inst.Prefix {
		if prefix == 0 {
			continue
		}
		// Register only the size prefixes represented by the typed family.
		// Never silently drop LOCK, REP, segment or address-size prefixes.
		// Decoder-rejected prefix orderings remain explicit decode failures.
		if prefix&x86asm.PrefixInvalid != 0 || (prefix&0xff != x86asm.PrefixDataSize && !prefix.IsREX()) {
			return "", true, fmt.Errorf("raw %s has an invalid or unregistered prefix %s", inst.Op, prefix)
		}
		if prefix.IsREX() && inst.Mode != 64 {
			return "", true, fmt.Errorf("raw %s has a REX prefix outside 64-bit mode", inst.Op)
		}
	}
	for _, extra := range inst.Args[1:] {
		if extra != nil {
			return "", true, fmt.Errorf("raw %s has extra operands", inst.Op)
		}
	}
	argument := ""
	if inst.Args[0] != nil {
		immediate, ok := inst.Args[0].(x86asm.Imm)
		if kind != amd64FarReturn || !ok || immediate < 0 || immediate > 65535 {
			return "", true, fmt.Errorf("raw %s requires no operand or an encoded unsigned imm16", inst.Op)
		}
		argument = fmt.Sprintf(" $%d", immediate)
	}
	for op, spec := range amd64FarReturnSpecs {
		if spec.kind == kind && spec.bits == inst.DataSize {
			return string(op) + argument, true, nil
		}
	}
	return "", true, fmt.Errorf("raw %s has unregistered operand size %d", inst.Op, inst.DataSize)
}
