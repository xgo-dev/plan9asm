package plan9asm

import (
	"fmt"
	"strings"
)

type x86ImmediatePackedCompareForm struct {
	x86PackedIntegerCompareForm
	unsigned  bool
	predicate uint8
}

// All eight _yvpcmpb opcodes use the same six ordered Go rows. Operand
// properties are shared with lowering and numerical effects; no source or
// memory authority follows from matching this grammar.
func x86ImmediatePackedCompareProperties(op Op, ins Instr, arch string) (x86ImmediatePackedCompareForm, bool, error) {
	base, suffix, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64ImmediatePackedCompareSpecs[base]
	if !known {
		return x86ImmediatePackedCompareForm{}, false, nil
	}
	form := x86ImmediatePackedCompareForm{unsigned: spec.unsigned}
	form.spec.laneBits, form.maskResult = spec.laneBits, true
	fail := func() (x86ImmediatePackedCompareForm, bool, error) {
		return form, true, fmt.Errorf("%s %s operands/suffix outside Go immediate packed compare grammar: %q", arch, op, ins.Raw)
	}
	// The named Go 386 frontend cannot represent these four/five-operand
	// instructions. It does not borrow the distinct physical raw EVEX role.
	physicalMode32 := arch == "386" && (ins.x86Encoded || ins.x86SourceRaw != nil)
	if arch != "amd64" && !physicalMode32 || ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) ||
		len(ins.Args) != 4 && len(ins.Args) != 5 {
		return fail()
	}
	immediate := ins.Args[0]
	if immediate.Kind != OpImm || immediate.ImmRaw != "" || immediate.ImmIsFloat || immediate.Imm < 0 || immediate.Imm > 255 {
		return fail()
	}
	binary, valid := x86PackedMaskCompareProperties(ins, arch, 1, spec.laneBits, dotted, suffix)
	if !valid {
		return fail()
	}
	if err := x86Mode32VectorRegisterContext(ins, arch); err != nil {
		return form, true, err
	}
	form.x86PackedBinaryForm = binary
	form.source, form.predicate = ins.Args[form.first], uint8(immediate.Imm)
	if form.memory >= 0 && (ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride) {
		return form, true, fmt.Errorf("%w: immediate packed compare has no bound address-size override", ErrProbeNeedsContext)
	}
	return form, true, nil
}
