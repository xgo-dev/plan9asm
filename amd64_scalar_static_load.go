package plan9asm

import "fmt"

type x86ScalarStaticLoadForm struct {
	source      Operand
	destination Reg
	bytes       int64
	extension   bool
}

// Reuse the complete scalar MOV/extension grammar, not its independent SDK
// source capability. A normalized copy describes only the effective SB row;
// the returned operand always retains the caller's original representation.
func x86ScalarStaticLoadProperties(ins Instr, arch string) (x86ScalarStaticLoadForm, bool) {
	if len(ins.Args) != 2 || !x86ResultNamedPredicateInstruction(ins) {
		return x86ScalarStaticLoadForm{}, false
	}
	address, valid := x86StaticSBReadAddress(ins.Args[0], arch)
	if !valid {
		return x86ScalarStaticLoadForm{}, false
	}
	projected := x86SourceMoveInstruction(ins, arch)
	projected.Args = []Operand{
		{Kind: OpSym, Sym: fmt.Sprintf("%s%+d(SB)", address.symbol, address.offset)},
		ins.Args[1],
	}
	form, valid := x86NumericalSBReadProperties(projected, arch)
	if !valid || form.spec.compare || form.spec.vector != x86NumericalSBScalar ||
		form.operand != 0 || form.partner != 1 {
		return x86ScalarStaticLoadForm{}, false
	}
	return x86ScalarStaticLoadForm{
		source: ins.Args[0], destination: ins.Args[1].Reg,
		bytes: form.spec.sourceBytes, extension: form.spec.extension,
	}, true
}

// Ordinary Go declarations supply numerical input only for this exact read.
// The original module-owned DATA, SDK and raw consumers remain independent.
func (c *amd64Ctx) lowerGoReadOnlyLoad(ins Instr) (bool, error) {
	form, known := x86ScalarStaticLoadProperties(ins, c.goarch)
	if !known || c.goReadOnlyStorage.readFor(ins, c.goarch) == nil {
		return false, nil
	}
	if err := c.scalarFPResultInitialized(); err != nil {
		return true, err
	}
	if form.extension {
		return true, c.lowerScalarExtensionMove(ins.Op, ins)
	}
	return true, c.lowerScalarNativeLoad(x86ScalarNativeLoadForm{
		source: form.source, destination: form.destination, bytes: form.bytes,
	}, ins)
}
