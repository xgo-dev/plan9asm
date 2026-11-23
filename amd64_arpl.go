package plan9asm

import (
	"fmt"
	"strings"
)

// Go's 386 yrl_ml row encodes opcode 63 with a fixed word destination.
// The same opcode in 64-bit mode belongs to MOVSXD.
type x86ARPLForm struct {
	source, destination Operand
}

func x86ARPLProperties(op Op, ins Instr, arch string) (x86ARPLForm, bool, error) {
	var form x86ARPLForm
	name, _, suffix := strings.Cut(string(op), ".")
	if !strings.EqualFold(name, "ARPL") {
		return form, false, nil
	}
	fail := func() (x86ARPLForm, bool, error) {
		return form, true, fmt.Errorf("%s %s expects a 386 word register and register/memory destination: %q", arch, op, ins.Raw)
	}
	if arch != "386" || suffix || !strings.EqualFold(string(ins.Op), name) || len(ins.Args) != 2 ||
		ins.x86SourceRaw != nil && !x86RawOrdinaryVectorSource(ins, arch) {
		return fail()
	}
	form.source, form.destination = ins.Args[0], ins.Args[1]
	if form.source.Kind != OpReg || !isX86YrlRegisterForArch(form.source.Reg, arch) {
		return fail()
	}
	if form.destination.Kind == OpReg {
		if !isX86YrlRegisterForArch(form.destination.Reg, arch) {
			return fail()
		}
		return form, true, nil
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return form, true, fmt.Errorf("%w: ARPL requires the original native address form", ErrProbeNeedsContext)
	}
	if projected, segment, err := x86NamedSegmentMemorySource(ins, form.destination, arch); segment {
		if err != nil {
			return form, true, err
		}
		form.destination = projected
	}
	if !x86ScalarCompareMemoryValid(form.destination, arch) {
		return fail()
	}
	return form, true, nil
}

func (form x86ARPLForm) effects() x86TypedByteEffect {
	return x86TypedByteEffect{
		requiresResultProof: true,
		flagsDefined:        x86ByteFlagZF,
		flagsKilled:         x86ByteFlagZF,
		operands: []x86TypedByteOperand{
			{index: 0, operand: form.source, width: 2, read: true},
			{index: 1, operand: form.destination, width: 2, read: true, write: true},
		},
	}
}

func (c *amd64Ctx) loweredARPLTransfer(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86ARPLProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known && err != nil
	}
	if form.destination.Kind == OpFP {
		if _, err := c.logicalIntegerFPSpan(form.destination.FPOffset, 2); err != nil {
			return false, true
		}
		return x86ResultTransfer(ins, state, owned, 0, arch), true
	}
	if !x86OrdinaryNativeMemoryOperand(form.destination, arch) {
		return false, false
	}
	if !x86ResultRead(form.source, 2, state, owned, arch) {
		return false, true
	}
	// The typed raw identity is already checked. Project only the address
	// classifier for this paired native read/write, never the source entry.
	addressView := ins
	addressView.x86SourceRaw, addressView.x86Encoded = nil, false
	address := form.destination
	if !x86ResultNativeRMWAddress(addressView, address, state, owned, arch, form.source) &&
		!x86ResultNativeNumericAddress(address, state, arch) &&
		!c.ownsWritableStaticScalar(address, 2, arch) {
		return false, true
	}
	state.flags |= x86ByteFlagZF
	return true, true
}

func (c *amd64Ctx) lowerARPL(ins Instr, form x86ARPLForm) error {
	source, err := c.evalIntSized(form.source, I16)
	if err != nil {
		return err
	}
	if c.nativeMemoryOperand(ins, 1) {
		return c.emitNativeARPL(form.destination, source)
	}
	loadDestination := c.loadIntDestination
	if form.destination.Kind == OpFP {
		loadDestination = c.loadLogicalIntegerFPDestination
	}
	destination, write, err := loadDestination(form.destination, I16)
	if err != nil {
		return err
	}
	sourceRPL, oldRPL := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i16 %s, 3\n", sourceRPL, source)
	fmt.Fprintf(c.b, "  %%%s = and i16 %s, 3\n", oldRPL, destination)
	changed, selector, adjusted, result := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult i16 %%%s, %%%s\n", changed, oldRPL, sourceRPL)
	fmt.Fprintf(c.b, "  %%%s = and i16 %s, -4\n", selector, destination)
	fmt.Fprintf(c.b, "  %%%s = or i16 %%%s, %%%s\n", adjusted, selector, sourceRPL)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i16 %%%s, i16 %s\n", result, changed, adjusted, destination)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", changed, c.flagsZSlot)
	return write("%" + result)
}

func (c *amd64Ctx) emitNativeARPL(destination Operand, source string) error {
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) {
		return fmt.Errorf("%w: ARPL memory requires a native 386 target", ErrProbeNeedsContext)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(destination)
	if err != nil {
		return err
	}
	segment := ""
	switch pointerType {
	case "ptr addrspace(256)":
		segment = "%gs:"
	case "ptr addrspace(257)":
		segment = "%fs:"
	}
	// Keep the two-byte read/write and its fault behavior even if RPL is
	// unchanged. The output byte is written after both inputs are consumed.
	assembly := "arpl ${2:w}, " + segment + "$1; sete $0"
	changed, flag := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i8 asm sideeffect %q, \"=q,=*m,r,*m,~{memory},~{flags}\"(%s elementtype(i16) %s, i16 %s, %s elementtype(i16) %s)\n",
		changed, assembly, pointerType, pointer, source, pointerType, pointer)
	fmt.Fprintf(c.b, "  %%%s = trunc i8 %%%s to i1\n", flag, changed)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", flag, c.flagsZSlot)
	return nil
}
