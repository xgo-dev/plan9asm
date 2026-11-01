package plan9asm

import (
	"fmt"
	"strings"
)

type x86ImplicitDivideSpec struct {
	bits   int
	signed bool
}

// Complete Go ydivb/Ymb and ydivl/Yml rows. Division has trapping semantics,
// not multiply's ordinary numerical transfer or a generic LLVM div/rem rule.
var x86ImplicitDivideSpecs = map[Op]x86ImplicitDivideSpec{
	"DIVB": {8, false}, "DIVW": {16, false}, "DIVL": {32, false}, "DIVQ": {64, false},
	"IDIVB": {8, true}, "IDIVW": {16, true}, "IDIVL": {32, true}, "IDIVQ": {64, true},
}

type x86ImplicitDivideForm struct {
	spec   x86ImplicitDivideSpec
	source Operand
}

func x86ImplicitDivideProperties(op Op, ins Instr, arch string) (x86ImplicitDivideForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86ImplicitDivideSpecs[Op(name)]
	form := x86ImplicitDivideForm{spec: spec}
	if !known {
		return form, false, nil
	}
	fail := func() (x86ImplicitDivideForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside Go implicit division source grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || arch == "386" && spec.bits == 64 || dotted || len(ins.Args) != 1 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) ||
		!isX86ScalarMultiplyDivideSource(ins.Args[0], spec.bits, arch) {
		return fail()
	}
	form.source = ins.Args[0]
	if form.source.Kind == OpReg {
		return form, true, nil
	}
	if projected, segment, err := x86NamedSegmentMemorySource(ins, form.source, arch); segment {
		if err != nil {
			return form, true, err
		}
		form.source = projected
	}
	if form.source.Kind == OpMem {
		if err := x86SymbolIndexedMemoryError(form.source.Mem, arch); err != nil {
			return form, true, err
		}
	}
	if !x86ScalarCompareMemoryValid(form.source, arch) {
		return fail()
	}
	return form, true, nil
}

func (c *amd64Ctx) lowerImplicitDivide(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86ImplicitDivideProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) ||
		!x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil {
		return true, false, fmt.Errorf("%w: division needs its named x86 target and original address size", ErrProbeNeedsContext)
	}
	if form.source.Kind == OpReg {
		if x86LogicalSourceFrameRegister(form.source.Reg, c.goarch) {
			return true, false, fmt.Errorf("%w: division cannot consume an unbound physical SP/BP source", ErrProbeNeedsContext)
		}
	} else if form.source.Kind != OpFP && !x86OrdinaryNativeMemoryOperand(form.source, c.goarch) {
		return true, false, fmt.Errorf("%w: division needs owned logical FP bytes or original native memory backing", ErrProbeNeedsContext)
	}
	return true, false, c.emitNativeImplicitDivide(form)
}

// The original opcode owns zero-divisor and quotient-overflow #DE as well as
// exact memory fault priority. Pure LLVM div/rem can become poison or truncate
// an overflowing quotient; llvm.trap would raise the wrong native exception.
// Early-clobber outputs keep the divisor/address distinct from the tied old
// AX/DX inputs, including AL/AH aliases. No result is read before the call.
func (c *amd64Ctx) emitNativeImplicitDivide(form x86ImplicitDivideForm) error {
	width := amd64IntegerTypeForBits(form.spec.bits)
	accumulatorType := width
	if form.spec.bits == 8 {
		accumulatorType = I16
	}
	accumulator, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AX}, accumulatorType)
	if err != nil {
		return err
	}
	name := "div"
	if form.spec.signed {
		name = "idiv"
	}
	name += map[int]string{8: "b", 16: "w", 32: "l", 64: "q"}[form.spec.bits]
	outputType, constraints, arguments := string(accumulatorType), "=&{ax},0", string(accumulatorType)+" "+accumulator
	operandIndex := 2
	if form.spec.bits != 8 {
		high, err := c.evalIntSized(Operand{Kind: OpReg, Reg: DX}, width)
		if err != nil {
			return err
		}
		outputType = fmt.Sprintf("{ %s, %s }", width, width)
		constraints, arguments = "=&{ax},=&{dx},0,1", fmt.Sprintf("%s %s, %s %s", width, accumulator, width, high)
		operandIndex = 4
	}
	assembly, memoryClobber := "", ""
	if form.source.Kind == OpReg || form.source.Kind == OpFP {
		value, err := c.implicitDivideRegisterValue(form.source, width)
		if err != nil {
			return err
		}
		constraint := "r"
		if form.spec.bits == 8 {
			constraint = "q"
		}
		constraints += "," + constraint
		arguments += fmt.Sprintf(", %s %s", width, value)
		modifier := map[int]string{8: "b", 16: "w", 32: "k", 64: "q"}[form.spec.bits]
		assembly = fmt.Sprintf("%s ${%d:%s}", name, operandIndex, modifier)
	} else {
		pointer, pointerType, _, err := c.packedVectorMemoryPointer(form.source)
		if err != nil {
			return err
		}
		segment := ""
		if pointerType == "ptr addrspace(256)" {
			segment = "%gs:"
		} else if pointerType == "ptr addrspace(257)" {
			segment = "%fs:"
		}
		constraints += ",r"
		arguments += fmt.Sprintf(", %s %s", pointerType, pointer)
		assembly, memoryClobber = fmt.Sprintf("%s %s($%d)", name, segment, operandIndex), ",~{memory}"
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s)\n", result, outputType, assembly,
		constraints+",~{flags}"+memoryClobber, arguments)
	if form.spec.bits == 8 {
		return c.storeRegSized(AX, I16, "%"+result)
	}
	for index, register := range []Reg{AX, DX} {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, %d\n", value, outputType, result, index)
		if err := c.storeRegSized(register, width, "%"+value); err != nil {
			return err
		}
	}
	return nil
}

// Logical FP is a collection of separately owned scalar fields, not native
// contiguous stack backing. Gather its exact initialized bits into the same
// register-source opcode used above. The opcode, rather than LLVM arithmetic,
// still owns zero-divisor and quotient-overflow #DE, including dead results.
func (c *amd64Ctx) implicitDivideRegisterValue(source Operand, width LLVMType) (string, error) {
	if source.Kind != OpFP {
		return c.evalIntSized(source, width)
	}
	value, handled, err := c.loadIntegerFPBytesMode(source.FPOffset, width, true)
	if err != nil {
		return "", err
	}
	if !handled {
		return "", fmt.Errorf("%w: division divisor lacks exact owned logical FP bytes", ErrProbeNeedsContext)
	}
	return value, nil
}

// This descriptor is deliberately not in x86TypedInstructionByteEffect.
// Only the paired native lowerer supplies a numerical continuation. The two
// post-transfer footprint consumers may still revoke exactly the GP outputs.
func x86ImplicitDivideWrites(form x86ImplicitDivideForm) []x86TypedByteOperand {
	if form.spec.bits == 8 {
		return []x86TypedByteOperand{{operand: Operand{Kind: OpReg, Reg: AX}, width: 2, write: true}}
	}
	width := int64(form.spec.bits / 8)
	return []x86TypedByteOperand{
		{operand: Operand{Kind: OpReg, Reg: AX}, width: width, write: true},
		{operand: Operand{Kind: OpReg, Reg: DX}, width: width, write: true},
	}
}

func x86LoweredImplicitDivideStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, known, err := x86ImplicitDivideProperties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil ||
		form.source.Kind == OpReg && x86LogicalSourceFrameRegister(form.source.Reg, arch) {
		return false, true
	}
	if form.source.Kind != OpReg && form.source.Kind != OpFP && !x86RegisterAddressedNativeMemoryOperand(form.source, arch) {
		return false, true
	}
	width, accumulatorWidth := int64(form.spec.bits/8), int64(form.spec.bits/8)
	if form.spec.bits == 8 {
		accumulatorWidth = 2
	}
	if !x86ResultReadWithNativeContinuation(ins, form.source, width, state, owned, arch, true) ||
		!x86ResultRead(Operand{Kind: OpReg, Reg: AX}, accumulatorWidth, state, owned, arch) ||
		form.spec.bits != 8 && !x86ResultRead(Operand{Kind: OpReg, Reg: DX}, width, state, owned, arch) {
		return false, true
	}
	for _, output := range x86ImplicitDivideWrites(form) {
		if !x86ResultStore(output.operand, output.width, state, owned, 0, arch) {
			return false, true
		}
		index, mask, _ := x86ResultGP(output.operand.Reg, output.width, arch)
		state.canonicalGP[index] &^= mask
		if output.width == 4 && arch == "amd64" {
			state.canonicalGP[index] |= 0xf0
		}
		state.callerAddressGP[index] = false
	}
	state.flags = 0 // All six status flags are architecturally undefined; DF/ID stay unchanged.
	return true, true
}
