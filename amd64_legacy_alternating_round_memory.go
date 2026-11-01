package plan9asm

import (
	"fmt"
	"strings"
)

// A paired legacy whole opcode supplies numerical bytes only on continuation.
// It grants no pointee extent, stack backing, source or raw-entry permission.
func x86LegacyAlternatingRoundMemorySource(ins Instr, source Operand, arch string) bool {
	return x86ResultNamedPredicateInstruction(ins) &&
		(source.Kind == OpMem || source.Kind == OpSym) && x86OrdinaryNativeMemoryOperand(source, arch)
}

// Both families consume their already normalized form. A ROUND immediate
// distinguishes its unary packed result from ADDSUB's old-destination input;
// scalar ROUND reads only copied upper bytes, not its overwritten low lane.
func (c *amd64Ctx) emitLegacyAlternatingRoundMemory(ins Instr, form x86FloatBinaryForm, immediate *uint8) error {
	source := ins.Args[form.first]
	if !form.legacy || form.byteWidth != 16 || !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) ||
		!x86LegacyAlternatingRoundMemorySource(ins, source, c.goarch) {
		return fmt.Errorf("%w: %s needs its original ordinary legacy memory source", ErrProbeNeedsContext, ins.Op)
	}
	typ := amd64FMA3LLVMType(128/form.bits, form.bits)
	input, inputType, constraint, template, err := c.nativeFloatingCompareSource(source,
		x86FloatCompareForm{x86FloatBinaryForm: form}, typ, "")
	if err != nil {
		return err
	}
	args, constraints := inputType+" "+input, "=x,"+constraint
	if immediate == nil || form.scalar {
		old, err := c.loadX(ins.Args[form.destination].Reg)
		if err != nil {
			return err
		}
		carrier := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to %s\n", carrier, old, typ)
		args, constraints = typ+" %"+carrier+", "+args, "=x,0,"+constraint
		template = strings.ReplaceAll(template, "$1", "$2")
	}
	assembly := strings.ToLower(string(ins.Op)) + " "
	if immediate != nil {
		assembly += fmt.Sprintf("$$%d, ", *immediate)
	}
	assembly += template + ", $0"
	result, bytes := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s)\n", result, typ, assembly, constraints+",~{memory},~{fpsr}", args)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bytes, typ, result)
	return c.storeX(ins.Args[form.destination].Reg, "%"+bytes)
}
