package plan9asm

import (
	"fmt"
	"strings"
)

type x86CPUQuerySpec struct {
	native  string
	inputs  []Reg
	outputs []Reg
	opBytes []byte // Complete Go ynone/Pm opcode row, after its 0x0f prefix.
}

var x86CPUQuerySpecs = map[Op]x86CPUQuerySpec{
	OpCPUID:  {"cpuid", []Reg{AX, CX}, []Reg{AX, BX, CX, DX}, []byte{0xa2}},
	OpXGETBV: {"xgetbv", []Reg{CX}, []Reg{AX, DX}, []byte{0x01, 0xd0}},
}

func x86CPUQueryProperties(op Op, ins Instr, arch string) (x86CPUQuerySpec, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86CPUQuerySpecs[Op(name)]
	if !known {
		return x86CPUQuerySpec{}, false, nil
	}
	if len(ins.Args) != 0 || dotted || arch != "amd64" && arch != "386" ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return spec, true, fmt.Errorf("%s %s requires the exact zero-operand Go CPU-query form: %q", arch, op, ins.Raw)
	}
	return spec, true, nil
}

// The native emitter consumes these same low dword inputs before overwriting
// its zero-extended outputs. Continued execution supplies numerical bytes,
// not a pointer, caller region, raw entry or promise that XGETBV cannot fault.
func x86TypedCPUQueryByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	spec, known, err := x86CPUQueryProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	if !x86RegisterQueryPreservesSourceState(ins) {
		return x86TypedByteEffect{}, true, fmt.Errorf("%w: CPU query original/normalized source identity differs", ErrProbeNeedsContext)
	}
	effect := x86TypedByteEffect{requiresResultProof: true}
	for _, register := range spec.inputs {
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: -1, operand: Operand{Kind: OpReg, Reg: register}, width: 4, read: true,
		})
	}
	for _, register := range spec.outputs {
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: -1, operand: Operand{Kind: OpReg, Reg: register}, width: 4, write: true,
		})
	}
	return effect, true, nil
}

func x86TypedRegisterQueryByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	if effect, known, err := x86TypedHardwareRandomByteEffect(op, ins, arch); known {
		return effect, known, err
	}
	if effect, known, err := x86TypedCPUQueryByteEffect(op, ins, arch); known {
		return effect, known, err
	}
	if effect, known, err := x86TypedTimestampByteEffect(op, ins, arch); known {
		return effect, known, err
	}
	return x86TypedRTMStatusByteEffect(op, ins, arch)
}

// Register queries keep DF and the private numerical stack. Their separate
// descriptors retain all GP and FLAGS writes: an RTM status query, unlike a CPU
// query or timestamp, replaces FLAGS. Random producers also replace their one
// destination and FLAGS. Other opcodes cannot inherit this exact source boundary.
func x86RegisterQueryPreservesSourceState(ins Instr) bool {
	if x86HardwareRandomPreservesSourceState(ins) {
		return true
	}
	name := Op(strings.ToUpper(string(ins.Op)))
	_, cpu := x86CPUQuerySpecs[name]
	_, timestamp := x86TimestampSpecs[name]
	rtm, transaction := amd64RTMSpecs[name]
	status := transaction && rtm.kind == amd64RTMTest
	if !cpu && !timestamp && !status || len(ins.Args) != 0 || ins.x86Encoded || ins.x86RawNearReturn != nil ||
		ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return false
	}
	origin := ins.x86SourceRaw
	return origin == nil || len(origin.args) == 0 && strings.EqualFold(string(origin.op), string(ins.Op))
}

func (spec x86CPUQuerySpec) resultType() LLVMType {
	return LLVMType("{ " + strings.TrimSuffix(strings.Repeat("i32, ", len(spec.outputs)), ", ") + " }")
}

func (spec x86CPUQuerySpec) constraints() string {
	var fields []string
	for _, register := range spec.outputs {
		fields = append(fields, "={"+strings.ToLower(string(register))+"}")
	}
	for _, register := range spec.inputs {
		fields = append(fields, "{"+strings.ToLower(string(register))+"}")
	}
	// Preserve source ordering at the compiler boundary. These conservative
	// clobbers do not assert that XGETBV serializes hardware or changes flags.
	fields = append(fields, "~{dirflag}", "~{fpsr}", "~{flags}", "~{memory}")
	return strings.Join(fields, ",")
}

func emitX86CPUQuery(b *strings.Builder, spec x86CPUQuerySpec, inputs []string, newTmp func() string) []string {
	arguments := make([]string, len(inputs))
	for index, input := range inputs {
		arguments[index] = "i32 " + input
	}
	call := newTmp()
	fmt.Fprintf(b, "  %%%s = call %s asm sideeffect %q, %q(%s)\n",
		call, spec.resultType(), spec.native, spec.constraints(), strings.Join(arguments, ", "))
	outputs := make([]string, len(spec.outputs))
	for index := range outputs {
		part := newTmp()
		fmt.Fprintf(b, "  %%%s = extractvalue %s %%%s, %d\n", part, spec.resultType(), call, index)
		outputs[index] = "%" + part
	}
	return outputs
}

func (c *amd64Ctx) lowerX86CPUQuery(op Op, ins Instr) (bool, bool, error) {
	spec, known, err := x86CPUQueryProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	inputs := make([]string, len(spec.inputs))
	for index, register := range spec.inputs {
		value, err := c.loadReg(register)
		if err != nil {
			return true, false, err
		}
		inputs[index] = c.truncI64(value, I32)
	}
	outputs := emitX86CPUQuery(c.b, spec, inputs, c.newTmp)
	for index, register := range spec.outputs {
		if err := c.storeRegSized(register, I32, outputs[index]); err != nil {
			return true, false, err
		}
	}
	return true, false, nil
}
