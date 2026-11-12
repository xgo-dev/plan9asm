package plan9asm

import (
	"fmt"
	"strings"
)

type x86TimestampSpec struct {
	outputs amd64ImplicitRegisterSet
	opBytes []byte // Complete Go ynone/Pm row, including its literal terminator.
}

// Zero-operand syntax and implicit data flow are separate from native ISA
// availability. Executing the whole instruction retains TSC/AUX and faults;
// no software zero or host-clock substitute is an architectural timestamp.
var x86TimestampSpecs = map[Op]x86TimestampSpec{
	"RDTSC":  {amd64ImplicitAX | amd64ImplicitDX, []byte{0x31}},
	"RDTSCP": {amd64ImplicitAX | amd64ImplicitDX | amd64ImplicitCX, []byte{0x01, 0xf9, 0}},
}

func x86TimestampProperties(op Op, ins Instr, arch string) (x86TimestampSpec, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86TimestampSpecs[Op(name)]
	if !known {
		return x86TimestampSpec{}, false, nil
	}
	if len(ins.Args) != 0 {
		return spec, true, fmt.Errorf("%s takes no operands: %q", name, ins.Raw)
	}
	if dotted || arch != "amd64" && arch != "386" ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return spec, true, fmt.Errorf("%s %s requires the exact zero-operand Go timestamp form: %q", arch, op, ins.Raw)
	}
	return spec, true, nil
}

func x86TimestampRegisters(spec x86TimestampSpec) []Reg {
	registers := []Reg{AX, DX}
	if spec.outputs&amd64ImplicitCX != 0 {
		registers = append(registers, CX)
	}
	return registers
}

// These implicit dword writes share the original zero-operand grammar and
// output directory with the native emitter. They read no numerical input and
// preserve integer FLAGS/DF. Initialization alone grants no entry, memory or
// caller authority, nor a claim that the hardware instruction cannot fault.
func x86TypedTimestampByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	spec, known, err := x86TimestampProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	if !x86TimestampPreservesSourceState(ins) {
		return x86TypedByteEffect{}, true, fmt.Errorf("%w: timestamp original/normalized source identity differs", ErrProbeNeedsContext)
	}
	effect := x86TypedByteEffect{requiresResultProof: true}
	for _, register := range x86TimestampRegisters(spec) {
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: -1, operand: Operand{Kind: OpReg, Reg: register}, width: 4, write: true,
		})
	}
	return effect, true, nil
}

// Both x86 modes have the same exact zero-operand state footprint. This
// instruction-local observation authorizes neither a function's raw entry nor
// storage. Raw handoffs must retain the decoder's original opcode and operands.
func x86TimestampPreservesSourceState(ins Instr) bool {
	_, known := x86TimestampSpecs[Op(strings.ToUpper(string(ins.Op)))]
	return known && x86RegisterQueryPreservesSourceState(ins)
}

func (c *amd64Ctx) lowerX86Timestamp(op Op, ins Instr) (bool, bool, error) {
	spec, known, err := x86TimestampProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	registers := x86TimestampRegisters(spec)
	resultType := "{ i32, i32 }"
	constraints := "={ax},={dx}"
	if spec.outputs&amd64ImplicitCX != 0 {
		resultType = "{ i32, i32, i32 }"
		constraints += ",={cx}"
	}
	// Compiler clobbers are conservative scheduling constraints, not a claim
	// that RDTSC serializes the CPU or changes the source's arithmetic flags.
	constraints += ",~{dirflag},~{fpsr},~{flags},~{memory}"
	call := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q()\n",
		call, resultType, strings.ToLower(string(op)), constraints)
	for index, register := range registers {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, %d\n", value, resultType, call, index)
		if err := c.storeRegSized(register, I32, "%"+value); err != nil {
			return true, false, err
		}
	}
	return true, false, nil
}
