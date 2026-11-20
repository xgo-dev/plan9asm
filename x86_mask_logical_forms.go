package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
)

func (spec amd64MaskLogicalSpec) writesFlags() bool {
	return spec.kind == amd64MaskTest || spec.kind == amd64MaskOrTest
}

func (spec amd64MaskLogicalSpec) argumentCount() int {
	if spec.kind == amd64MaskNot || spec.writesFlags() {
		return 2
	}
	return 3
}

// The complete Go family has only K,K and K,K,K operand shapes. Width,
// numerical dependencies and FLAGS writes remain independent of that syntax.
func x86MaskLogicalProperties(op Op, ins Instr, arch string) (amd64MaskLogicalSpec, bool, error) {
	name, _, suffix := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64MaskLogicalSpecs[Op(name)]
	if !known {
		return amd64MaskLogicalSpec{}, false, nil
	}
	valid := !suffix && (arch == "amd64" || arch == "386") &&
		(ins.Op == "" || strings.EqualFold(string(ins.Op), name)) && len(ins.Args) == spec.argumentCount()
	for _, operand := range ins.Args {
		valid = valid && amd64IsKOperand(operand)
	}
	if !valid {
		return spec, true, fmt.Errorf("%s %s requires its exact Go K-register form: %q", arch, op, ins.Raw)
	}
	return spec, true, nil
}

func x86MaskLogicalResultStep(ins Instr, state *x86ResultState, arch string) (bool, bool) {
	spec, known, err := x86MaskLogicalProperties(ins.Op, ins, arch)
	if !known || err != nil || !x86MaskLogicalPreservesStorage(ins) {
		return false, known
	}
	inputs := 2
	if spec.kind == amd64MaskNot {
		inputs = 1
	}
	// Equal-source XOR/XNOR/ANDN produces a width-bounded constant without
	// observing the incoming bits. Do not extend that rule to AND/OR/TEST.
	constant := (spec.kind == amd64MaskXOR || spec.kind == amd64MaskXNOR || spec.kind == amd64MaskAndNot) &&
		ins.Args[0].Reg == ins.Args[1].Reg
	if !constant {
		for _, operand := range ins.Args[:inputs] {
			index, _ := amd64ParseKReg(operand.Reg)
			if !state.masks[index] {
				return false, true
			}
		}
	}
	if spec.writesFlags() {
		state.flags = x86ByteFlagsAll
	} else {
		destination, _ := amd64ParseKReg(ins.Args[len(ins.Args)-1].Reg)
		state.masks[destination] = true
	}
	return true, true // No GP, vector, DF, memory or unrelated mask writes.
}

// These K-only forms are identical in both x86 modes and never touch GP,
// private storage or DF/ID. Their separate transfer still checks every mask
// input and accounts for FLAGS writes. Raw source must retain the decoder's
// exact opcode/operands; this grants no native entry, frame or memory role.
func x86MaskLogicalPreservesStorage(ins Instr) bool {
	if _, known, err := x86MaskLogicalProperties(ins.Op, ins, "amd64"); !known || err != nil {
		return false
	}
	if ins.x86Encoded || ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 ||
		ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return false
	}
	origin := ins.x86SourceRaw
	return origin == nil || origin.op == ins.Op && reflect.DeepEqual(origin.args, ins.Args)
}
