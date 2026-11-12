package plan9asm

import (
	"fmt"
	"strings"
)

type x86AHFlagsSpec struct {
	toAH bool
}

// The complete ynone/Px family in both Go x86 modes. AH is an implicit byte
// operand; OF, DF and all other FLAGS are outside this five-bit transfer.
var x86AHFlagsSpecs = map[Op]x86AHFlagsSpec{
	"LAHF": {toAH: true}, "SAHF": {},
}

const x86AHFlagsMask = x86ByteFlagCF | x86ByteFlagPF | x86ByteFlagAF | x86ByteFlagZF | x86ByteFlagSF

func x86AHFlagsProperties(op Op, ins Instr, arch string) (x86AHFlagsSpec, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86AHFlagsSpecs[Op(name)]
	if !known {
		return spec, false, nil
	}
	if len(ins.Args) != 0 {
		return spec, true, fmt.Errorf("%s %s takes no operands: %q", arch, op, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || dotted ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return spec, true, fmt.Errorf("%s %s outside Go AH/FLAGS ynone grammar: %q", arch, op, ins.Raw)
	}
	return spec, true, nil
}

func x86TypedAHFlagsEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	spec, known, err := x86AHFlagsProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	effect := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: -1, operand: Operand{Kind: OpReg, Reg: AH}, width: 1, read: !spec.toAH, write: spec.toAH},
	}}
	if spec.toAH {
		effect.flagsRead = x86AHFlagsMask
	} else {
		effect.flagsDefined, effect.flagsKilled = x86AHFlagsMask, x86AHFlagsMask
	}
	return effect, true, nil
}
