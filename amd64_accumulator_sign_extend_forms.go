package plan9asm

import (
	"fmt"
	"strings"
)

type x86AccumulatorSignExtendSpec struct {
	sourceBytes, destinationBytes int64
	destination                   Reg
}

// Complete x86 ynone / 98,99 family. The prefix selects the operand width; the
// destination distinguishes sign extension from the sign-only high half.
var x86AccumulatorSignExtendSpecs = map[Op]x86AccumulatorSignExtendSpec{
	"CBW":  {1, 2, AX},
	"CWDE": {2, 4, AX},
	"CDQE": {4, 8, AX},
	"CWD":  {2, 2, DX},
	"CDQ":  {4, 4, DX},
	"CQO":  {8, 8, DX},
}

func x86AccumulatorSignExtendProperties(op Op, ins Instr, arch string) (x86AccumulatorSignExtendSpec, bool, error) {
	name := strings.ToUpper(string(op))
	base, _, dotted := strings.Cut(name, ".")
	spec, known := x86AccumulatorSignExtendSpecs[Op(base)]
	if !known {
		return spec, false, nil
	}
	if arch == "" {
		arch = "amd64"
	}
	if arch != "amd64" && arch != "386" || arch == "386" && spec.destinationBytes == 8 ||
		dotted || len(ins.Args) != 0 || ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return spec, true, fmt.Errorf("%s %s requires its original zero-operand ynone row: %q", arch, op, ins.Raw)
	}
	return spec, true, nil
}

func x86TypedAccumulatorSignExtendByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	if !x86ResultNamedPredicateInstruction(ins) {
		return x86TypedByteEffect{}, false, nil
	}
	spec, known, err := x86AccumulatorSignExtendProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	return x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: -1, operand: Operand{Kind: OpReg, Reg: AX}, width: spec.sourceBytes, read: true},
		{index: -1, operand: Operand{Kind: OpReg, Reg: spec.destination}, width: spec.destinationBytes, write: true},
	}}, true, nil
}
