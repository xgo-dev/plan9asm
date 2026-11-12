package plan9asm

import (
	"fmt"
	"strings"
)

type x86ScalarBitScanSpec struct {
	bits    int
	reverse bool
}

// All six Go yml_rl rows. Zero input cannot independently initialize the
// destination: current Intel SDM preserves it, with a historical dword upper
// half exception. Only a whole native opcode retains that target's behavior.
var x86ScalarBitScanSpecs = map[Op]x86ScalarBitScanSpec{
	"BSFW": {16, false}, "BSFL": {32, false}, "BSFQ": {64, false},
	"BSRW": {16, true}, "BSRL": {32, true}, "BSRQ": {64, true},
}

func x86ScalarBitScanProperties(op Op, ins Instr, arch string) (x86ScalarBitScanSpec, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86ScalarBitScanSpecs[Op(name)]
	if !known {
		return spec, false, nil
	}
	// This is exactly the same complete Yml-to-Yrl operand grammar as the
	// registered count family. Reuse only its shape, never its defined value
	// or status flags, and preserve the original source instruction identity.
	shape := ins
	shape.Op = Op(fmt.Sprintf("POPCNT%s", name[len(name)-1:]))
	_, _, err := x86ScalarBitCountProperties(shape.Op, shape, arch)
	if dotted || ins.Op != "" && !strings.EqualFold(string(ins.Op), name) || err != nil {
		return spec, true, fmt.Errorf("%s %s outside Go scalar bit-scan grammar: %q", arch, op, ins.Raw)
	}
	return spec, true, nil
}
