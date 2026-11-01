package plan9asm

import (
	"fmt"
	"strings"
)

type x86CarryControlSpec struct {
	set, complement bool
}

// asm6.go's complete CLC/STC/CMC family is ynone/Px in both x86 modes.
// Only CF changes; none of the other arithmetic flags or DF is defined here.
var x86CarryControlSpecs = map[Op]x86CarryControlSpec{
	"CLC": {}, "STC": {set: true}, "CMC": {complement: true},
}

func x86CarryControlProperties(op Op, ins Instr, arch string) (x86CarryControlSpec, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86CarryControlSpecs[Op(name)]
	if !known {
		return spec, false, nil
	}
	if arch != "386" && arch != "amd64" || dotted || len(ins.Args) != 0 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return spec, true, fmt.Errorf("%s %s outside Go carry-control ynone grammar: %q", arch, op, ins.Raw)
	}
	return spec, true, nil
}

func x86TypedCarryControlByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	spec, known, err := x86CarryControlProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	effect := x86TypedByteEffect{flagsKilled: x86ByteFlagCF, flagsDefined: x86ByteFlagCF}
	if spec.complement {
		effect.flagsRead = x86ByteFlagCF
	}
	return effect, true, nil
}
