package plan9asm

import (
	"fmt"
	"strings"
)

type x86DirectionControlSpec struct {
	backward bool
}

// These are Go's complete two ynone/Px rows, in both x86 source modes.
// DF is separate from the six arithmetic status flags and from pointer facts.
var x86DirectionControlSpecs = map[Op]x86DirectionControlSpec{
	"CLD": {},
	"STD": {backward: true},
}

func x86DirectionControlProperties(op Op, ins Instr, arch string) (x86DirectionControlSpec, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86DirectionControlSpecs[Op(name)]
	if !known {
		return spec, false, nil
	}
	if len(ins.Args) != 0 {
		return spec, true, fmt.Errorf("%s takes no operands; %s direction-control ynone grammar: %q", name, arch, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || dotted || len(ins.Args) != 0 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return spec, true, fmt.Errorf("%s %s outside Go direction-control ynone grammar: %q", arch, op, ins.Raw)
	}
	return spec, true, nil
}

func (c *amd64Ctx) lowerDirectionControl(ins Instr) (bool, error) {
	spec, known, err := x86DirectionControlProperties(ins.Op, ins, c.goarch)
	if !known || err != nil {
		return known, err
	}
	if c.directionSlot != "" {
		fmt.Fprintf(c.b, "  store i1 %t, ptr %s\n", spec.backward, c.directionSlot)
	}
	// Every target consumes virtual DF in the exact string helpers. Only a
	// matching x86 backend also owns the physical direction-flag side effect;
	// embedding CLD/STD in an ARM/WASM module is not portable emulation.
	if x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) {
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, \"~{dirflag}\"()\n", strings.ToLower(string(ins.Op)))
	}
	return true, nil
}
