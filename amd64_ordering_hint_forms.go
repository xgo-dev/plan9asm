package plan9asm

import (
	"fmt"
	"strings"
)

type x86OrderingHintSpec struct {
	native string
}

// The complete Go ynone axis has no explicit or implicit data operands.
// Hardware ordering/hint execution is not a source-memory permission.
var x86OrderingHintSpecs = map[Op]x86OrderingHintSpec{
	"LFENCE": {native: "lfence"},
	"MFENCE": {native: "mfence"},
	"SFENCE": {native: "sfence"},
	"PAUSE":  {native: "pause"},
}

func x86OrderingHintProperties(op Op, ins Instr, arch string) (x86OrderingHintSpec, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86OrderingHintSpecs[Op(name)]
	if !known {
		return x86OrderingHintSpec{}, false, nil
	}
	if dotted || arch != "386" && arch != "amd64" || len(ins.Args) != 0 ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return spec, true, fmt.Errorf("%s %s requires its exact zero-operand Go ordering/hint form: %q", arch, op, ins.Raw)
	}
	return spec, true, nil
}

func (c *amd64Ctx) lowerX86OrderingHint(op Op, ins Instr) (bool, bool, error) {
	spec, known, err := x86OrderingHintProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	// Conservative compiler memory scheduling is separate from architectural
	// semantics: these instructions have no source data or arithmetic outputs.
	// A litmus sample is not a proof of the hardware memory model.
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", spec.native, "~{memory}")
	return true, false, nil
}
