package plan9asm

import (
	"fmt"
	"strings"
)

type x86UndefinedTrapSpec struct {
	native  string
	opBytes []byte // Complete canonical Go ynone/Px row.
}

// UNDEF is Go's canonical spelling; UD2 is the physical decoder/internal
// spelling of the same opcode. Neither spelling is a returning debug trap.
var x86UndefinedTrapSpecs = map[Op]x86UndefinedTrapSpec{
	"UNDEF": {native: "ud2", opBytes: []byte{0x0f, 0x0b}},
}

func x86UndefinedTrapProperties(op Op, ins Instr, arch string) (x86UndefinedTrapSpec, bool, error) {
	name, _, suffix := strings.Cut(strings.ToUpper(string(op)), ".")
	canonical := name
	if name == "UD2" {
		canonical = "UNDEF"
	}
	spec, known := x86UndefinedTrapSpecs[Op(canonical)]
	if !known {
		local := ins
		if local.Op == "" {
			local.Op = op
		}
		if strings.EqualFold(string(local.Op), string(op)) {
			if form, transfer, err := x86InsertExtractProperties(local, arch); transfer && err == nil && form.undefinedOpcode() {
				return x86UndefinedTrapSpec{native: "ud2"}, true, nil
			}
			if form, move, err := amd64PackedVectorMoveProperties(local, arch); move && err == nil && form.undefinedOpcode() {
				return x86UndefinedTrapSpec{native: "ud2"}, true, nil
			}
			if form, compact, err := x86PackedCompactProperties(op, local, arch); compact && err == nil && form.undefinedOpcode() {
				return x86UndefinedTrapSpec{native: "ud2"}, true, nil
			}
		}
		if form, narrow, err := x86SingleSourceNarrowProperties(op, ins, arch); narrow && err == nil && form.undefinedOpcode() {
			return x86UndefinedTrapSpec{native: "ud2"}, true, nil
		}
		if form, half, err := x86NamedHalfProperties(op, ins, arch); half && err == nil && form.undefinedOpcode() {
			return x86UndefinedTrapSpec{native: "ud2"}, true, nil
		}
		if form, nonTemporal, err := x86MOVNTIProperties(op, ins, arch); nonTemporal && err == nil && form.trap {
			return x86UndefinedTrapSpec{native: "ud2"}, true, nil
		}
		if form, nonTemporal, err := x86NonTemporalVectorProperties(op, ins, arch); nonTemporal && err == nil && form.trap {
			// Go's Yml register row encodes a reserved ModRM form. Preserve
			// its terminal #UD, not fictitious source/GP or memory effects.
			return x86UndefinedTrapSpec{native: "ud2"}, true, nil
		}
		return x86UndefinedTrapSpec{}, false, nil
	}
	if suffix || len(ins.Args) != 0 || arch != "386" && arch != "amd64" ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return spec, true, fmt.Errorf("%s %s requires an exact zero-operand undefined-instruction form: %q", arch, op, ins.Raw)
	}
	return spec, true, nil
}

func (c *amd64Ctx) lowerX86UndefinedTrap(op Op, ins Instr) (bool, bool, error) {
	spec, known, err := x86UndefinedTrapProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	// Use the exact architectural fault instruction, not merely unreachable
	// or a target-dependent generic trap that may select a different signal.
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q()\n", spec.native, "~{memory}")
	c.b.WriteString("  unreachable\n")
	return true, true, nil
}
