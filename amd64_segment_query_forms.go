package plan9asm

import (
	"fmt"
	"strings"
)

// The complete Go yml_rl/ydivl selector-query family shares one typed shape.
// Destination width does not enlarge the selector's two-byte source tuple.
func x86SegmentQueryProperties(op Op, ins Instr, arch string) (amd64SegmentQueryForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64SegmentQuerySpecs[Op(name)]
	form := amd64SegmentQueryForm{spec: spec}
	if !known {
		return form, false, nil
	}
	if arch == "" {
		arch = "amd64"
	}
	fail := func() (amd64SegmentQueryForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside complete Go selector-query grammar: %q", arch, op, ins.Raw)
	}
	want := 2
	if spec.bits == 0 {
		want = 1
	}
	if arch != "amd64" && arch != "386" || arch == "386" && spec.bits == 64 || dotted ||
		len(ins.Args) != want || ins.Op != "" && !strings.EqualFold(string(ins.Op), name) {
		return fail()
	}
	form.selector = ins.Args[0]
	if form.selector.Kind == OpReg {
		if !isX86YrlRegisterForArch(form.selector.Reg, arch) {
			return fail()
		}
	} else if !x86PackedShiftMemoryValid(form.selector, arch) || x86NamedMultiplyMemoryError(form.selector, arch) != nil {
		return fail()
	}
	if want == 2 {
		destination := ins.Args[1]
		if destination.Kind != OpReg || !isX86YrlRegisterForArch(destination.Reg, arch) {
			return fail()
		}
		form.destination = destination.Reg
	}
	return form, true, nil
}

func x86TypedSegmentQueryByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86SegmentQueryProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	effect := x86TypedByteEffect{requiresResultProof: true, flagsDefined: x86ByteFlagZF,
		operands: []x86TypedByteOperand{{index: 0, operand: form.selector, width: 2, read: true}}}
	if form.spec.bits != 0 {
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: 1, operand: ins.Args[1], width: int64(form.spec.bits / 8), read: true, write: true,
		})
	}
	return effect, true, nil
}
