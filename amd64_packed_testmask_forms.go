package plan9asm

import (
	"fmt"
	"strings"
)

type x86PackedTestMaskForm struct {
	x86PackedBinaryForm
	spec   amd64PackedTestMaskSpec
	source Operand
}

// Source vectors, optional K input and K result are disjoint roles. The
// shared mask-result grammar grants no numerical bytes or memory backing.
func x86PackedTestMaskProperties(op Op, ins Instr, arch string) (x86PackedTestMaskForm, bool, error) {
	base, suffix, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64PackedTestMaskSpecs[base]
	f := x86PackedTestMaskForm{spec: spec}
	if !known {
		return f, false, nil
	}
	fail := func() (x86PackedTestMaskForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside packed integer test-to-mask grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail()
	}
	local := ins
	local.Op = op
	roles, valid := x86PackedMaskCompareProperties(local, arch, 0, spec.laneBits, dotted, suffix)
	if !valid {
		return fail()
	}
	f.x86PackedBinaryForm, f.source = roles, ins.Args[roles.first]
	for _, index := range []int{roles.first, roles.second} {
		arg := ins.Args[index]
		if arg.Kind == OpReg && !amd64GoPackedVectorMoveRegister(arg, roles.byteWidth, arch) {
			return fail()
		}
	}
	if roles.memory >= 0 && (ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride) {
		return f, true, fmt.Errorf("%w: test-to-mask has no bound address-size override", ErrProbeNeedsContext)
	}
	return f, true, nil
}

func x86TypedPackedTestMaskByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	f, known, err := x86PackedTestMaskProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	effect := x86PackedMaskResultEffect(ins, f.x86PackedBinaryForm, f.source, true)
	effect.requiresResultProof = true
	return effect, true, nil
}
