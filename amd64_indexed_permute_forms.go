package plan9asm

import (
	"fmt"
	"strings"
)

// _yvblendmpd is the existing complete EVEX binary grammar. The mode adds
// old-destination dependencies, not another register/memory/suffix parser.
func x86IndexedPermuteProperties(op Op, ins Instr, arch string) (x86PackedBinaryForm, amd64IndexedPermuteSpec, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64IndexedPermuteSpecs[Op(base)]
	if !known {
		return x86PackedBinaryForm{}, spec, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return x86PackedBinaryForm{}, spec, true, fmt.Errorf("indexed permute dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	local, contextual := x86VectorValueMemoryInput(ins, arch)
	local.Op = op
	grammar := x86PackedBinarySpec{encoding: x86PackedLogicalEVEX, zeroing: true}
	if spec.broadcast {
		grammar.broadcastBytes = spec.laneBits / 8
	}
	form, err := x86PackedBinaryProperties(local, arch, grammar)
	if err == nil && contextual {
		err = x86VectorValueMemoryContext(ins)
	}
	return form, spec, true, err
}

func x86ResultIndexedPermuteStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	form, spec, known, err := x86IndexedPermuteProperties(ins.Op, ins, arch)
	if !known {
		return false, false
	}
	if err != nil {
		return false, true
	}
	return x86ResultFixedVectorInputs(ins, form, spec.mode != amd64IndexedPermuteSingle, state, owned, arch), true
}
