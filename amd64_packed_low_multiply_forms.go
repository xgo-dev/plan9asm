package plan9asm

import (
	"fmt"
	"strings"
)

type x86PackedLowMultiplySpec struct {
	x86PackedBinarySpec
	laneBits int
}

// PMULLW/VPMULLW already use the word family's typed grammar, including
// its distinct MMX source bank. D/Q share that binary grammar, not its bank.
var x86PackedLowMultiplySpecs = map[Op]x86PackedLowMultiplySpec{
	"PMULLD":  {x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, 32},
	"VPMULLD": {x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, broadcastBytes: 4, zeroing: true}, 32},
	"VPMULLQ": {x86PackedBinarySpec{encoding: x86PackedLogicalEVEX, broadcastBytes: 8, zeroing: true}, 64},
}

type x86PackedLowMultiplyForm struct {
	x86PackedBinaryForm
	spec x86PackedLowMultiplySpec
}

func x86PackedLowMultiplyProperties(op Op, ins Instr, arch string) (x86PackedLowMultiplyForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86PackedLowMultiplySpecs[Op(base)]
	if !known {
		return x86PackedLowMultiplyForm{}, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return x86PackedLowMultiplyForm{}, true, fmt.Errorf("packed low multiply dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	local := ins
	local.Op = op
	grammarArch := arch
	if arch == "386" && local.x86Encoded && spec.encoding != x86PackedLogicalLegacyFP {
		// Only the decoder can supply this physical identity. Go's named
		// mode32 frontend has a separate three-operand limit.
		grammarArch = "amd64"
	}
	binary, err := x86PackedBinaryProperties(local, grammarArch, spec.x86PackedBinarySpec)
	if err == nil && grammarArch != arch && binary.memory >= 0 && !x86PackedShiftMemoryValid(local.Args[binary.memory], arch) {
		err = fmt.Errorf("386 %s physical source has an unbound address", op)
	}
	if err == nil {
		err = x86Mode32VectorRegisterContext(local, arch)
	}
	if err == nil && binary.memory >= 0 && (ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride) {
		err = fmt.Errorf("%w: packed low multiply has no bound address-size override", ErrProbeNeedsContext)
	}
	return x86PackedLowMultiplyForm{binary, spec}, true, err
}
