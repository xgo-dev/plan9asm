package plan9asm

import (
	"fmt"
	"strings"
)

// Go's ymshufb has only X/m128, X, not the ISA's separate MMX form.
// Both vector encodings share the binary grammar, with no broadcast or SAE.
var x86ByteShuffleSpecs = map[Op]x86PackedBinarySpec{
	"PSHUFB":  {encoding: x86PackedLogicalLegacyFP},
	"VPSHUFB": {encoding: x86PackedLogicalVEXOrEVEX, zeroing: true},
}

func x86ByteShuffleProperties(op Op, ins Instr, arch string) (x86PackedBinaryForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86ByteShuffleSpecs[Op(base)]
	if !known {
		return x86PackedBinaryForm{}, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return x86PackedBinaryForm{}, true, fmt.Errorf("byte shuffle dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	local := ins
	local.Op = op
	grammarArch := arch
	if arch == "386" && ins.x86Encoded && spec.encoding != x86PackedLogicalLegacyFP {
		// Physical EVEX masking does not inherit cmd/asm's named operand cap.
		grammarArch = "amd64"
	}
	form, err := x86PackedBinaryProperties(local, grammarArch, spec)
	if err == nil && grammarArch != arch && form.memory >= 0 && !x86PackedShiftMemoryValid(local.Args[form.memory], arch) {
		err = fmt.Errorf("386 byte shuffle physical source has an unbound address")
	}
	if err == nil {
		err = x86Mode32VectorRegisterContext(local, arch)
	}
	if err == nil && form.memory >= 0 && (ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride) {
		err = fmt.Errorf("%w: byte shuffle has no bound address-size override", ErrProbeNeedsContext)
	}
	return form, true, err
}

// A dynamic control byte may select any byte of its own 128-bit data lane.
// This is numerical definedness, never a memory, alignment or caller grant.
func x86ByteShuffleDefinedBytes(width int, control, data uint64) uint64 {
	var known uint64
	for start := 0; start < width; start += 16 {
		lane := uint64(0xffff) << uint(start)
		if data&lane == lane {
			known |= control & lane
		}
	}
	return known
}

func x86TypedByteShuffleEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86ByteShuffleProperties(op, ins, arch)
	if !known || err != nil || !form.legacy {
		return x86TypedByteEffect{}, known && (err != nil || form.legacy), err
	}
	return x86PackedBinaryDependencyEffect(ins, form, ins.Args[form.first]), true, nil
}
