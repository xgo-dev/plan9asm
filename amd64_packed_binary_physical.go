package plan9asm

import (
	"fmt"
	"strings"
)

// These families share physical operand normalization, not their numerical
// effects or source permissions. Only the existing MMX adapter copies operands;
// the binary grammar reads the original slice without changing it. The boolean
// preserves the families' zero-form return before binary parsing has begun.
func x86PackedBinaryPhysicalSource(op Op, ins Instr, arch string, spec x86PackedBinarySpec,
	family string) (x86PackedBinaryForm, Operand, bool, error) {
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return x86PackedBinaryForm{}, Operand{}, false,
			fmt.Errorf("%s dispatch/source opcode mismatch: %s/%s", family, op, ins.Op)
	}
	local := ins
	local.Op = op
	if spec.encoding == x86PackedLogicalLegacyInteger {
		var err error
		local, err = x86LegacyMMXReadInstruction(local, arch)
		if err != nil {
			return x86PackedBinaryForm{}, Operand{}, false, err
		}
	}
	grammarArch := arch
	if arch == "386" && local.x86Encoded && spec.encoding == x86PackedLogicalVEXOrEVEX {
		grammarArch = "amd64" // Only the complete physical decoder sets this marker.
	}
	binary, err := x86PackedBinaryProperties(local, grammarArch, spec)
	var source Operand
	if err == nil {
		source = local.Args[binary.first]
		if grammarArch != arch && binary.memory >= 0 && !x86PackedShiftMemoryValid(source, arch) {
			err = fmt.Errorf("386 %s physical source has an unbound address", op)
		}
		if err == nil {
			err = x86Mode32VectorRegisterContext(local, arch)
		}
		if err == nil && binary.memory >= 0 && (ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride) {
			err = fmt.Errorf("%w: %s has no bound address-size override", ErrProbeNeedsContext, family)
		}
	}
	return binary, source, true, err
}
