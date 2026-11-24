package plan9asm

import (
	"fmt"
	"strings"
)

type x86IFMAForm struct {
	x86PackedBinaryForm
	spec amd64IFMASpec
}

func x86IFMAProperties(op Op, ins Instr, arch string) (x86IFMAForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64IFMASpecs[Op(base)]
	if !known {
		return x86IFMAForm{}, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return x86IFMAForm{}, true, fmt.Errorf("IFMA dispatch/source opcode mismatch")
	}
	local := ins
	local.Op = op
	physical := ins.x86Encoded || ins.x86SourceRaw != nil
	form, err := x86PackedBinaryOperandGrammar(local, arch, spec.x86PackedBinarySpec, physical)
	if err == nil {
		err = x86Mode32VectorRegisterContext(local, arch)
	}
	if err == nil && form.memory >= 0 {
		source := ins.Args[form.memory]
		if source.Kind == OpMem {
			if !x86ConditionalMoveOffsetKnown(source.Mem) || source.Mem.IndexExt != "" ||
				source.Mem.Segment != "" && source.Mem.Segment != FS && source.Mem.Segment != GS {
				err = fmt.Errorf("IFMA source has an unresolved or foreign address")
			} else {
				err = x86SymbolIndexedMemoryError(source.Mem, arch)
			}
		}
		if source.Kind == OpSym {
			if address, parseErr := parseInt(strings.TrimSpace(source.Sym)); parseErr == nil &&
				address != int64(int32(address)) && !(arch == "386" && address == int64(uint32(address))) {
				err = fmt.Errorf("IFMA absolute source exceeds Go's disp32 extent")
			}
		}
		if err == nil && (ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride) {
			err = fmt.Errorf("%w: IFMA needs its original default address mode", ErrProbeNeedsContext)
		}
	}
	return x86IFMAForm{form, spec}, true, err
}

func x86TypedIFMAByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86IFMAProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	var buf [5]x86TypedByteOperand
	effect, n := x86TypedIFMAEffectForFormInto(&buf, ins, form)
	effect.operands = append([]x86TypedByteOperand(nil), buf[:n]...)
	return effect, true, nil
}

// Each qword lane reads bits 51:0 (low seven bytes) of both multiplicands and
// all eight bytes of the old accumulator, even under zero masking.
func x86TypedIFMAEffectForFormInto(dst *[5]x86TypedByteOperand, ins Instr, form x86IFMAForm) (x86TypedByteEffect, int) {
	effect, n := x86TypedFixedVectorInputsInto(dst, ins, form.x86PackedBinaryForm, true)
	effect.vectorLaneBytes = 8
	dst[0].laneReadMask = 0x7f
	dst[0].broadcast = form.broadcast
	dst[1].laneReadMask = 0xff
	dst[2].laneReadMask = 0x7f
	return effect, n
}
