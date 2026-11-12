package plan9asm

import (
	"fmt"
	"strings"
)

type x86PackedExtendSpec struct {
	inputBits  int
	outputBits int
	vector     bool
	opcode     byte
}

type x86PackedZeroExtendSpec = x86PackedExtendSpec

// Legacy yxm_q4 and the two AVX tables have different physical source widths:
// ratio two uses _yvcvtdq2pd (Y/m256 to Z); the other ratios _yvbroadcastss.
// None permits broadcast, SAE or rounding. EVEX masking is per widened lane.
var x86PackedZeroExtendSpecs = map[Op]x86PackedZeroExtendSpec{
	"PMOVZXBW":  {8, 16, false, 0x30},
	"PMOVZXBD":  {8, 32, false, 0x31},
	"PMOVZXBQ":  {8, 64, false, 0x32},
	"PMOVZXWD":  {16, 32, false, 0x33},
	"PMOVZXWQ":  {16, 64, false, 0x34},
	"PMOVZXDQ":  {32, 64, false, 0x35},
	"VPMOVZXBW": {8, 16, true, 0x30},
	"VPMOVZXBD": {8, 32, true, 0x31},
	"VPMOVZXBQ": {8, 64, true, 0x32},
	"VPMOVZXWD": {16, 32, true, 0x33},
	"VPMOVZXWQ": {16, 64, true, 0x34},
	"VPMOVZXDQ": {32, 64, true, 0x35},
}

type x86PackedExtendForm struct {
	spec                x86PackedExtendSpec
	byteWidth           int
	sourceRegisterBytes int
	memoryBytes         int
	destination         int
	memory              int
	mask                int
	zeroing             bool
	signed              bool
}

type x86PackedZeroExtendForm = x86PackedExtendForm

// This specifies encoding and byte effects, never caller bounds or permission.
func x86PackedZeroExtendProperties(ins Instr, goarch string) (x86PackedZeroExtendForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	if _, known := x86PackedZeroExtendSpecs[Op(base)]; !known {
		return x86PackedExtendForm{}, false, nil
	}
	return x86PackedExtendProperties(ins, goarch)
}

// Sign and zero extension share operand shape, shrinking tuples and masked
// access rules, not membership, sign-byte dependencies or raw authority.
func x86PackedExtendProperties(ins Instr, goarch string) (x86PackedExtendForm, bool, error) {
	base, suffix, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, recognized := x86PackedZeroExtendSpecs[Op(base)]
	signed := false
	if !recognized {
		spec, recognized = x86PackedSignExtendSpecs[Op(base)]
		signed = true
	}
	if !recognized {
		return x86PackedExtendForm{}, false, nil
	}
	form := x86PackedExtendForm{
		spec: spec, destination: len(ins.Args) - 1, memory: -1, mask: -1,
		zeroing: suffix == "Z", sourceRegisterBytes: 16, signed: signed,
	}
	fail := func() (x86PackedExtendForm, bool, error) {
		return form, true, fmt.Errorf("%s %s operands/suffix outside Go packed widening grammar: %q", goarch, ins.Op, ins.Raw)
	}
	if goarch != "amd64" && goarch != "386" || len(ins.Args) != 2 && len(ins.Args) != 3 ||
		dotted && (!spec.vector || suffix != "Z") {
		return fail()
	}
	if len(ins.Args) == 3 {
		if !spec.vector || !amd64NonzeroKOperand(ins.Args[1]) {
			return fail()
		}
		form.mask = 1
	} else if form.zeroing {
		return fail()
	}
	destination := ins.Args[form.destination]
	form.byteWidth = amd64VectorByteWidth(destination.Reg)
	if !spec.vector {
		index, valid := amd64ParseXReg(destination.Reg)
		if destination.Kind != OpReg || !valid || index >= 16 || goarch == "386" && index >= 8 {
			return fail()
		}
	} else if !amd64GoPackedVectorMoveRegister(destination, form.byteWidth, goarch) {
		return fail()
	}
	form.memoryBytes = form.byteWidth * spec.inputBits / spec.outputBits
	if form.memoryBytes > 16 {
		form.sourceRegisterBytes = 32
	}
	source := ins.Args[0]
	if source.Kind == OpReg {
		if !amd64EVEXVectorRegister(source, form.sourceRegisterBytes) {
			return fail()
		}
		index, _ := amd64VectorRegisterIndex(source.Reg, form.sourceRegisterBytes)
		if !spec.vector && (index >= 16 || goarch == "386" && index >= 8) {
			return fail()
		}
	} else if isAMD64MemoryOperand(source) {
		if source.Kind == OpSym {
			symbol := strings.TrimSpace(source.Sym)
			_, absolute := parseInt(symbol)
			if strings.HasPrefix(symbol, "$") || !strings.HasSuffix(symbol, "(SB)") && absolute != nil {
				return fail()
			}
		}
		if source.Kind == OpMem {
			displacement := source.Mem.Off
			if displacement != int64(int32(displacement)) &&
				(goarch != "386" || displacement != int64(uint32(displacement))) ||
				!x86MemoryRegistersValidForArch(source.Mem, goarch) || source.Mem.Index != "" &&
				(source.Mem.Index == SP || source.Mem.Scale != 1 && source.Mem.Scale != 2 && source.Mem.Scale != 4 && source.Mem.Scale != 8) {
				return fail()
			}
		}
		form.memory = 0
	} else {
		return fail()
	}
	return form, true, x86Mode32VectorRegisterContext(ins, goarch)
}

func x86TypedPackedZeroExtendByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	if _, known, err := x86PackedZeroExtendProperties(ins, arch); !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	return x86TypedPackedExtendByteEffect(op, ins, arch)
}

func x86TypedPackedExtendByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86PackedExtendProperties(ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	if op != ins.Op {
		return x86TypedByteEffect{}, true, fmt.Errorf("packed widening effect/source opcode mismatch")
	}
	effect := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: 0, operand: ins.Args[0], width: int64(form.memoryBytes), read: true},
		{index: form.destination, operand: ins.Args[form.destination], width: int64(form.byteWidth),
			read: form.mask >= 0 && !form.zeroing, write: true},
	}}
	if form.mask >= 0 {
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: form.mask, operand: ins.Args[form.mask], width: 8, read: true,
		})
	}
	return effect, true, nil
}
