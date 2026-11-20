package plan9asm

import "strings"

type x86PackedUnpackSpec struct {
	laneBits int
	high     bool
	grammar  x86PackedBinarySpec
}

// Go's six ymm rows include MMX. Its other six legacy rows use yxm.
// All twelve vector rows use _yvandnpd, but only D/Q/PS/PD permit BCST.
// Their EVEX memory exception class is E4NF: masking does not suppress faults.
var x86PackedUnpackSpecs = map[Op]x86PackedUnpackSpec{
	"PUNPCKLBW":   {8, false, x86PackedBinarySpec{x86PackedLogicalLegacyInteger, 0, false}},
	"PUNPCKHBW":   {8, true, x86PackedBinarySpec{x86PackedLogicalLegacyInteger, 0, false}},
	"PUNPCKLWL":   {16, false, x86PackedBinarySpec{x86PackedLogicalLegacyInteger, 0, false}},
	"PUNPCKHWL":   {16, true, x86PackedBinarySpec{x86PackedLogicalLegacyInteger, 0, false}},
	"PUNPCKLLQ":   {32, false, x86PackedBinarySpec{x86PackedLogicalLegacyInteger, 0, false}},
	"PUNPCKHLQ":   {32, true, x86PackedBinarySpec{x86PackedLogicalLegacyInteger, 0, false}},
	"PUNPCKLQDQ":  {64, false, x86PackedBinarySpec{x86PackedLogicalLegacyFP, 0, false}},
	"PUNPCKHQDQ":  {64, true, x86PackedBinarySpec{x86PackedLogicalLegacyFP, 0, false}},
	"UNPCKLPS":    {32, false, x86PackedBinarySpec{x86PackedLogicalLegacyFP, 0, false}},
	"UNPCKHPS":    {32, true, x86PackedBinarySpec{x86PackedLogicalLegacyFP, 0, false}},
	"UNPCKLPD":    {64, false, x86PackedBinarySpec{x86PackedLogicalLegacyFP, 0, false}},
	"UNPCKHPD":    {64, true, x86PackedBinarySpec{x86PackedLogicalLegacyFP, 0, false}},
	"VPUNPCKLBW":  {8, false, x86PackedBinarySpec{x86PackedLogicalVEXOrEVEX, 0, true}},
	"VPUNPCKHBW":  {8, true, x86PackedBinarySpec{x86PackedLogicalVEXOrEVEX, 0, true}},
	"VPUNPCKLWD":  {16, false, x86PackedBinarySpec{x86PackedLogicalVEXOrEVEX, 0, true}},
	"VPUNPCKHWD":  {16, true, x86PackedBinarySpec{x86PackedLogicalVEXOrEVEX, 0, true}},
	"VPUNPCKLDQ":  {32, false, x86PackedBinarySpec{x86PackedLogicalVEXOrEVEX, 4, true}},
	"VPUNPCKHDQ":  {32, true, x86PackedBinarySpec{x86PackedLogicalVEXOrEVEX, 4, true}},
	"VPUNPCKLQDQ": {64, false, x86PackedBinarySpec{x86PackedLogicalVEXOrEVEX, 8, true}},
	"VPUNPCKHQDQ": {64, true, x86PackedBinarySpec{x86PackedLogicalVEXOrEVEX, 8, true}},
	"VUNPCKLPS":   {32, false, x86PackedBinarySpec{x86PackedLogicalVEXOrEVEX, 4, true}},
	"VUNPCKHPS":   {32, true, x86PackedBinarySpec{x86PackedLogicalVEXOrEVEX, 4, true}},
	"VUNPCKLPD":   {64, false, x86PackedBinarySpec{x86PackedLogicalVEXOrEVEX, 8, true}},
	"VUNPCKHPD":   {64, true, x86PackedBinarySpec{x86PackedLogicalVEXOrEVEX, 8, true}},
}

type x86PackedUnpackForm struct {
	x86PackedBinaryForm
	spec   x86PackedUnpackSpec
	source Operand
}

// Pure byte dependencies shared by independent caller and result observers.
// Memory access, register mode, mask and alignment roles remain prerequisites
// of each consumer; no dependency mask shrinks a native memory operation.
func x86PackedUnpackDefinedBytes(form x86PackedUnpackForm, first, second, old uint64) uint64 {
	laneBytes := form.spec.laneBits / 8
	groupBytes := 16
	if form.byteWidth < groupBytes {
		groupBytes = form.byteWidth
	}
	half := groupBytes / 2
	start := 0
	if form.spec.high {
		start = half
	}
	var known uint64
	for group := 0; group < form.byteWidth; group += groupBytes {
		for offset := 0; offset < half; offset += laneBytes {
			for byteIndex := 0; byteIndex < laneBytes; byteIndex++ {
				source := uint(group + start + offset + byteIndex)
				destination := uint(group + 2*offset + byteIndex)
				known |= (second >> source & 1) << destination
				known |= (first >> source & 1) << (destination + uint(laneBytes))
			}
		}
	}
	if form.mask >= 0 && !form.zeroing {
		known &= old
	}
	return known
}

func x86PackedUnpackProperties(ins Instr, goarch string) (x86PackedUnpackForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, recognized := x86PackedUnpackSpecs[Op(base)]
	if !recognized {
		return x86PackedUnpackForm{}, false, nil
	}
	local := ins
	if spec.grammar.encoding == x86PackedLogicalLegacyInteger {
		var err error
		local, err = x86LegacyMMXReadInstruction(ins, goarch)
		if err != nil {
			return x86PackedUnpackForm{}, true, err
		}
	}
	form, err := x86PackedBinaryProperties(local, goarch, spec.grammar)
	// Intel's three MMX low-unpack rows are mm/m32, unlike the high
	// rows' mm/m64. The unused high source half is not a memory access.
	if err == nil && form.mmx && form.memory >= 0 && !spec.high {
		form.memoryBytes = 4
	}
	if err == nil {
		err = x86Mode32VectorRegisterContext(ins, goarch)
	}
	result := x86PackedUnpackForm{x86PackedBinaryForm: form, spec: spec}
	if err == nil {
		result.source = local.Args[form.first]
	}
	return result, true, err
}
