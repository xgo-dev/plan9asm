package plan9asm

import "fmt"

type arm64RawFloatCompare struct {
	op          Op
	zero        bool
	absolute    bool
	arrangement arm64VectorArrangement
	first       int
	second      int
	destination int
}

type arm64RawFloatCompareEncoding struct {
	base        uint32
	op          Op
	absolute    bool
	arrangement arm64VectorArrangement
}

var arm64RawFloatCompareBinaryEncodings = []arm64RawFloatCompareEncoding{
	{0x0e402400, "VFCMEQ", false, arm64VectorArrangement{16, 4}},
	{0x4e402400, "VFCMEQ", false, arm64VectorArrangement{16, 8}},
	{0x0e20e400, "VFCMEQ", false, arm64VectorArrangement{32, 2}},
	{0x4e20e400, "VFCMEQ", false, arm64VectorArrangement{32, 4}},
	{0x4e60e400, "VFCMEQ", false, arm64VectorArrangement{64, 2}},

	{0x2e402400, "VFCMGE", false, arm64VectorArrangement{16, 4}},
	{0x6e402400, "VFCMGE", false, arm64VectorArrangement{16, 8}},
	{0x2e20e400, "VFCMGE", false, arm64VectorArrangement{32, 2}},
	{0x6e20e400, "VFCMGE", false, arm64VectorArrangement{32, 4}},
	{0x6e60e400, "VFCMGE", false, arm64VectorArrangement{64, 2}},

	{0x2ec02400, "VFCMGT", false, arm64VectorArrangement{16, 4}},
	{0x6ec02400, "VFCMGT", false, arm64VectorArrangement{16, 8}},
	{0x2ea0e400, "VFCMGT", false, arm64VectorArrangement{32, 2}},
	{0x6ea0e400, "VFCMGT", false, arm64VectorArrangement{32, 4}},
	{0x6ee0e400, "VFCMGT", false, arm64VectorArrangement{64, 2}},

	{0x2e402c00, "VFACGE", true, arm64VectorArrangement{16, 4}},
	{0x6e402c00, "VFACGE", true, arm64VectorArrangement{16, 8}},
	{0x2e20ec00, "VFACGE", true, arm64VectorArrangement{32, 2}},
	{0x6e20ec00, "VFACGE", true, arm64VectorArrangement{32, 4}},
	{0x6e60ec00, "VFACGE", true, arm64VectorArrangement{64, 2}},

	{0x2ec02c00, "VFACGT", true, arm64VectorArrangement{16, 4}},
	{0x6ec02c00, "VFACGT", true, arm64VectorArrangement{16, 8}},
	{0x2ea0ec00, "VFACGT", true, arm64VectorArrangement{32, 2}},
	{0x6ea0ec00, "VFACGT", true, arm64VectorArrangement{32, 4}},
	{0x6ee0ec00, "VFACGT", true, arm64VectorArrangement{64, 2}},
}

var arm64RawFloatCompareZeroEncodings = []arm64RawFloatCompareEncoding{
	{0x0ef8d800, "VFCMEQ", false, arm64VectorArrangement{16, 4}},
	{0x4ef8d800, "VFCMEQ", false, arm64VectorArrangement{16, 8}},
	{0x0ea0d800, "VFCMEQ", false, arm64VectorArrangement{32, 2}},
	{0x4ea0d800, "VFCMEQ", false, arm64VectorArrangement{32, 4}},
	{0x4ee0d800, "VFCMEQ", false, arm64VectorArrangement{64, 2}},

	{0x2ef8c800, "VFCMGE", false, arm64VectorArrangement{16, 4}},
	{0x6ef8c800, "VFCMGE", false, arm64VectorArrangement{16, 8}},
	{0x2ea0c800, "VFCMGE", false, arm64VectorArrangement{32, 2}},
	{0x6ea0c800, "VFCMGE", false, arm64VectorArrangement{32, 4}},
	{0x6ee0c800, "VFCMGE", false, arm64VectorArrangement{64, 2}},

	{0x0ef8c800, "VFCMGT", false, arm64VectorArrangement{16, 4}},
	{0x4ef8c800, "VFCMGT", false, arm64VectorArrangement{16, 8}},
	{0x0ea0c800, "VFCMGT", false, arm64VectorArrangement{32, 2}},
	{0x4ea0c800, "VFCMGT", false, arm64VectorArrangement{32, 4}},
	{0x4ee0c800, "VFCMGT", false, arm64VectorArrangement{64, 2}},

	{0x2ef8d800, "VFCMLE", false, arm64VectorArrangement{16, 4}},
	{0x6ef8d800, "VFCMLE", false, arm64VectorArrangement{16, 8}},
	{0x2ea0d800, "VFCMLE", false, arm64VectorArrangement{32, 2}},
	{0x6ea0d800, "VFCMLE", false, arm64VectorArrangement{32, 4}},
	{0x6ee0d800, "VFCMLE", false, arm64VectorArrangement{64, 2}},

	{0x0ef8e800, "VFCMLT", false, arm64VectorArrangement{16, 4}},
	{0x4ef8e800, "VFCMLT", false, arm64VectorArrangement{16, 8}},
	{0x0ea0e800, "VFCMLT", false, arm64VectorArrangement{32, 2}},
	{0x4ea0e800, "VFCMLT", false, arm64VectorArrangement{32, 4}},
	{0x4ee0e800, "VFCMLT", false, arm64VectorArrangement{64, 2}},
}

func decodeARM64RawFloatCompare(word uint32) (arm64RawFloatCompare, bool) {
	const binaryRegisters = uint32(31 | 31<<5 | 31<<16)
	for _, encoding := range arm64RawFloatCompareBinaryEncodings {
		if word&^binaryRegisters == encoding.base {
			return arm64RawFloatCompare{
				op:          encoding.op,
				absolute:    encoding.absolute,
				arrangement: encoding.arrangement,
				first:       int(word>>5) & 31,
				second:      int(word>>16) & 31,
				destination: int(word) & 31,
			}, true
		}
	}

	const zeroRegisters = uint32(31 | 31<<5)
	for _, encoding := range arm64RawFloatCompareZeroEncodings {
		if word&^zeroRegisters == encoding.base {
			return arm64RawFloatCompare{
				op:          encoding.op,
				zero:        true,
				arrangement: encoding.arrangement,
				first:       int(word>>5) & 31,
				destination: int(word) & 31,
			}, true
		}
	}
	return arm64RawFloatCompare{}, false
}

func (c *arm64Ctx) lowerRawFloatCompare(form arm64RawFloatCompare) error {
	predicate, ok := arm64FloatComparePredicate(form.op)
	if !ok {
		return fmt.Errorf("arm64 raw %s decoder reached no semantic lowerer", form.op)
	}
	return c.lowerARM64VectorFloatCompareValues(
		predicate,
		form.absolute,
		form.arrangement,
		Reg(fmt.Sprintf("V%d", form.first)),
		Reg(fmt.Sprintf("V%d", form.second)),
		form.zero,
		Reg(fmt.Sprintf("V%d", form.destination)),
	)
}
