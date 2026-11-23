package plan9asm

type arm64RawFloatCompare struct {
	operation     *arm64FloatCompareOperation
	arrangement   arm64VectorArrangement
	first, second int
	destination   int
	zero          bool
}

type arm64FloatCompareOpcode struct {
	single, half uint32
}

type arm64FloatCompareOperation struct {
	op                  Op
	mnemonic, predicate string
	binary, zero        arm64FloatCompareOpcode
	absolute            bool
}

var arm64FloatCompareOperations = [...]arm64FloatCompareOperation{
	{op: "VFCMEQ", mnemonic: "fcmeq", predicate: "oeq",
		binary: arm64FloatCompareOpcode{0x0e20e400, 0x0e402400}, zero: arm64FloatCompareOpcode{0x0ea0d800, 0x0ef8d800}},
	{op: "VFCMGE", mnemonic: "fcmge", predicate: "oge",
		binary: arm64FloatCompareOpcode{0x2e20e400, 0x2e402400}, zero: arm64FloatCompareOpcode{0x2ea0c800, 0x2ef8c800}},
	{op: "VFCMGT", mnemonic: "fcmgt", predicate: "ogt",
		binary: arm64FloatCompareOpcode{0x2ea0e400, 0x2ec02400}, zero: arm64FloatCompareOpcode{0x0ea0c800, 0x0ef8c800}},
	{op: "VFCMLE", mnemonic: "fcmle", predicate: "ole",
		zero: arm64FloatCompareOpcode{0x2ea0d800, 0x2ef8d800}},
	{op: "VFCMLT", mnemonic: "fcmlt", predicate: "olt",
		zero: arm64FloatCompareOpcode{0x0ea0e800, 0x0ef8e800}},
	{op: "VFACGE", mnemonic: "facge", predicate: "oge", absolute: true,
		binary: arm64FloatCompareOpcode{0x2e20ec00, 0x2e402c00}},
	{op: "VFACGT", mnemonic: "facgt", predicate: "ogt", absolute: true,
		binary: arm64FloatCompareOpcode{0x2ea0ec00, 0x2ec02c00}},
}

func (code arm64FloatCompareOpcode) elementBits(base uint32) int {
	const double = 1 << 22
	switch {
	case code.single == 0:
		return 0
	case base == code.half:
		return 16
	case base&^double == code.single:
		return 32 << (base >> 22 & 1)
	default:
		return 0
	}
}

func decodeARM64RawFloatCompare(word uint32) (arm64RawFloatCompare, bool) {
	const scalarBit, qBit = 1 << 28, 1 << 30
	const firstAndDestination, secondRegister = 31<<5 | 31, 31 << 16

	scalar, q := word&scalarBit != 0, word&qBit != 0
	if scalar && !q {
		return arm64RawFloatCompare{}, false
	}
	zeroBase := word &^ (scalarBit | qBit | firstAndDestination)
	binaryBase := zeroBase &^ secondRegister
	for i := range arm64FloatCompareOperations {
		op := &arm64FloatCompareOperations[i]
		bits := op.binary.elementBits(binaryBase)
		zero := bits == 0
		if zero {
			bits = op.zero.elementBits(zeroBase)
		}
		if bits == 0 || bits == 64 && !q {
			continue
		}
		lanes := 1
		if !scalar {
			lanes = 64 / bits
			if q {
				lanes *= 2
			}
		}
		form := arm64RawFloatCompare{
			operation: op, arrangement: arm64VectorArrangement{bits, lanes},
			first: int(word >> 5 & 31), destination: int(word & 31), zero: zero,
		}
		if !zero {
			form.second = int(word >> 16 & 31)
		}
		return form, true
	}
	return arm64RawFloatCompare{}, false
}
