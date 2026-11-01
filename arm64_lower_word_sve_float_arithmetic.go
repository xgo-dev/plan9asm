package plan9asm

type arm64SVEFloatArithmeticSpec struct {
	kind       arm64RawSVEFloatKind
	vector     uint32
	predicated uint32
	immediate  uint32
	constants  [2]float64
	indexed    [3]uint32
}

// All named arithmetic forms and raw encodings use the same immediate
// choices. Raw normalization feeds the existing typed semantic forms.
var arm64SVEFloatArithmeticSpecs = map[Op]arm64SVEFloatArithmeticSpec{
	"ZFADD": {kind: arm64RawSVEFloatAdd, vector: 0x65000000, predicated: 0x65008000,
		immediate: 0x65188000, constants: [2]float64{0.5, 1}},
	"ZFSUB": {kind: arm64RawSVEFloatSub, vector: 0x65000400, predicated: 0x65018000,
		immediate: 0x65198000, constants: [2]float64{0.5, 1}},
	"ZFSUBR": {kind: arm64RawSVEFloatSubReverse, predicated: 0x65038000,
		immediate: 0x651b8000, constants: [2]float64{0.5, 1}},
	"ZFMUL": {kind: arm64RawSVEFloatMul, vector: 0x65000800, predicated: 0x65028000,
		immediate: 0x651a8000, constants: [2]float64{0.5, 2}, indexed: [3]uint32{0x64202000, 0x64a02000, 0x64e02000}},
}

type arm64SVEFloatArithmeticRawTables struct {
	vector, predicated, immediate map[uint32]arm64SVEFloatArithmeticSpec
	indexed                       map[uint32]int
}

var arm64SVEFloatArithmeticRaw = func() arm64SVEFloatArithmeticRawTables {
	tables := arm64SVEFloatArithmeticRawTables{
		vector: make(map[uint32]arm64SVEFloatArithmeticSpec), predicated: make(map[uint32]arm64SVEFloatArithmeticSpec),
		immediate: make(map[uint32]arm64SVEFloatArithmeticSpec), indexed: make(map[uint32]int),
	}
	for _, spec := range arm64SVEFloatArithmeticSpecs {
		if spec.vector != 0 {
			tables.vector[spec.vector] = spec
		}
		tables.predicated[spec.predicated], tables.immediate[spec.immediate] = spec, spec
		for size, base := range spec.indexed {
			if base != 0 {
				tables.indexed[base] = size + 1
			}
		}
	}
	return tables
}()

func decodeARM64RawSVEFloatArithmetic(word uint32) (arm64RawSVEFloat, bool) {
	form := arm64RawSVEFloat{elementBits: 8 << (word >> 22 & 3), destination: int(word & 31)}
	if spec, ok := arm64SVEFloatArithmeticRaw.vector[word&0xff20fc00]; ok {
		form.kind = spec.kind
		form.first, form.second = int(word>>5&31), int(word>>16&31)
	} else if spec, ok := arm64SVEFloatArithmeticRaw.predicated[word&0xff3fe000]; ok {
		form.kind, form.predicated = spec.kind, true
		form.first, form.predicate = int(word>>5&31), int(word>>10&7)
	} else if spec, ok := arm64SVEFloatArithmeticRaw.immediate[word&0xff3fe3c0]; ok {
		form.kind, form.predicated, form.hasImmediate = spec.kind, true, true
		form.first, form.predicate = form.destination, int(word>>10&7)
		form.immediate = spec.constants[word>>5&1]
	} else {
		size, ok := arm64SVEFloatArithmeticRaw.indexed[word&0xffe0fc00]
		if !ok {
			size, ok = arm64SVEFloatArithmeticRaw.indexed[word&0xffa0fc00]
			if !ok || size != 1 {
				return arm64RawSVEFloat{}, false
			}
		}
		form.kind, form.hasLane, form.elementBits = arm64RawSVEFloatMul, true, 8<<size
		form.first, form.second, form.lane = int(word>>5&31), int(word>>16&7), int(word>>19&3)
		if size == 1 {
			form.lane |= int(word >> 20 & 4)
		} else if size == 3 {
			form.second, form.lane = int(word>>16&15), int(word>>20&1)
		}
	}
	return form, form.elementBits >= 16
}
