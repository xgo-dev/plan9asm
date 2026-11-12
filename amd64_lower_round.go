package plan9asm

import "fmt"

type amd64RoundSpec struct {
	laneBits int
	scalar   bool
	vector   bool
}

// amd64RoundSpecs mirrors Go 1.27's yxshuf, _yvroundpd, and _yvdppd tables.
// The legacy family is X-only, the packed VEX family is X/Y, and the scalar
// VEX family has an explicit upper-lane source.
var amd64RoundSpecs = map[Op]amd64RoundSpec{
	"ROUNDPS":  {laneBits: 32},
	"ROUNDPD":  {laneBits: 64},
	"ROUNDSS":  {laneBits: 32, scalar: true},
	"ROUNDSD":  {laneBits: 64, scalar: true},
	"VROUNDPS": {laneBits: 32, vector: true},
	"VROUNDPD": {laneBits: 64, vector: true},
	"VROUNDSS": {laneBits: 32, scalar: true, vector: true},
	"VROUNDSD": {laneBits: 64, scalar: true, vector: true},
}

func (c *amd64Ctx) lowerRound(rawOp Op, ins Instr) (ok bool, terminated bool, err error) {
	local := ins
	local.Op = rawOp
	form, known, err := x86RoundProperties(local, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if !form.spec.vector && form.memory && form.source.Kind != OpFP {
		memory := x86FloatBinaryForm{bits: form.spec.laneBits, scalar: form.spec.scalar, legacy: true,
			first: 1, second: len(ins.Args) - 1, destination: len(ins.Args) - 1, mask: -1,
			byteWidth: 16, memory: 1, memoryBytes: form.memoryBytes}
		return true, false, c.emitLegacyAlternatingRoundMemory(local, memory, &form.immediate)
	}
	intrinsic := amd64RoundIntrinsic(form.immediate)
	if form.spec.scalar {
		return c.lowerScalarRound(form, intrinsic)
	}
	return c.lowerPackedRound(form, intrinsic)
}

func amd64RoundIntrinsic(imm uint8) string {
	if imm&4 != 0 {
		return "rint"
	}
	switch imm & 3 {
	case 0:
		return "roundeven"
	case 1:
		return "floor"
	case 2:
		return "ceil"
	default:
		return "trunc"
	}
}

func (c *amd64Ctx) lowerScalarRound(form x86RoundForm, intrinsic string) (bool, bool, error) {
	spec, destination := form.spec, form.destination
	value, err := c.loadAlternatingRoundFloat(form.source, form.memoryBytes, spec.laneBits, spec.vector)
	if err != nil {
		return true, false, err
	}
	rounded := c.emitScalarFloatRound(value, spec.laneBits, intrinsic)
	bits := c.newTmp()
	floatingType := amd64FloatingTypeForBits(spec.laneBits)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to i%d\n", bits, floatingType, rounded, spec.laneBits)
	baseBytes, err := c.loadX(form.upper.Reg)
	if err != nil {
		return true, false, err
	}
	base := c.bitcastVectorBytesToIntegerLanes(16, 128/spec.laneBits, spec.laneBits, baseBytes)
	if spec.vector {
		return true, false, c.storeScalarMoveRegister(destination.Reg, spec.laneBits, "%"+bits, base, "", false)
	}
	return true, false, c.storeVectorScalarRegister(destination.Reg, spec.laneBits, "%"+bits, base, "", false)
}

func (c *amd64Ctx) lowerPackedRound(form x86RoundForm, intrinsic string) (bool, bool, error) {
	spec, destination, byteWidth := form.spec, form.destination, form.byteWidth
	bytesValue, err := c.loadRoundPackedBytes(form)
	if err != nil {
		return true, false, err
	}
	lanes := byteWidth * 8 / spec.laneBits
	floatingType := fmt.Sprintf("<%d x %s>", lanes, amd64FloatingTypeForBits(spec.laneBits))
	floating := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", floating, byteWidth, bytesValue, floatingType)
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", value, floatingType, floating, lane)
		rounded := c.emitScalarFloatRound("%"+value, spec.laneBits, intrinsic)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %s, i32 %d\n", inserted, floatingType, result, amd64FloatingTypeForBits(spec.laneBits), rounded, lane)
		result = "%" + inserted
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", out, floatingType, result, byteWidth)
	if spec.vector {
		return true, false, c.storePackedMoveOperand(destination, byteWidth, "%"+out)
	}
	return true, false, c.storeX(destination.Reg, "%"+out)
}

func (c *amd64Ctx) emitScalarFloatRound(value string, bits int, intrinsic string) string {
	typeName := amd64FloatingTypeForBits(bits)
	intrinsicSuffix := "f64"
	if bits == 32 {
		intrinsicSuffix = "f32"
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s)\n", result, typeName, intrinsic, intrinsicSuffix, typeName, value)
	return "%" + result
}
