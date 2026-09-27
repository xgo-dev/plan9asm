package plan9asm

import (
	"fmt"
	"strings"
)

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
	raw := strings.ToUpper(string(rawOp))
	if strings.Contains(raw, ".") {
		base := Op(strings.SplitN(raw, ".", 2)[0])
		if _, recognized := amd64RoundSpecs[base]; recognized {
			return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, base, ins.Raw)
		}
		return false, false, nil
	}
	spec, recognized := amd64RoundSpecs[Op(raw)]
	if !recognized {
		return false, false, nil
	}
	wantArgs := 3
	if spec.vector && spec.scalar {
		wantArgs = 4
	}
	if len(ins.Args) != wantArgs {
		return true, false, fmt.Errorf("%s %s expects immediate, source, %sdestination: %q", c.goarch, raw, map[bool]string{true: "upper-lane source, "}[spec.vector && spec.scalar], ins.Raw)
	}
	if ins.Args[0].Kind != OpImm {
		return true, false, fmt.Errorf("%s %s expects an 8-bit immediate: %q", c.goarch, raw, ins.Raw)
	}
	imm := ins.Args[0].Imm
	if (!spec.vector && (imm < 0 || imm > 255)) || (spec.vector && (imm < -128 || imm > 255)) {
		return true, false, fmt.Errorf("%s %s immediate is outside Go 1.27's table: %q", c.goarch, raw, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s destination must be a vector register: %q", c.goarch, raw, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if spec.scalar {
		if byteWidth != 16 || !c.isGoVEXVectorRegister(destination, 16, false) {
			return true, false, fmt.Errorf("%s %s destination must be an X register in the Go VEX class: %q", c.goarch, raw, ins.Raw)
		}
	} else if (!spec.vector && byteWidth != 16) || (spec.vector && byteWidth != 16 && byteWidth != 32) || !c.isGoVEXVectorRegister(destination, byteWidth, false) {
		return true, false, fmt.Errorf("%s %s destination has a width outside Go 1.27's table: %q", c.goarch, raw, ins.Raw)
	}
	source := ins.Args[1]
	if !c.isGoVEXVectorRegister(source, byteWidth, true) {
		return true, false, fmt.Errorf("%s %s source must be same-width X/Y or memory: %q", c.goarch, raw, ins.Raw)
	}
	if spec.vector && spec.scalar {
		upper := ins.Args[2]
		if !c.isGoVEXVectorRegister(upper, 16, false) {
			return true, false, fmt.Errorf("%s %s upper-lane source must be an X register: %q", c.goarch, raw, ins.Raw)
		}
	}
	intrinsic := amd64RoundIntrinsic(uint8(imm))
	if spec.scalar {
		return c.lowerScalarRound(spec, ins, destination, intrinsic)
	}
	return c.lowerPackedRound(spec, source, destination, byteWidth, intrinsic)
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

func (c *amd64Ctx) lowerScalarRound(spec amd64RoundSpec, ins Instr, destination Operand, intrinsic string) (bool, bool, error) {
	value, err := c.evalScalarFloatForInteger(ins.Args[1], spec.laneBits)
	if err != nil {
		return true, false, err
	}
	rounded := c.emitScalarFloatRound(value, spec.laneBits, intrinsic)
	bits := c.newTmp()
	floatingType := amd64FloatingTypeForBits(spec.laneBits)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to i%d\n", bits, floatingType, rounded, spec.laneBits)
	baseReg := destination.Reg
	if spec.vector {
		baseReg = ins.Args[2].Reg
	}
	baseBytes, err := c.loadX(baseReg)
	if err != nil {
		return true, false, err
	}
	base := c.bitcastVectorBytesToIntegerLanes(16, 128/spec.laneBits, spec.laneBits, baseBytes)
	return true, false, c.storeVectorScalarRegister(destination.Reg, spec.laneBits, "%"+bits, base, "", false)
}

func (c *amd64Ctx) lowerPackedRound(spec amd64RoundSpec, source, destination Operand, byteWidth int, intrinsic string) (bool, bool, error) {
	bytesValue, err := c.loadPackedCompareBytes(source, byteWidth)
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
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
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
