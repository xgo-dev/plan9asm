package plan9asm

import (
	"fmt"
	"strings"
)

type amd64Reciprocal14Spec struct {
	laneBits int
	scalar   bool
}

// amd64Reciprocal14Specs covers every opcode backed by Go 1.27's
// _yvexpandpd and _yvgetexpsd reciprocal-estimate tables.
var amd64Reciprocal14Specs = map[Op]amd64Reciprocal14Spec{
	"VRCP14PS":   {laneBits: 32},
	"VRCP14PD":   {laneBits: 64},
	"VRCP14SS":   {laneBits: 32, scalar: true},
	"VRCP14SD":   {laneBits: 64, scalar: true},
	"VRSQRT14PS": {laneBits: 32},
	"VRSQRT14PD": {laneBits: 64},
	"VRSQRT14SS": {laneBits: 32, scalar: true},
	"VRSQRT14SD": {laneBits: 64, scalar: true},
}

// The complete Go RCP14/RSQRT14 family uses the existing typed native helper.
// Its approximation observes dynamic DAZ/FTZ, and active native memory reads
// must remain observable even when the numerical result is dead.
func (c *amd64Ctx) lowerReciprocal14(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := amd64Reciprocal14Specs[Op(base)]; !known {
		return false, false, nil
	}
	return c.lowerNativeFloatingHelper(op, ins)
}

// lowerReciprocalEstimate implements the complete Go 1.27 legacy and VEX
// RCP/RSQRT estimate family. Pure packed register estimates retain their
// intrinsics and legal CSE; memory estimates preserve their original opcode,
// full native access and legacy alignment fault even with a dead result.
func (c *amd64Ctx) lowerReciprocalEstimate(rawOp Op, ins Instr) (ok bool, terminated bool, err error) {
	raw := strings.ToUpper(string(rawOp))
	base, _, _ := strings.Cut(raw, ".")
	if _, scalar := x86ScalarReciprocalSpecs[Op(base)]; scalar {
		if raw != base {
			return true, false, fmt.Errorf("%s %s has no suffixed form in Go 1.27: %q", c.goarch, base, ins.Raw)
		}
		return c.lowerScalarReciprocalEstimate(base, ins)
	}
	form, known, err := x86PackedReciprocalProperties(rawOp, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	return true, false, c.emitPackedReciprocalEstimate(ins, form)
}

func (c *amd64Ctx) emitPackedReciprocalEstimate(ins Instr, form x86PackedReciprocalForm) error {
	if ins.x86AddressBits != 0 {
		return fmt.Errorf("%w: %s needs its original address-size binding", ErrProbeNeedsContext, ins.Op)
	}
	source, destination := ins.Args[0], ins.Args[1]
	byteWidth := form.byteWidth
	lanes := byteWidth / 4
	vectorType := fmt.Sprintf("<%d x float>", lanes)
	result := c.newTmp()
	if source.Kind != OpReg && source.Kind != OpFP {
		pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
		if err != nil {
			return err
		}
		segment := ""
		if source.Kind == OpMem && source.Mem.Segment != "" {
			segment = "%" + strings.ToLower(string(source.Mem.Segment)) + ":"
		}
		assembly := strings.ToLower(string(form.op)) + " " + segment + "$1, $0"
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s elementtype([%d x i8]) %s)\n",
			result, vectorType, assembly, "=x,*m,~{memory}", pointerType, byteWidth, pointer)
	} else {
		value, err := c.loadFloatingVectorOperand(source, byteWidth, lanes, 32)
		if err != nil {
			return err
		}
		intrinsic := "llvm.x86.sse.rcp.ps"
		if strings.Contains(string(form.op), "RSQRT") {
			intrinsic = "llvm.x86.sse.rsqrt.ps"
		}
		if byteWidth == 32 {
			intrinsic = "llvm.x86.avx.rcp.ps.256"
			if strings.Contains(string(form.op), "RSQRT") {
				intrinsic = "llvm.x86.avx.rsqrt.ps.256"
			}
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %s)\n", result, vectorType, intrinsic, vectorType, value)
	}
	bytesValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <%d x i8>\n", bytesValue, vectorType, result, byteWidth)
	if form.legacy {
		return c.storeLegacyXViews(destination.Reg, "%"+bytesValue)
	}
	return c.storePackedMoveOperand(destination, byteWidth, "%"+bytesValue)
}

func (c *amd64Ctx) lowerScalarReciprocalEstimate(base string, ins Instr) (bool, bool, error) {
	form, _, err := x86ScalarReciprocalProperties(Op(base), ins, c.goarch)
	if err != nil {
		return true, false, err
	}
	return true, false, c.emitScalarReciprocalEstimate(ins, form)
}

func (c *amd64Ctx) emitScalarReciprocalEstimate(ins Instr, form x86ScalarReciprocalForm) error {
	if ins.x86AddressBits != 0 {
		return fmt.Errorf("%w: %s needs its original address-size binding", ErrProbeNeedsContext, ins.Op)
	}
	upper, err := c.loadFloatingVectorOperand(ins.Args[form.base], 16, 4, 32)
	if err != nil {
		return err
	}
	value, sourceType, constraint, template, err := c.scalarReciprocalNativeSource(ins.Args[0])
	if err != nil {
		return err
	}
	// Keep the scalar hardware approximation, not a packed estimate or generic
	// division/sqrt. The original opcode has no SIMD exceptions, ignores RC,
	// treats denormals as signed zero and leaves all MXCSR status untouched.
	assembly := strings.ToLower(string(ins.Op)) + " "
	constraints, args := "=x,", ""
	if form.spec.vector {
		assembly += template + ", $2, $0"
		constraints += constraint + ",x"
		args = fmt.Sprintf("%s %s, <4 x float> %s", sourceType, value, upper)
	} else {
		assembly += strings.Replace(template, "$1", "$2", 1) + ", $0"
		constraints += "0," + constraint
		args = fmt.Sprintf("<4 x float> %s, %s %s", upper, sourceType, value)
	}
	result, bytes := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <4 x float> asm sideeffect %q, %q(%s)\n", result, assembly, constraints+",~{memory},~{fpsr}", args)
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x float> %%%s to <16 x i8>\n", bytes, result)
	if !form.spec.vector {
		return c.storeLegacyXViews(ins.Args[form.destination].Reg, "%"+bytes)
	}
	return c.storePackedMoveOperand(ins.Args[form.destination], 16, "%"+bytes)
}

func (c *amd64Ctx) scalarReciprocalNativeSource(source Operand) (value, typ, constraint, template string, err error) {
	if source.Kind == OpReg {
		value, err = c.loadFloatingVectorOperand(source, 16, 4, 32)
		return value, "<4 x float>", "x", "$1", err
	}
	if source.Kind == OpFP {
		bits, loadErr := c.loadScalarLaneFPBits(source.FPOffset, 32)
		if loadErr != nil {
			return "", "", "", "", loadErr
		}
		scalar, inserted := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast i32 %s to float\n", scalar, bits)
		fmt.Fprintf(c.b, "  %%%s = insertelement <4 x float> zeroinitializer, float %%%s, i32 0\n", inserted, scalar)
		return "%" + inserted, "<4 x float>", "x", "$1", nil
	}
	// A sideeffecting m32 operand keeps the original access even for Void.
	// This pointer is not a widened virtual FP slot or invented backing.
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return "", "", "", "", err
	}
	segment := ""
	if source.Kind == OpMem && source.Mem.Segment != "" {
		segment = "%" + strings.ToLower(string(source.Mem.Segment)) + ":"
	}
	return pointer, pointerType + " elementtype([4 x i8])", "*m", segment + "$1", nil
}
