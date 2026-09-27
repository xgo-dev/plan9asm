package plan9asm

import (
	"fmt"
	"strings"
)

type amd64ApproximateMathMode uint8

const (
	amd64ApproximateExp2 amd64ApproximateMathMode = iota
	amd64ApproximateReciprocal28
	amd64ApproximateReciprocalSqrt28
)

type amd64ApproximateMathSpec struct {
	laneBits int
	scalar   bool
	mode     amd64ApproximateMathMode
}

// amd64ApproximateMathSpecs models the complete AVX512ER family exposed by
// Go 1.27's _yvexp2pd and _yvgetexpsd tables. The type axes describe the
// mathematical operation, lane type, and packed/scalar operand shape; the
// parser below derives every legal mask, zero, broadcast, and SAE form.
var amd64ApproximateMathSpecs = map[Op]amd64ApproximateMathSpec{
	"VEXP2PS":    {laneBits: 32, mode: amd64ApproximateExp2},
	"VEXP2PD":    {laneBits: 64, mode: amd64ApproximateExp2},
	"VRCP28PS":   {laneBits: 32, mode: amd64ApproximateReciprocal28},
	"VRCP28PD":   {laneBits: 64, mode: amd64ApproximateReciprocal28},
	"VRCP28SS":   {laneBits: 32, scalar: true, mode: amd64ApproximateReciprocal28},
	"VRCP28SD":   {laneBits: 64, scalar: true, mode: amd64ApproximateReciprocal28},
	"VRSQRT28PS": {laneBits: 32, mode: amd64ApproximateReciprocalSqrt28},
	"VRSQRT28PD": {laneBits: 64, mode: amd64ApproximateReciprocalSqrt28},
	"VRSQRT28SS": {laneBits: 32, scalar: true, mode: amd64ApproximateReciprocalSqrt28},
	"VRSQRT28SD": {laneBits: 64, scalar: true, mode: amd64ApproximateReciprocalSqrt28},
}

type amd64ApproximateMathForm struct {
	properties  amd64BinaryFloatingSuffix
	source      Operand
	passthrough Operand
	destination Operand
	mask        string
}

func (c *amd64Ctx) lowerApproximateMath(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64ApproximateMathSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	form, err := c.parseApproximateMathForm(baseOp, suffix, spec, ins)
	if err != nil {
		return true, false, err
	}
	if spec.scalar {
		return c.lowerScalarApproximateMath(spec, form)
	}
	return c.lowerPackedApproximateMath(spec, form)
}

func (c *amd64Ctx) parseApproximateMathForm(baseOp, suffix string, spec amd64ApproximateMathSpec, ins Instr) (amd64ApproximateMathForm, error) {
	var form amd64ApproximateMathForm
	properties, validSuffix := parseAMD64BinaryFloatingSuffix(suffix)
	if !validSuffix || properties.rounding != "" || spec.scalar && properties.broadcast {
		return form, fmt.Errorf("%s %s has a suffix absent from Go 1.27's AVX512ER tables: %q", c.goarch, baseOp, ins.Raw)
	}
	wantArgs := 2
	if spec.scalar {
		wantArgs = 3
	}
	if len(ins.Args) != wantArgs && len(ins.Args) != wantArgs+1 {
		return form, fmt.Errorf("%s %s has the wrong operand count for its packed/scalar grammar: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == wantArgs+1
	if c.goarch == "386" && spec.scalar && masked {
		return form, fmt.Errorf("386 %s mask forms exceed the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if properties.zeroing && !masked {
		return form, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	maskIndex := len(ins.Args) - 2
	if masked && !amd64NonzeroKOperand(ins.Args[maskIndex]) {
		return form, fmt.Errorf("%s %s masked form expects K1-K7: %q", c.goarch, baseOp, ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return form, fmt.Errorf("%s %s destination must be a vector register: %q", c.goarch, baseOp, ins.Raw)
	}
	wantWidth := 64
	if spec.scalar {
		wantWidth = 16
	}
	if amd64VectorByteWidth(destination.Reg) != wantWidth || !c.isGoEVEXVectorRegister(destination, wantWidth) {
		return form, fmt.Errorf("%s %s destination must be an in-range %s register: %q", c.goarch, baseOp, map[bool]string{true: "X", false: "Z"}[spec.scalar], ins.Raw)
	}

	source := ins.Args[0]
	if properties.broadcast {
		if !isAMD64MemoryOperand(source) {
			return form, fmt.Errorf("%s %s.BCST requires a scalar memory source: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if source.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(source, wantWidth) {
			return form, fmt.Errorf("%s %s source register must match its destination width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return form, fmt.Errorf("%s %s source must be a matching vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	if properties.sae && source.Kind != OpReg {
		return form, fmt.Errorf("%s %s.SAE requires a register source: %q", c.goarch, baseOp, ins.Raw)
	}

	passthrough := Operand{}
	if spec.scalar {
		passthrough = ins.Args[1]
		if !c.isGoEVEXVectorRegister(passthrough, 16) {
			return form, fmt.Errorf("%s %s scalar passthrough must be an in-range X register: %q", c.goarch, baseOp, ins.Raw)
		}
	}
	mask := ""
	if masked {
		var err error
		mask, err = c.loadK(ins.Args[maskIndex].Reg)
		if err != nil {
			return form, err
		}
	}
	return amd64ApproximateMathForm{
		properties: properties, source: source, passthrough: passthrough,
		destination: destination, mask: mask,
	}, nil
}

func (c *amd64Ctx) lowerPackedApproximateMath(spec amd64ApproximateMathSpec, form amd64ApproximateMathForm) (bool, bool, error) {
	lanes := 512 / spec.laneBits
	typ := amd64FloatingVectorType(lanes, spec.laneBits)
	var source string
	if form.properties.broadcast {
		scalar, err := c.loadFloatingScalarOperand(form.source, spec.laneBits)
		if err != nil {
			return true, false, err
		}
		source = c.splatFloatingScalar(scalar, lanes, spec.laneBits)
	} else {
		var err error
		source, err = c.loadFloatingVectorOperand(form.source, 64, lanes, spec.laneBits)
		if err != nil {
			return true, false, err
		}
	}

	result := c.newTmp()
	assembly := approximateMathAssembly(spec, form.properties.sae, form.mask != "", form.properties.zeroing)
	clobbers := "~{dirflag},~{fpsr},~{flags}"
	if form.mask == "" {
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %s)\n", result, typ, assembly, "=v,v,"+clobbers, typ, source)
	} else {
		merge := "zeroinitializer"
		if !form.properties.zeroing {
			var err error
			merge, err = c.loadFloatingVectorOperand(form.destination, 64, lanes, spec.laneBits)
			if err != nil {
				return true, false, err
			}
		}
		mask := c.approximateMathMask32(form.mask)
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %s, %s %s, i32 %s)\n",
			result, typ, assembly, "=v,0,v,r,~{k1},"+clobbers, typ, merge, typ, source, mask)
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <64 x i8>\n", bytes, typ, result)
	return true, false, c.storeVectorBytes(form.destination.Reg, 64, "%"+bytes)
}

func (c *amd64Ctx) lowerScalarApproximateMath(spec amd64ApproximateMathSpec, form amd64ApproximateMathForm) (bool, bool, error) {
	lanes := 128 / spec.laneBits
	typ := amd64FloatingVectorType(lanes, spec.laneBits)
	var source string
	if form.source.Kind == OpReg {
		var err error
		source, err = c.loadFloatingVectorOperand(form.source, 16, lanes, spec.laneBits)
		if err != nil {
			return true, false, err
		}
	} else {
		scalar, err := c.loadFloatingScalarOperand(form.source, spec.laneBits)
		if err != nil {
			return true, false, err
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s zeroinitializer, %s %s, i32 0\n", inserted, typ, amd64FloatingScalarType(spec.laneBits), scalar)
		source = "%" + inserted
	}
	passthrough, err := c.loadFloatingVectorOperand(form.passthrough, 16, lanes, spec.laneBits)
	if err != nil {
		return true, false, err
	}

	result := c.newTmp()
	assembly := approximateMathAssembly(spec, form.properties.sae, form.mask != "", form.properties.zeroing)
	clobbers := "~{dirflag},~{fpsr},~{flags}"
	if form.mask == "" {
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %s, %s %s)\n",
			result, typ, assembly, "=v,v,v,"+clobbers, typ, source, typ, passthrough)
	} else {
		merge := "zeroinitializer"
		if !form.properties.zeroing {
			merge, err = c.loadFloatingVectorOperand(form.destination, 16, lanes, spec.laneBits)
			if err != nil {
				return true, false, err
			}
		}
		mask := c.approximateMathMask32(form.mask)
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %s, %s %s, %s %s, i32 %s)\n",
			result, typ, assembly, "=v,0,v,v,r,~{k1},"+clobbers,
			typ, merge, typ, source, typ, passthrough, mask)
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bytes, typ, result)
	return true, false, c.storeVectorBytes(form.destination.Reg, 16, "%"+bytes)
}

func approximateMathAssembly(spec amd64ApproximateMathSpec, sae, masked, zeroing bool) string {
	assembly := ""
	if masked {
		maskOperand := 3
		if spec.scalar {
			maskOperand = 4
		}
		assembly = fmt.Sprintf("kmovw ${%d:k}, %%k1; ", maskOperand)
	}
	assembly += approximateMathMnemonic(spec)
	if sae {
		assembly += " {sae},"
	}
	if spec.scalar {
		if masked {
			assembly += " $2, $3, $0"
		} else {
			assembly += " $1, $2, $0"
		}
	} else if masked {
		assembly += " $2, $0"
	} else {
		assembly += " $1, $0"
	}
	if masked {
		assembly += " {%k1}"
		if zeroing {
			assembly += " {z}"
		}
	}
	return assembly
}

func approximateMathMnemonic(spec amd64ApproximateMathSpec) string {
	stem := map[amd64ApproximateMathMode]string{
		amd64ApproximateExp2:             "vexp2",
		amd64ApproximateReciprocal28:     "vrcp28",
		amd64ApproximateReciprocalSqrt28: "vrsqrt28",
	}[spec.mode]
	if spec.scalar {
		if spec.laneBits == 32 {
			return stem + "ss"
		}
		return stem + "sd"
	}
	if spec.laneBits == 32 {
		return stem + "ps"
	}
	return stem + "pd"
}

func (c *amd64Ctx) approximateMathMask32(mask string) string {
	truncated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", truncated, mask)
	return "%" + truncated
}
