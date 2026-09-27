package plan9asm

import (
	"fmt"
	"strings"
)

type amd64Reciprocal14Spec struct {
	laneBits int
	scalar   bool
	rsqr     bool
}

// amd64Reciprocal14Specs covers every opcode backed by Go 1.27's
// _yvexpandpd and _yvgetexpsd reciprocal-estimate tables.
var amd64Reciprocal14Specs = map[Op]amd64Reciprocal14Spec{
	"VRCP14PS":   {laneBits: 32},
	"VRCP14PD":   {laneBits: 64},
	"VRCP14SS":   {laneBits: 32, scalar: true},
	"VRCP14SD":   {laneBits: 64, scalar: true},
	"VRSQRT14PS": {laneBits: 32, rsqr: true},
	"VRSQRT14PD": {laneBits: 64, rsqr: true},
	"VRSQRT14SS": {laneBits: 32, scalar: true, rsqr: true},
	"VRSQRT14SD": {laneBits: 64, scalar: true, rsqr: true},
}

// lowerReciprocal14 implements the complete Go 1.27 RCP14/RSQRT14 family.
// Packed PS/PD forms accept X/Y/Z register or memory sources, scalar-memory
// broadcast, and K1-K7 merge/.Z masking. Scalar SS/SD forms accept an X or
// scalar-memory source, an X passthrough, and the same masking on amd64; the
// four-operand masked scalar form exceeds the 386 assembler's operand limit.
func (c *amd64Ctx) lowerReciprocal14(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, found := amd64Reciprocal14Specs[Op(baseOp)]
	if !found {
		return false, false, nil
	}
	properties, validSuffix := parseAMD64BinaryFloatingSuffix(suffix)
	if !validSuffix || properties.sae || properties.rounding != "" || spec.scalar && properties.broadcast {
		return true, false, fmt.Errorf("%s %s suffix is absent from its Go 1.27 encoding: %q", c.goarch, baseOp, ins.Raw)
	}
	if spec.scalar {
		return c.lowerScalarReciprocal14(baseOp, spec, properties, ins)
	}
	return c.lowerPackedReciprocal14(baseOp, spec, properties, ins)
}

func (c *amd64Ctx) lowerPackedReciprocal14(baseOp string, spec amd64Reciprocal14Spec, properties amd64BinaryFloatingSuffix, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("%s %s expects source, [K1-K7,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 3
	if properties.zeroing && !masked {
		return true, false, fmt.Errorf("%s %s.Z requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("%s %s masked form requires K1-K7: %q", c.goarch, baseOp, ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s destination must be X, Y, or Z: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 || !c.isGoEVEXVectorRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's EVEX vector class: %q", c.goarch, baseOp, ins.Raw)
	}
	source := ins.Args[0]
	if properties.broadcast {
		if !isAMD64MemoryOperand(source) {
			return true, false, fmt.Errorf("%s %s.BCST requires a scalar memory source: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if source.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(source, byteWidth) {
			return true, false, fmt.Errorf("%s %s source register must match its destination: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s source must be a matching vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	lanes := byteWidth * 8 / spec.laneBits
	llvmType := amd64FloatingVectorType(lanes, spec.laneBits)
	var sourceValue string
	if properties.broadcast {
		scalar, err := c.loadFloatingScalarOperand(source, spec.laneBits)
		if err != nil {
			return true, false, err
		}
		sourceValue = c.splatFloatingScalar(scalar, lanes, spec.laneBits)
	} else {
		var err error
		sourceValue, err = c.loadFloatingVectorOperand(source, byteWidth, lanes, spec.laneBits)
		if err != nil {
			return true, false, err
		}
	}

	passthrough := "zeroinitializer"
	mask := "-1"
	maskBits := 8
	if spec.laneBits == 32 && byteWidth == 64 {
		maskBits = 16
	}
	if masked {
		loadedMask, err := c.loadK(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		mask = c.truncateReciprocal14Mask(loadedMask, maskBits)
		if !properties.zeroing {
			passthrough, err = c.loadFloatingVectorOperand(destination, byteWidth, lanes, spec.laneBits)
			if err != nil {
				return true, false, err
			}
		}
	}
	family := "rcp14"
	if spec.rsqr {
		family = "rsqrt14"
	}
	intrinsic := fmt.Sprintf("llvm.x86.avx512.%s.%s.%d", family, map[int]string{32: "ps", 64: "pd"}[spec.laneBits], byteWidth*8)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %s, %s %s, i%d %s)\n", result, llvmType, intrinsic, llvmType, sourceValue, llvmType, passthrough, maskBits, mask)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <%d x i8>\n", out, llvmType, result, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+out)
}

func (c *amd64Ctx) lowerScalarReciprocal14(baseOp string, spec amd64Reciprocal14Spec, properties amd64BinaryFloatingSuffix, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("%s %s expects source, passthrough, [K1-K7,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked {
		return true, false, fmt.Errorf("386 %s mask forms exceed the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if properties.zeroing && !masked {
		return true, false, fmt.Errorf("%s %s.Z requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[2]) {
		return true, false, fmt.Errorf("%s %s masked form requires K1-K7: %q", c.goarch, baseOp, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	passthroughArg := ins.Args[1]
	if !c.isGoEVEXVectorRegister(destination, 16) || !c.isGoEVEXVectorRegister(passthroughArg, 16) {
		return true, false, fmt.Errorf("%s %s passthrough and destination must be X registers: %q", c.goarch, baseOp, ins.Raw)
	}
	source := ins.Args[0]
	if source.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(source, 16) {
			return true, false, fmt.Errorf("%s %s source must be an X register or scalar memory: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s source must be an X register or scalar memory: %q", c.goarch, baseOp, ins.Raw)
	}

	lanes := 128 / spec.laneBits
	llvmType := amd64FloatingVectorType(lanes, spec.laneBits)
	scalar, err := c.loadFloatingScalarOperand(source, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	sourceValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement %s zeroinitializer, %s %s, i32 0\n", sourceValue, llvmType, amd64FloatingScalarType(spec.laneBits), scalar)
	passthrough, err := c.loadFloatingVectorOperand(passthroughArg, 16, lanes, spec.laneBits)
	if err != nil {
		return true, false, err
	}
	merge := "zeroinitializer"
	mask := "-1"
	if masked {
		loadedMask, err := c.loadK(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
		mask = c.truncateReciprocal14Mask(loadedMask, 8)
		if !properties.zeroing {
			merge, err = c.loadFloatingVectorOperand(destination, 16, lanes, spec.laneBits)
			if err != nil {
				return true, false, err
			}
		}
	}
	family := "rcp14"
	if spec.rsqr {
		family = "rsqrt14"
	}
	intrinsic := fmt.Sprintf("llvm.x86.avx512.%s.%s", family, map[int]string{32: "ss", 64: "sd"}[spec.laneBits])
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %s, %s %%%s, %s %s, i8 %s)\n", result, llvmType, intrinsic, llvmType, passthrough, llvmType, sourceValue, llvmType, merge, mask)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", out, llvmType, result)
	return true, false, c.storeVectorBytes(destination.Reg, 16, "%"+out)
}

func (c *amd64Ctx) truncateReciprocal14Mask(mask string, bits int) string {
	truncated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", truncated, mask, bits)
	return "%" + truncated
}

// lowerReciprocalEstimate implements the complete Go 1.27 legacy and VEX
// RCP/RSQRT estimate family: packed RCPPS/RSQRTPS/VRCPPS/VRSQRTPS plus scalar
// RCPSS/RSQRTSS/VRCPSS/VRSQRTSS. LLVM's target intrinsics preserve the
// instructions' approximate semantics instead of replacing them with exact
// generic floating-point operations.
func (c *amd64Ctx) lowerReciprocalEstimate(rawOp Op, ins Instr) (ok bool, terminated bool, err error) {
	raw := strings.ToUpper(string(rawOp))
	base := raw
	if dot := strings.IndexByte(raw, '.'); dot >= 0 {
		base = raw[:dot]
	}
	switch base {
	case "RCPPS", "RSQRTPS", "VRCPPS", "VRSQRTPS",
		"RCPSS", "RSQRTSS", "VRCPSS", "VRSQRTSS":
	default:
		return false, false, nil
	}
	if raw != base {
		return true, false, fmt.Errorf("%s %s has no suffixed form in Go 1.27: %q", c.goarch, base, ins.Raw)
	}
	if strings.HasSuffix(base, "SS") {
		return c.lowerScalarReciprocalEstimate(base, ins)
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("%s %s expects vector-or-memory source and vector destination: %q", c.goarch, base, ins.Raw)
	}

	source, destination := ins.Args[0], ins.Args[1]
	byteWidth := amd64VectorByteWidth(destination.Reg)
	legacy := base == "RCPPS" || base == "RSQRTPS"
	if legacy {
		if destination.Kind != OpReg || byteWidth != 16 || !c.isGoLegacyXReg(destination.Reg) {
			return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's legacy X register class: %q", c.goarch, base, ins.Raw)
		}
		if source.Kind == OpReg && !c.isGoLegacyXReg(source.Reg) {
			return true, false, fmt.Errorf("%s %s source must be an in-range X register or memory: %q", c.goarch, base, ins.Raw)
		}
	} else {
		if destination.Kind != OpReg || byteWidth != 16 && byteWidth != 32 || !amd64VEXVectorRegister(destination, byteWidth) {
			return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's VEX X/Y register classes: %q", c.goarch, base, ins.Raw)
		}
		if source.Kind == OpReg && !amd64VEXVectorRegister(source, byteWidth) {
			return true, false, fmt.Errorf("%s %s source must match the destination width: %q", c.goarch, base, ins.Raw)
		}
	}
	if source.Kind != OpReg && !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s source must be a matching vector register or memory: %q", c.goarch, base, ins.Raw)
	}

	lanes := byteWidth / 4
	value, err := c.loadPackedReciprocalSource(source, byteWidth, lanes)
	if err != nil {
		return true, false, err
	}
	intrinsic := "llvm.x86.sse.rcp.ps"
	if strings.Contains(base, "RSQRT") {
		intrinsic = "llvm.x86.sse.rsqrt.ps"
	}
	if byteWidth == 32 {
		intrinsic = "llvm.x86.avx.rcp.ps.256"
		if strings.Contains(base, "RSQRT") {
			intrinsic = "llvm.x86.avx.rsqrt.ps.256"
		}
	}
	vectorType := fmt.Sprintf("<%d x float>", lanes)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %s)\n", result, vectorType, intrinsic, vectorType, value)
	bytesValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <%d x i8>\n", bytesValue, vectorType, result, byteWidth)
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, "%"+bytesValue)
}

func (c *amd64Ctx) lowerScalarReciprocalEstimate(base string, ins Instr) (bool, bool, error) {
	legacy := base == "RCPSS" || base == "RSQRTSS"
	wantArgs := 3
	if legacy {
		wantArgs = 2
	}
	if len(ins.Args) != wantArgs {
		return true, false, fmt.Errorf("%s %s expects %d operands from its Go 1.27 table: %q", c.goarch, base, wantArgs, ins.Raw)
	}

	source := ins.Args[0]
	destination := ins.Args[len(ins.Args)-1]
	passthrough := destination
	if !legacy {
		passthrough = ins.Args[1]
	}
	if legacy {
		if destination.Kind != OpReg || !c.isGoLegacyXReg(destination.Reg) {
			return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's legacy X register class: %q", c.goarch, base, ins.Raw)
		}
		if source.Kind == OpReg && !c.isGoLegacyXReg(source.Reg) {
			return true, false, fmt.Errorf("%s %s source must be an in-range X register or scalar memory: %q", c.goarch, base, ins.Raw)
		}
		if source.Kind == OpMem && !x86MemoryRegistersValidForArch(source.Mem, c.goarch) {
			return true, false, fmt.Errorf("%s %s source uses an out-of-range legacy address register: %q", c.goarch, base, ins.Raw)
		}
	} else {
		if !amd64VEXVectorRegister(passthrough, 16) || !amd64VEXVectorRegister(destination, 16) {
			return true, false, fmt.Errorf("%s %s passthrough and destination must be VEX X registers: %q", c.goarch, base, ins.Raw)
		}
		if source.Kind == OpReg && !amd64VEXVectorRegister(source, 16) {
			return true, false, fmt.Errorf("%s %s source must be a VEX X register or scalar memory: %q", c.goarch, base, ins.Raw)
		}
	}
	if source.Kind != OpReg && !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s source must be an X register or scalar memory: %q", c.goarch, base, ins.Raw)
	}

	scalar, err := c.loadScalarReciprocalSource(source)
	if err != nil {
		return true, false, err
	}
	input := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <4 x float> zeroinitializer, float %s, i32 0\n", input, scalar)
	intrinsic := "llvm.x86.sse.rcp.ps"
	if strings.Contains(base, "RSQRT") {
		intrinsic = "llvm.x86.sse.rsqrt.ps"
	}
	estimates := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <4 x float> @%s(<4 x float> %%%s)\n", estimates, intrinsic, input)
	estimate := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <4 x float> %%%s, i32 0\n", estimate, estimates)
	upper, err := c.loadFloatingVectorOperand(passthrough, 16, 4, 32)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <4 x float> %s, float %%%s, i32 0\n", result, upper, estimate)
	bytesValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x float> %%%s to <16 x i8>\n", bytesValue, result)
	return true, false, c.storeVectorBytes(destination.Reg, 16, "%"+bytesValue)
}

func (c *amd64Ctx) loadScalarReciprocalSource(source Operand) (string, error) {
	if source.Kind == OpSym {
		// A bare integer is absolute memory in the Go assembler; '$' is the
		// immediate spelling and is intentionally rejected by this family.
		if address, err := parseInt(source.Sym); err == nil {
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load float, ptr %s, align 1\n", value, c.ptrFromAddrI64(fmt.Sprintf("%d", address)))
			return "%" + value, nil
		}
	}
	return c.loadFloatingScalarOperand(source, 32)
}

func (c *amd64Ctx) loadPackedReciprocalSource(source Operand, byteWidth, lanes int) (string, error) {
	if source.Kind == OpSym {
		// As in Go's x86 assembler, a bare integer is an absolute memory
		// operand. '$' is required for an immediate.
		if address, parseErr := parseInt(source.Sym); parseErr == nil {
			bytesValue := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load <%d x i8>, ptr %s, align 1\n", bytesValue, byteWidth, c.ptrFromAddrI64(fmt.Sprintf("%d", address)))
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %%%s to <%d x float>\n", value, byteWidth, bytesValue, lanes)
			return "%" + value, nil
		}
	}
	return c.loadFloatingVectorOperand(source, byteWidth, lanes, 32)
}
