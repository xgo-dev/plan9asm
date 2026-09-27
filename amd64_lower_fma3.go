package plan9asm

import (
	"fmt"
	"strings"
)

type amd64FMA3Mode uint8

const (
	amd64FMA3Add amd64FMA3Mode = iota
	amd64FMA3Sub
	amd64FMA3NegAdd
	amd64FMA3NegSub
	amd64FMA3AddSub
	amd64FMA3SubAdd
)

type amd64FMA3Spec struct {
	laneBits int
	order    int
	mode     amd64FMA3Mode
	scalar   bool
	rawOnly  bool
}

// amd64FMA3Specs is the complete Go 1.27 FMA3 family. The 36 packed
// instructions use _yvaddpd and the 24 scalar instructions use _yvaddsd.
// The additional 30 MAP6 FP16 forms are accepted only from raw bytes.
var amd64FMA3Specs = map[Op]amd64FMA3Spec{
	"VFMADD132PS":    {laneBits: 32, order: 132, mode: amd64FMA3Add},
	"VFMADD132PD":    {laneBits: 64, order: 132, mode: amd64FMA3Add},
	"VFMADD132SS":    {laneBits: 32, order: 132, mode: amd64FMA3Add, scalar: true},
	"VFMADD132SD":    {laneBits: 64, order: 132, mode: amd64FMA3Add, scalar: true},
	"VFMADD213PS":    {laneBits: 32, order: 213, mode: amd64FMA3Add},
	"VFMADD213PD":    {laneBits: 64, order: 213, mode: amd64FMA3Add},
	"VFMADD213SS":    {laneBits: 32, order: 213, mode: amd64FMA3Add, scalar: true},
	"VFMADD213SD":    {laneBits: 64, order: 213, mode: amd64FMA3Add, scalar: true},
	"VFMADD231PS":    {laneBits: 32, order: 231, mode: amd64FMA3Add},
	"VFMADD231PD":    {laneBits: 64, order: 231, mode: amd64FMA3Add},
	"VFMADD231SS":    {laneBits: 32, order: 231, mode: amd64FMA3Add, scalar: true},
	"VFMADD231SD":    {laneBits: 64, order: 231, mode: amd64FMA3Add, scalar: true},
	"VFMSUB132PS":    {laneBits: 32, order: 132, mode: amd64FMA3Sub},
	"VFMSUB132PD":    {laneBits: 64, order: 132, mode: amd64FMA3Sub},
	"VFMSUB132SS":    {laneBits: 32, order: 132, mode: amd64FMA3Sub, scalar: true},
	"VFMSUB132SD":    {laneBits: 64, order: 132, mode: amd64FMA3Sub, scalar: true},
	"VFMSUB213PS":    {laneBits: 32, order: 213, mode: amd64FMA3Sub},
	"VFMSUB213PD":    {laneBits: 64, order: 213, mode: amd64FMA3Sub},
	"VFMSUB213SS":    {laneBits: 32, order: 213, mode: amd64FMA3Sub, scalar: true},
	"VFMSUB213SD":    {laneBits: 64, order: 213, mode: amd64FMA3Sub, scalar: true},
	"VFMSUB231PS":    {laneBits: 32, order: 231, mode: amd64FMA3Sub},
	"VFMSUB231PD":    {laneBits: 64, order: 231, mode: amd64FMA3Sub},
	"VFMSUB231SS":    {laneBits: 32, order: 231, mode: amd64FMA3Sub, scalar: true},
	"VFMSUB231SD":    {laneBits: 64, order: 231, mode: amd64FMA3Sub, scalar: true},
	"VFNMADD132PS":   {laneBits: 32, order: 132, mode: amd64FMA3NegAdd},
	"VFNMADD132PD":   {laneBits: 64, order: 132, mode: amd64FMA3NegAdd},
	"VFNMADD132SS":   {laneBits: 32, order: 132, mode: amd64FMA3NegAdd, scalar: true},
	"VFNMADD132SD":   {laneBits: 64, order: 132, mode: amd64FMA3NegAdd, scalar: true},
	"VFNMADD213PS":   {laneBits: 32, order: 213, mode: amd64FMA3NegAdd},
	"VFNMADD213PD":   {laneBits: 64, order: 213, mode: amd64FMA3NegAdd},
	"VFNMADD213SS":   {laneBits: 32, order: 213, mode: amd64FMA3NegAdd, scalar: true},
	"VFNMADD213SD":   {laneBits: 64, order: 213, mode: amd64FMA3NegAdd, scalar: true},
	"VFNMADD231PS":   {laneBits: 32, order: 231, mode: amd64FMA3NegAdd},
	"VFNMADD231PD":   {laneBits: 64, order: 231, mode: amd64FMA3NegAdd},
	"VFNMADD231SS":   {laneBits: 32, order: 231, mode: amd64FMA3NegAdd, scalar: true},
	"VFNMADD231SD":   {laneBits: 64, order: 231, mode: amd64FMA3NegAdd, scalar: true},
	"VFNMSUB132PS":   {laneBits: 32, order: 132, mode: amd64FMA3NegSub},
	"VFNMSUB132PD":   {laneBits: 64, order: 132, mode: amd64FMA3NegSub},
	"VFNMSUB132SS":   {laneBits: 32, order: 132, mode: amd64FMA3NegSub, scalar: true},
	"VFNMSUB132SD":   {laneBits: 64, order: 132, mode: amd64FMA3NegSub, scalar: true},
	"VFNMSUB213PS":   {laneBits: 32, order: 213, mode: amd64FMA3NegSub},
	"VFNMSUB213PD":   {laneBits: 64, order: 213, mode: amd64FMA3NegSub},
	"VFNMSUB213SS":   {laneBits: 32, order: 213, mode: amd64FMA3NegSub, scalar: true},
	"VFNMSUB213SD":   {laneBits: 64, order: 213, mode: amd64FMA3NegSub, scalar: true},
	"VFNMSUB231PS":   {laneBits: 32, order: 231, mode: amd64FMA3NegSub},
	"VFNMSUB231PD":   {laneBits: 64, order: 231, mode: amd64FMA3NegSub},
	"VFNMSUB231SS":   {laneBits: 32, order: 231, mode: amd64FMA3NegSub, scalar: true},
	"VFNMSUB231SD":   {laneBits: 64, order: 231, mode: amd64FMA3NegSub, scalar: true},
	"VFMADDSUB132PS": {laneBits: 32, order: 132, mode: amd64FMA3AddSub},
	"VFMADDSUB132PD": {laneBits: 64, order: 132, mode: amd64FMA3AddSub},
	"VFMADDSUB213PS": {laneBits: 32, order: 213, mode: amd64FMA3AddSub},
	"VFMADDSUB213PD": {laneBits: 64, order: 213, mode: amd64FMA3AddSub},
	"VFMADDSUB231PS": {laneBits: 32, order: 231, mode: amd64FMA3AddSub},
	"VFMADDSUB231PD": {laneBits: 64, order: 231, mode: amd64FMA3AddSub},
	"VFMSUBADD132PS": {laneBits: 32, order: 132, mode: amd64FMA3SubAdd},
	"VFMSUBADD132PD": {laneBits: 64, order: 132, mode: amd64FMA3SubAdd},
	"VFMSUBADD213PS": {laneBits: 32, order: 213, mode: amd64FMA3SubAdd},
	"VFMSUBADD213PD": {laneBits: 64, order: 213, mode: amd64FMA3SubAdd},
	"VFMSUBADD231PS": {laneBits: 32, order: 231, mode: amd64FMA3SubAdd},
	"VFMSUBADD231PD": {laneBits: 64, order: 231, mode: amd64FMA3SubAdd},
	"VFMADD132PH":    {laneBits: 16, order: 132, mode: amd64FMA3Add, rawOnly: true},
	"VFMADD132SH":    {laneBits: 16, order: 132, mode: amd64FMA3Add, scalar: true, rawOnly: true},
	"VFMSUB132PH":    {laneBits: 16, order: 132, mode: amd64FMA3Sub, rawOnly: true},
	"VFMSUB132SH":    {laneBits: 16, order: 132, mode: amd64FMA3Sub, scalar: true, rawOnly: true},
	"VFNMADD132PH":   {laneBits: 16, order: 132, mode: amd64FMA3NegAdd, rawOnly: true},
	"VFNMADD132SH":   {laneBits: 16, order: 132, mode: amd64FMA3NegAdd, scalar: true, rawOnly: true},
	"VFNMSUB132PH":   {laneBits: 16, order: 132, mode: amd64FMA3NegSub, rawOnly: true},
	"VFNMSUB132SH":   {laneBits: 16, order: 132, mode: amd64FMA3NegSub, scalar: true, rawOnly: true},
	"VFMADDSUB132PH": {laneBits: 16, order: 132, mode: amd64FMA3AddSub, rawOnly: true},
	"VFMSUBADD132PH": {laneBits: 16, order: 132, mode: amd64FMA3SubAdd, rawOnly: true},
	"VFMADD213PH":    {laneBits: 16, order: 213, mode: amd64FMA3Add, rawOnly: true},
	"VFMADD213SH":    {laneBits: 16, order: 213, mode: amd64FMA3Add, scalar: true, rawOnly: true},
	"VFMSUB213PH":    {laneBits: 16, order: 213, mode: amd64FMA3Sub, rawOnly: true},
	"VFMSUB213SH":    {laneBits: 16, order: 213, mode: amd64FMA3Sub, scalar: true, rawOnly: true},
	"VFNMADD213PH":   {laneBits: 16, order: 213, mode: amd64FMA3NegAdd, rawOnly: true},
	"VFNMADD213SH":   {laneBits: 16, order: 213, mode: amd64FMA3NegAdd, scalar: true, rawOnly: true},
	"VFNMSUB213PH":   {laneBits: 16, order: 213, mode: amd64FMA3NegSub, rawOnly: true},
	"VFNMSUB213SH":   {laneBits: 16, order: 213, mode: amd64FMA3NegSub, scalar: true, rawOnly: true},
	"VFMADDSUB213PH": {laneBits: 16, order: 213, mode: amd64FMA3AddSub, rawOnly: true},
	"VFMSUBADD213PH": {laneBits: 16, order: 213, mode: amd64FMA3SubAdd, rawOnly: true},
	"VFMADD231PH":    {laneBits: 16, order: 231, mode: amd64FMA3Add, rawOnly: true},
	"VFMADD231SH":    {laneBits: 16, order: 231, mode: amd64FMA3Add, scalar: true, rawOnly: true},
	"VFMSUB231PH":    {laneBits: 16, order: 231, mode: amd64FMA3Sub, rawOnly: true},
	"VFMSUB231SH":    {laneBits: 16, order: 231, mode: amd64FMA3Sub, scalar: true, rawOnly: true},
	"VFNMADD231PH":   {laneBits: 16, order: 231, mode: amd64FMA3NegAdd, rawOnly: true},
	"VFNMADD231SH":   {laneBits: 16, order: 231, mode: amd64FMA3NegAdd, scalar: true, rawOnly: true},
	"VFNMSUB231PH":   {laneBits: 16, order: 231, mode: amd64FMA3NegSub, rawOnly: true},
	"VFNMSUB231SH":   {laneBits: 16, order: 231, mode: amd64FMA3NegSub, scalar: true, rawOnly: true},
	"VFMADDSUB231PH": {laneBits: 16, order: 231, mode: amd64FMA3AddSub, rawOnly: true},
	"VFMSUBADD231PH": {laneBits: 16, order: 231, mode: amd64FMA3SubAdd, rawOnly: true},
}

type amd64FMA3Suffix struct {
	broadcast bool
	zeroing   bool
	rounding  string
}

func parseAMD64FMA3Suffix(suffix string) (amd64FMA3Suffix, bool) {
	switch suffix {
	case "":
		return amd64FMA3Suffix{}, true
	case "Z":
		return amd64FMA3Suffix{zeroing: true}, true
	case "BCST":
		return amd64FMA3Suffix{broadcast: true}, true
	case "BCST.Z":
		return amd64FMA3Suffix{broadcast: true, zeroing: true}, true
	case "RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE":
		return amd64FMA3Suffix{rounding: suffix}, true
	case "RN_SAE.Z", "RD_SAE.Z", "RU_SAE.Z", "RZ_SAE.Z":
		return amd64FMA3Suffix{zeroing: true, rounding: strings.TrimSuffix(suffix, ".Z")}, true
	default:
		return amd64FMA3Suffix{}, false
	}
}

func (c *amd64Ctx) lowerFMA3(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64FMA3Specs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if spec.rawOnly && !ins.x86Encoded {
		return true, false, fmt.Errorf("%s is absent from Go's named assembler table; raw encoding required", baseOp)
	}
	properties, validSuffix := parseAMD64FMA3Suffix(suffix)
	if !validSuffix {
		return true, false, fmt.Errorf("%s %s has a suffix absent from Go 1.27's FMA3 optab: %q", c.goarch, baseOp, ins.Raw)
	}
	if spec.scalar && properties.broadcast {
		return true, false, fmt.Errorf("%s %s scalar forms do not support broadcast: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("%s %s expects src1, src2, [K mask,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked && !ins.x86Encoded {
		return true, false, fmt.Errorf("386 %s mask forms exceed Go 1.27's assembler operand limit: %q", baseOp, ins.Raw)
	}
	if properties.zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}

	dstArg := ins.Args[len(ins.Args)-1]
	if dstArg.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s destination must be a vector register: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(dstArg.Reg)
	if spec.scalar {
		if byteWidth != 16 {
			return true, false, fmt.Errorf("%s %s scalar destination must be an X register: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 {
		return true, false, fmt.Errorf("%s %s packed destination must be an X, Y, or Z register: %q", c.goarch, baseOp, ins.Raw)
	}
	if !c.isGoEVEXVectorRegister(dstArg, byteWidth) || !c.isGoEVEXVectorRegister(ins.Args[1], byteWidth) {
		return true, false, fmt.Errorf("%s %s second source and destination must be same-width Go 1.27 EVEX registers: %q", c.goarch, baseOp, ins.Raw)
	}
	if properties.rounding != "" && !spec.scalar && byteWidth != 64 {
		return true, false, fmt.Errorf("%s %s packed rounding is available only for Z registers: %q", c.goarch, baseOp, ins.Raw)
	}
	if properties.broadcast {
		if !isAMD64MemoryOperand(ins.Args[0]) {
			return true, false, fmt.Errorf("%s %s.BCST requires a memory first source: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if ins.Args[0].Kind == OpReg {
		if !c.isGoEVEXVectorRegister(ins.Args[0], byteWidth) {
			return true, false, fmt.Errorf("%s %s first source must match the destination width and register class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if properties.rounding != "" {
		return true, false, fmt.Errorf("%s %s explicit rounding requires a register first source: %q", c.goarch, baseOp, ins.Raw)
	} else if !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s %s first source must be a vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	var mask string
	if masked {
		if !amd64NonzeroKOperand(ins.Args[2]) {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		loadedMask, loadErr := c.loadK(ins.Args[2].Reg)
		if loadErr != nil {
			return true, false, loadErr
		}
		mask = loadedMask
	}
	if spec.scalar {
		return c.lowerScalarFMA3(spec, properties, ins, dstArg, mask)
	}
	return c.lowerPackedFMA3(spec, properties, ins, dstArg, byteWidth, mask)
}

func (c *amd64Ctx) lowerPackedFMA3(spec amd64FMA3Spec, properties amd64FMA3Suffix, ins Instr, dstArg Operand, byteWidth int, mask string) (bool, bool, error) {
	lanes := byteWidth * 8 / spec.laneBits
	llvmType := amd64FMA3LLVMType(lanes, spec.laneBits)
	load := func(arg Operand, allowBroadcast bool) (string, error) {
		sourceMask := ""
		if allowBroadcast {
			sourceMask = mask
		}
		bits, err := c.loadMaskedPackedCompareLanes(arg, byteWidth, spec.laneBits, allowBroadcast && properties.broadcast, sourceMask)
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to %s\n", value, lanes, spec.laneBits, bits, llvmType)
		return "%" + value, nil
	}
	first, err := load(ins.Args[0], true)
	if err != nil {
		return true, false, err
	}
	second, err := load(ins.Args[1], false)
	if err != nil {
		return true, false, err
	}
	old, err := load(dstArg, false)
	if err != nil {
		return true, false, err
	}
	computed := c.emitFMA3(spec, llvmType, lanes, first, second, old, properties.rounding)
	if mask != "" {
		computedBits := c.newTmp()
		oldBits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i%d>\n", computedBits, llvmType, computed, lanes, spec.laneBits)
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i%d>\n", oldBits, llvmType, old, lanes, spec.laneBits)
		masked := amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, "%"+computedBits, "%"+oldBits, mask, properties.zeroing)
		back := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to %s\n", back, lanes, spec.laneBits, masked, llvmType)
		computed = "%" + back
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", out, llvmType, computed, byteWidth)
	return true, false, c.storePackedMoveOperand(dstArg, byteWidth, "%"+out)
}

func (c *amd64Ctx) lowerScalarFMA3(spec amd64FMA3Spec, properties amd64FMA3Suffix, ins Instr, dstArg Operand, mask string) (bool, bool, error) {
	first, err := c.loadFMA3Scalar(ins.Args[0], spec.laneBits, mask)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadFMA3Scalar(ins.Args[1], spec.laneBits, "")
	if err != nil {
		return true, false, err
	}
	old, err := c.loadFMA3Scalar(dstArg, spec.laneBits, "")
	if err != nil {
		return true, false, err
	}
	llvmType := amd64FMA3LLVMType(1, spec.laneBits)
	computed := c.emitFMA3(spec, llvmType, 1, first, second, old, properties.rounding)
	destinationBytes, err := c.loadX(dstArg.Reg)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / spec.laneBits
	base := c.bitcastVectorBytesToIntegerLanes(16, lanes, spec.laneBits, destinationBytes)
	bits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to i%d\n", bits, llvmType, computed, spec.laneBits)
	return true, false, c.storeScalarMoveRegister(dstArg.Reg, spec.laneBits, "%"+bits, base, mask, properties.zeroing)
}

func (c *amd64Ctx) loadFMA3Scalar(arg Operand, laneBits int, mask string) (string, error) {
	var bits string
	var err error
	if arg.Kind == OpReg {
		bits, err = c.loadXLowInteger(arg.Reg, laneBits)
	} else if mask != "" {
		bits, err = c.loadVectorScalarMemory(arg, laneBits, mask)
	} else {
		bits, err = c.evalIntSized(arg, amd64IntegerTypeForBits(laneBits))
	}
	if err != nil {
		return "", err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast i%d %s to %s\n", value, laneBits, bits, amd64FMA3LLVMType(1, laneBits))
	return "%" + value, nil
}

func amd64FMA3LLVMType(lanes, laneBits int) string {
	element := "float"
	if laneBits == 16 {
		element = "half"
	} else if laneBits == 64 {
		element = "double"
	}
	if lanes == 1 {
		return element
	}
	return fmt.Sprintf("<%d x %s>", lanes, element)
}

func (c *amd64Ctx) splatFMA3Scalar(lanes, laneBits int, scalar string) string {
	typeName := amd64FMA3LLVMType(lanes, laneBits)
	element := amd64FMA3LLVMType(1, laneBits)
	seed := c.newTmp()
	splat := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement %s poison, %s %s, i32 0\n", seed, typeName, element, scalar)
	fmt.Fprintf(c.b, "  %%%s = shufflevector %s %%%s, %s poison, <%d x i32> zeroinitializer\n", splat, typeName, seed, typeName, lanes)
	return "%" + splat
}

func (c *amd64Ctx) emitFMA3(spec amd64FMA3Spec, llvmType string, lanes int, first, second, old, rounding string) string {
	a, b, addend := old, first, second
	switch spec.order {
	case 213:
		a, b, addend = second, old, first
	case 231:
		a, b, addend = second, first, old
	}
	if spec.mode == amd64FMA3NegAdd || spec.mode == amd64FMA3NegSub {
		negated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", negated, llvmType, a)
		a = "%" + negated
	}
	switch spec.mode {
	case amd64FMA3Sub, amd64FMA3NegSub:
		negated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", negated, llvmType, addend)
		addend = "%" + negated
	case amd64FMA3AddSub, amd64FMA3SubAdd:
		addend = c.alternateFMA3Addend(llvmType, lanes, addend, spec.mode == amd64FMA3AddSub)
	}
	result := c.newTmp()
	intrinsic := amd64FMA3IntrinsicName(lanes, spec.laneBits, rounding != "")
	if rounding == "" {
		fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %s, %s %s, %s %s)\n", result, llvmType, intrinsic, llvmType, a, llvmType, b, llvmType, addend)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %s, %s %s, %s %s, metadata !\"%s\", metadata !\"fpexcept.ignore\")\n", result, llvmType, intrinsic, llvmType, a, llvmType, b, llvmType, addend, amd64FMA3RoundingMetadata(rounding))
	}
	return "%" + result
}

func (c *amd64Ctx) alternateFMA3Addend(llvmType string, lanes int, addend string, negateEven bool) string {
	negated := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fneg %s %s\n", negated, llvmType, addend)
	var mask strings.Builder
	mask.WriteByte('<')
	for lane := 0; lane < lanes; lane++ {
		if lane > 0 {
			mask.WriteString(", ")
		}
		selected := lane%2 == 0
		if !negateEven {
			selected = !selected
		}
		fmt.Fprintf(&mask, "i1 %t", selected)
	}
	mask.WriteByte('>')
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %s, %s %%%s, %s %s\n", result, lanes, mask.String(), llvmType, negated, llvmType, addend)
	return "%" + result
}

func amd64FMA3IntrinsicName(lanes, laneBits int, constrained bool) string {
	prefix := "llvm.fma."
	if constrained {
		prefix = "llvm.experimental.constrained.fma."
	}
	suffix := "f32"
	if laneBits == 16 {
		suffix = "f16"
	} else if laneBits == 64 {
		suffix = "f64"
	}
	if lanes > 1 {
		suffix = fmt.Sprintf("v%d%s", lanes, suffix)
	}
	return prefix + suffix
}

func amd64FMA3RoundingMetadata(rounding string) string {
	switch rounding {
	case "RD_SAE":
		return "round.downward"
	case "RU_SAE":
		return "round.upward"
	case "RZ_SAE":
		return "round.towardzero"
	default:
		return "round.tonearest"
	}
}
