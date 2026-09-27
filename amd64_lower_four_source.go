package plan9asm

import (
	"fmt"
	"strings"
)

type amd64FourSourceMode uint8

const (
	amd64FourSourceFMA amd64FourSourceMode = iota
	amd64FourSourceDotWords
)

type amd64FourSourceSpec struct {
	mode       amd64FourSourceMode
	scalar     bool
	negative   bool
	saturating bool
}

// amd64FourSourceSpecs is the complete Go 1.27 AVX512_4FMAPS/AVX512_4VNNIW
// grammar. The opcode table records only semantic axes; memory, a consecutive
// four-register range, optional K mask, zeroing, and architecture rules are
// parsed once below.
var amd64FourSourceSpecs = map[Op]amd64FourSourceSpec{
	"V4FMADDPS":  {mode: amd64FourSourceFMA},
	"V4FMADDSS":  {mode: amd64FourSourceFMA, scalar: true},
	"V4FNMADDPS": {mode: amd64FourSourceFMA, negative: true},
	"V4FNMADDSS": {mode: amd64FourSourceFMA, scalar: true, negative: true},
	"VP4DPWSSD":  {mode: amd64FourSourceDotWords},
	"VP4DPWSSDS": {mode: amd64FourSourceDotWords, saturating: true},
}

type amd64FourSourceForm struct {
	memory      Operand
	sourceBase  int
	destination Operand
	mask        string
	zeroing     bool
}

func (c *amd64Ctx) lowerFourSource(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64FourSourceSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	form, err := c.parseFourSourceForm(baseOp, suffix, spec, ins)
	if err != nil {
		return true, false, err
	}
	if spec.mode == amd64FourSourceFMA {
		return c.lowerFourSourceFMA(spec, form)
	}
	return c.lowerFourSourceDotWords(spec, form)
}

func (c *amd64Ctx) parseFourSourceForm(baseOp, suffix string, spec amd64FourSourceSpec, ins Instr) (amd64FourSourceForm, error) {
	var form amd64FourSourceForm
	if suffix != "" && suffix != "Z" {
		return form, fmt.Errorf("%s %s has a suffix absent from Go 1.27's four-source tables: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return form, fmt.Errorf("%s %s expects memory, four-register range, [K1-K7,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked {
		return form, fmt.Errorf("386 %s mask forms exceed the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if suffix == "Z" && !masked {
		return form, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	if !isAMD64MemoryOperand(ins.Args[0]) {
		return form, fmt.Errorf("%s %s first source must be 16-byte memory: %q", c.goarch, baseOp, ins.Raw)
	}
	if ins.Args[0].Kind == OpMem && !x86MemoryRegistersValidForArch(ins.Args[0].Mem, c.goarch) {
		return form, fmt.Errorf("%s %s memory source uses an out-of-range address register: %q", c.goarch, baseOp, ins.Raw)
	}

	width := 64
	if spec.scalar {
		width = 16
	}
	rangeOperand := ins.Args[1]
	if rangeOperand.Kind != OpRegList || !rangeOperand.RegListRange || len(rangeOperand.RegList) != 4 {
		return form, fmt.Errorf("%s %s second source must be one consecutive four-register range: %q", c.goarch, baseOp, ins.Raw)
	}
	first := -1
	for index, register := range rangeOperand.RegList {
		registerIndex, valid := amd64VectorRegisterIndex(register, width)
		if !valid || c.goarch == "386" && registerIndex >= 8 || index != 0 && registerIndex != first+index {
			return form, fmt.Errorf("%s %s source range is outside Go 1.27's four-register class: %q", c.goarch, baseOp, ins.Raw)
		}
		if index == 0 {
			first = registerIndex
		}
	}

	destination := ins.Args[len(ins.Args)-1]
	destinationIndex, valid := amd64VectorRegisterIndex(destination.Reg, width)
	if destination.Kind != OpReg || !valid || c.goarch == "386" && destinationIndex >= 8 {
		return form, fmt.Errorf("%s %s destination must be an in-range %s register: %q", c.goarch, baseOp, map[bool]string{true: "X", false: "Z"}[spec.scalar], ins.Raw)
	}
	mask := ""
	if masked {
		if !amd64NonzeroKOperand(ins.Args[2]) {
			return form, fmt.Errorf("%s %s masked form expects K1-K7: %q", c.goarch, baseOp, ins.Raw)
		}
		loadedMask, loadErr := c.loadK(ins.Args[2].Reg)
		if loadErr != nil {
			return form, loadErr
		}
		mask = loadedMask
	}

	// The hardware ignores the low two encoded source-register bits. Preserve
	// that behavior for Go spellings such as [Z10-Z13], which the assembler
	// accepts even though the architectural block begins at Z8.
	return amd64FourSourceForm{
		memory: ins.Args[0], sourceBase: first &^ 3, destination: destination,
		mask: mask, zeroing: suffix == "Z",
	}, nil
}

func (c *amd64Ctx) lowerFourSourceFMA(spec amd64FourSourceSpec, form amd64FourSourceForm) (bool, bool, error) {
	activeMaskBits := 16
	if spec.scalar {
		activeMaskBits = 1
	}
	memoryBits, err := c.loadFourSourceMemoryI32(form, activeMaskBits)
	if err != nil {
		return true, false, err
	}
	memoryName := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %s to <4 x float>\n", memoryName, memoryBits)
	memory := "%" + memoryName
	if spec.scalar {
		return c.lowerFourSourceScalarFMA(spec, form, memory)
	}

	accumulator, err := c.loadFloatingVectorOperand(form.destination, 64, 16, 32)
	if err != nil {
		return true, false, err
	}
	original := accumulator
	for sourceIndex := 0; sourceIndex < 4; sourceIndex++ {
		sourceReg := Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d", form.sourceBase+sourceIndex))}
		source, loadErr := c.loadFloatingVectorOperand(sourceReg, 64, 16, 32)
		if loadErr != nil {
			return true, false, loadErr
		}
		factor := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <4 x float> %s, i32 %d\n", factor, memory, sourceIndex)
		factors := c.splatFMA3Scalar(16, 32, "%"+factor)
		if spec.negative {
			negated := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fneg <16 x float> %s\n", negated, source)
			source = "%" + negated
		}
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <16 x float> @llvm.fma.v16f32(<16 x float> %s, <16 x float> %s, <16 x float> %s)\n", result, source, factors, accumulator)
		accumulator = "%" + result
	}
	if form.mask != "" {
		computedBits := c.newTmp()
		originalBits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x float> %s to <16 x i32>\n", computedBits, accumulator)
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x float> %s to <16 x i32>\n", originalBits, original)
		masked := amd64ApplyI32LaneMask(c, 16, "%"+computedBits, "%"+originalBits, form.mask, form.zeroing)
		back := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i32> %s to <16 x float>\n", back, masked)
		accumulator = "%" + back
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x float> %s to <64 x i8>\n", out, accumulator)
	return true, false, c.storeZ(form.destination.Reg, "%"+out)
}

func (c *amd64Ctx) lowerFourSourceScalarFMA(spec amd64FourSourceSpec, form amd64FourSourceForm, memory string) (bool, bool, error) {
	accumulator, err := c.loadXLowF32(form.destination.Reg)
	if err != nil {
		return true, false, err
	}
	original := accumulator
	for sourceIndex := 0; sourceIndex < 4; sourceIndex++ {
		sourceReg := Reg(fmt.Sprintf("X%d", form.sourceBase+sourceIndex))
		source, loadErr := c.loadXLowF32(sourceReg)
		if loadErr != nil {
			return true, false, loadErr
		}
		if spec.negative {
			negated := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = fneg float %s\n", negated, source)
			source = "%" + negated
		}
		factor := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <4 x float> %s, i32 %d\n", factor, memory, sourceIndex)
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call float @llvm.fma.f32(float %s, float %%%s, float %s)\n", result, source, factor, accumulator)
		accumulator = "%" + result
	}
	if form.mask != "" {
		bit := amd64MaskBitI1(c, form.mask, 0)
		fallback := original
		if form.zeroing {
			fallback = "0.000000e+00"
		}
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %s, float %s, float %s\n", selected, bit, accumulator, fallback)
		accumulator = "%" + selected
	}
	destination, err := c.loadX(form.destination.Reg)
	if err != nil {
		return true, false, err
	}
	words := c.newTmp()
	bits := c.newTmp()
	inserted := c.newTmp()
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", words, destination)
	fmt.Fprintf(c.b, "  %%%s = bitcast float %s to i32\n", bits, accumulator)
	fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> %%%s, i32 %%%s, i32 0\n", inserted, words, bits)
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", out, inserted)
	return true, false, c.storeX(form.destination.Reg, "%"+out)
}

func (c *amd64Ctx) lowerFourSourceDotWords(spec amd64FourSourceSpec, form amd64FourSourceForm) (bool, bool, error) {
	memoryDwords, err := c.loadFourSourceMemoryI32(form, 16)
	if err != nil {
		return true, false, err
	}
	memoryName := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %s to <8 x i16>\n", memoryName, memoryDwords)
	memory := "%" + memoryName
	destinationBytes, err := c.loadZ(form.destination.Reg)
	if err != nil {
		return true, false, err
	}
	original := c.bitcastVectorBytesToIntegerLanes(64, 16, 32, destinationBytes)
	accumulator := original
	for sourceIndex := 0; sourceIndex < 4; sourceIndex++ {
		sourceReg := Reg(fmt.Sprintf("Z%d", form.sourceBase+sourceIndex))
		sourceBytes, loadErr := c.loadZ(sourceReg)
		if loadErr != nil {
			return true, false, loadErr
		}
		source := c.bitcastVectorBytesToIntegerLanes(64, 32, 16, sourceBytes)
		accumulator = c.emitFourSourceDotStep(accumulator, source, memory, sourceIndex, spec.saturating)
	}
	if form.mask != "" {
		accumulator = amd64ApplyI32LaneMask(c, 16, accumulator, original, form.mask, form.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i32> %s to <64 x i8>\n", out, accumulator)
	return true, false, c.storeZ(form.destination.Reg, "%"+out)
}

func (c *amd64Ctx) loadFourSourceMemoryI32(form amd64FourSourceForm, activeMaskBits int) (string, error) {
	if form.mask == "" {
		bytes, err := c.loadPackedCompareBytes(form.memory, 16)
		if err != nil {
			return "", err
		}
		return c.bitcastVectorBytesToIntegerLanes(16, 4, 32, bytes), nil
	}
	masked := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", masked, form.mask, (uint64(1)<<activeMaskBits)-1)
	active := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", active, masked)
	seed := c.newTmp()
	predicate := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i1> poison, i1 %%%s, i32 0\n", seed, active)
	fmt.Fprintf(c.b, "  %%%s = shufflevector <4 x i1> %%%s, <4 x i1> poison, <4 x i32> zeroinitializer\n", predicate, seed)
	pointer, pointerType, intrinsicSuffix, err := c.packedVectorMemoryPointer(form.memory)
	if err != nil {
		return "", err
	}
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <4 x i32> @llvm.masked.load.v4i32%s(%s align 1 %s, <4 x i1> %%%s, <4 x i32> zeroinitializer)\n",
		loaded, intrinsicSuffix, pointerType, pointer, predicate)
	return "%" + loaded, nil
}

func (c *amd64Ctx) emitFourSourceDotStep(accumulator, source, memory string, sourceIndex int, saturating bool) string {
	result := "poison"
	for lane := 0; lane < 16; lane++ {
		accumulatorLane := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <16 x i32> %s, i32 %d\n", accumulatorLane, accumulator, lane)
		total := ""
		if saturating {
			wide := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext i32 %%%s to i64\n", wide, accumulatorLane)
			total = "%" + wide
		} else {
			total = "%" + accumulatorLane
		}
		for word := 0; word < 2; word++ {
			sourceLane := c.newTmp()
			memoryLane := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <32 x i16> %s, i32 %d\n", sourceLane, source, lane*2+word)
			fmt.Fprintf(c.b, "  %%%s = extractelement <8 x i16> %s, i32 %d\n", memoryLane, memory, sourceIndex*2+word)
			wideSource := c.newTmp()
			wideMemory := c.newTmp()
			bits := 32
			if saturating {
				bits = 64
			}
			fmt.Fprintf(c.b, "  %%%s = sext i16 %%%s to i%d\n", wideSource, sourceLane, bits)
			fmt.Fprintf(c.b, "  %%%s = sext i16 %%%s to i%d\n", wideMemory, memoryLane, bits)
			product := c.newTmp()
			next := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = mul i%d %%%s, %%%s\n", product, bits, wideSource, wideMemory)
			fmt.Fprintf(c.b, "  %%%s = add i%d %s, %%%s\n", next, bits, total, product)
			total = "%" + next
		}
		if saturating {
			total = c.saturateFourSourceI64ToI32(total)
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <16 x i32> %s, i32 %s, i32 %d\n", inserted, result, total, lane)
		result = "%" + inserted
	}
	return result
}

func (c *amd64Ctx) saturateFourSourceI64ToI32(value string) string {
	above := c.newTmp()
	capped := c.newTmp()
	below := c.newTmp()
	bounded := c.newTmp()
	narrowed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp sgt i64 %s, 2147483647\n", above, value)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 2147483647, i64 %s\n", capped, above, value)
	fmt.Fprintf(c.b, "  %%%s = icmp slt i64 %%%s, -2147483648\n", below, capped)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 -2147483648, i64 %%%s\n", bounded, below, capped)
	fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i32\n", narrowed, bounded)
	return "%" + narrowed
}
