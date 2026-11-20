package plan9asm

import (
	"fmt"
	"math"
	"strings"
)

type arm64SVEFloatUnarySpec struct {
	intrinsic   string
	unpred      bool
	sdOnly      bool
	integerBits int
	fptoint     bool
	rawBase     uint32
	rawZeroBase uint32
}

var arm64SVEFloatUnarySpecs = map[Op]arm64SVEFloatUnarySpec{
	"ZFABS":     {intrinsic: "fabs", rawBase: 0x041ca000, rawZeroBase: 0x040ca000},
	"ZFNEG":     {intrinsic: "fneg", rawBase: 0x041da000, rawZeroBase: 0x040da000},
	"ZFRECPE":   {intrinsic: "frecpe.x", unpred: true, rawBase: 0x650e3000},
	"ZFRECPX":   {intrinsic: "frecpx", rawBase: 0x650ca000, rawZeroBase: 0x641b8000},
	"ZFRINT32X": {intrinsic: "rint", sdOnly: true, integerBits: 32, fptoint: true, rawBase: 0x6511a000, rawZeroBase: 0x641ca000},
	"ZFRINT32Z": {intrinsic: "trunc", sdOnly: true, integerBits: 32, fptoint: true, rawBase: 0x6510a000, rawZeroBase: 0x641c8000},
	"ZFRINT64X": {intrinsic: "rint", sdOnly: true, integerBits: 64, fptoint: true, rawBase: 0x6515a000, rawZeroBase: 0x641da000},
	"ZFRINT64Z": {intrinsic: "trunc", sdOnly: true, integerBits: 64, fptoint: true, rawBase: 0x6514a000, rawZeroBase: 0x641d8000},
	"ZFRINTA":   {intrinsic: "frinta", rawBase: 0x6504a000, rawZeroBase: 0x64198000},
	"ZFRINTI":   {intrinsic: "frinti", rawBase: 0x6507a000, rawZeroBase: 0x6419e000},
	"ZFRINTM":   {intrinsic: "frintm", rawBase: 0x6502a000, rawZeroBase: 0x6418c000},
	"ZFRINTN":   {intrinsic: "frintn", rawBase: 0x6500a000, rawZeroBase: 0x64188000},
	"ZFRINTP":   {intrinsic: "frintp", rawBase: 0x6501a000, rawZeroBase: 0x6418a000},
	"ZFRINTX":   {intrinsic: "frintx", rawBase: 0x6506a000, rawZeroBase: 0x6419c000},
	"ZFRINTZ":   {intrinsic: "frintz", rawBase: 0x6503a000, rawZeroBase: 0x6418e000},
	"ZFRSQRTE":  {intrinsic: "frsqrte.x", unpred: true, rawBase: 0x650f3000},
	"ZFSQRT":    {intrinsic: "fsqrt", rawBase: 0x650da000, rawZeroBase: 0x641ba000},
}

// The opcode bases and operand fields are the complete Go 1.27 unary family.
// Named and raw forms share one spec, including predication and sized rounding.
func decodeARM64RawSVEFloatUnary(word uint32) (Instr, bool) {
	size := word >> 22 & 3
	for op, spec := range arm64SVEFloatUnarySpecs {
		if !spec.sdOnly && size == 0 {
			continue
		}
		mask, zeroMask := uint32(0x00c01fff), uint32(0x00c01fff)
		if spec.unpred {
			mask = 0x00c003ff
		} else if spec.sdOnly {
			// Go's SzSD1718 and SzSD1415 put the S/D selector in
			// different positions for merging and zeroing encodings.
			mask, zeroMask = 0x00021fff, 0x00005fff
		}
		zero := !spec.unpred && word&^zeroMask == spec.rawZeroBase
		if !zero && word&^mask != spec.rawBase {
			continue
		}
		width := "BHSD"[size]
		if spec.sdOnly {
			shift := uint(17)
			if zero {
				shift = 14
			}
			width = "SD"[word>>shift&1]
		}
		args := []Operand{{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word>>5&31, width))}}
		if !spec.unpred {
			mode := "M"
			if zero {
				mode = "Z"
			}
			args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.%s", word>>10&7, mode))})
		}
		args = append(args, Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", word&31, width))})
		return Instr{Op: op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
	}
	return Instr{}, false
}

type arm64SVEFloatUnaryForm struct {
	elementBits int
	source      int
	predicate   int
	destination int
	zeroing     bool
}

func (c *arm64Ctx) lowerARM64SVEFloatUnary(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEFloatUnarySpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept an instruction suffix: %q", op, ins.Raw)
	}
	form := arm64SVEFloatUnaryForm{}
	if spec.unpred {
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 %s expects Zn.T, Zd.T: %q", op, ins.Raw)
		}
		source, sourceBits, sourceOK := arm64SVEFloatElementReg(ins.Args[0])
		destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[1])
		if !sourceOK || !destinationOK || sourceBits != destinationBits {
			return true, false, fmt.Errorf("arm64 %s requires matching H, S, or D vector widths: %q", op, ins.Raw)
		}
		form = arm64SVEFloatUnaryForm{elementBits: sourceBits, source: source, destination: destination}
	} else {
		if len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 %s expects Zn.T, Pg/M|Z, Zd.T: %q", op, ins.Raw)
		}
		source, sourceBits, sourceOK := arm64SVEFloatElementReg(ins.Args[0])
		destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[2])
		predicate, mergeOK := arm64ParseSVEPredicateMode(ins.Args[1], "M", 7)
		if !mergeOK {
			predicate, form.zeroing = 0, true
			var zeroOK bool
			predicate, zeroOK = arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7)
			if !zeroOK {
				return true, false, fmt.Errorf("arm64 %s requires P0..P7/M or P0..P7/Z: %q", op, ins.Raw)
			}
		}
		if !sourceOK || !destinationOK || sourceBits != destinationBits || (spec.sdOnly && sourceBits == 16) {
			return true, false, fmt.Errorf("arm64 %s vector widths do not match its Go 1.27 form: %q", op, ins.Raw)
		}
		form.elementBits = sourceBits
		form.source = source
		form.predicate = predicate
		form.destination = destination
	}
	return true, false, c.lowerARM64SVEFloatUnaryForm(spec, form)
}

func (c *arm64Ctx) lowerARM64SVEFloatUnaryForm(spec arm64SVEFloatUnarySpec, form arm64SVEFloatUnaryForm) error {
	source, vectorType, err := c.loadRawSVEFloatVector(form.source, form.elementBits)
	if err != nil {
		return err
	}
	_, _, lanes, err := arm64SVEFloatType(form.elementBits)
	if err != nil {
		return err
	}
	mangle := fmt.Sprintf("nxv%d%s", lanes, map[int]string{16: "f16", 32: "f32", 64: "f64"}[form.elementBits])
	if spec.integerBits != 0 {
		calculated, err := c.lowerARM64SVEFRIntSized(spec, source, vectorType, mangle, lanes, form.elementBits)
		if err != nil {
			return err
		}
		predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
		if err != nil {
			return err
		}
		inactive := "zeroinitializer"
		if !form.zeroing {
			inactive, _, err = c.loadRawSVEFloatVector(form.destination, form.elementBits)
			if err != nil {
				return err
			}
		}
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select %s %s, %s %s, %s %s\n", selected, predicateType, predicate, vectorType, calculated, vectorType, inactive)
		return c.storeRawSVEFloatVector(form.destination, form.elementBits, "%"+selected, vectorType)
	}
	result := c.newTmp()
	if spec.unpred {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.%s(%s %s)\n", result, vectorType, spec.intrinsic, mangle, vectorType, source)
	} else {
		predicate, predicateType, err := c.loadPRegElements(form.predicate, form.elementBits)
		if err != nil {
			return err
		}
		merge := source
		if !form.zeroing {
			merge, _, err = c.loadRawSVEFloatVector(form.destination, form.elementBits)
			if err != nil {
				return err
			}
		}
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.%s(%s %s, %s %s, %s %s)\n", result, vectorType, spec.intrinsic, mangle, vectorType, merge, predicateType, predicate, vectorType, source)
		if form.zeroing {
			integerType, _, err := arm64SVEVectorType(form.elementBits)
			if err != nil {
				return err
			}
			bits := c.newTmp()
			mask := c.newTmp()
			zeroed := c.newTmp()
			converted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", bits, vectorType, result, integerType)
			fmt.Fprintf(c.b, "  %%%s = sext %s %s to %s\n", mask, predicateType, predicate, integerType)
			fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", zeroed, integerType, bits, mask)
			fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to %s\n", converted, integerType, zeroed, vectorType)
			result = converted
		}
	}
	return c.storeRawSVEFloatVector(form.destination, form.elementBits, "%"+result, vectorType)
}

func (c *arm64Ctx) lowerARM64SVEFRIntSized(spec arm64SVEFloatUnarySpec, source, vectorType, mangle string, lanes, elementBits int) (string, error) {
	rounded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %s)\n", rounded, vectorType, spec.intrinsic, mangle, vectorType, source)
	integerType := fmt.Sprintf("<vscale x %d x i%d>", lanes, spec.integerBits)
	integers := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.fptosi.sat.nxv%di%d.%s(%s %%%s)\n", integers, integerType, lanes, spec.integerBits, mangle, vectorType, rounded)
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sitofp %s %%%s to %s\n", converted, integerType, integers, vectorType)
	minimum := -math.Ldexp(1, spec.integerBits-1)
	upper := math.Ldexp(1, spec.integerBits-1)
	minimumVector, err := c.arm64SVEFloatSplat(minimum, elementBits)
	if err != nil {
		return "", err
	}
	upperVector, err := c.arm64SVEFloatSplat(upper, elementBits)
	if err != nil {
		return "", err
	}
	geMinimum := c.newTmp()
	belowUpper := c.newTmp()
	valid := c.newTmp()
	fixed := c.newTmp()
	predicateType := fmt.Sprintf("<vscale x %d x i1>", lanes)
	fmt.Fprintf(c.b, "  %%%s = fcmp oge %s %%%s, %s\n", geMinimum, vectorType, rounded, minimumVector)
	fmt.Fprintf(c.b, "  %%%s = fcmp olt %s %%%s, %s\n", belowUpper, vectorType, rounded, upperVector)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", valid, predicateType, geMinimum, belowUpper)
	fmt.Fprintf(c.b, "  %%%s = select %s %%%s, %s %%%s, %s %s\n", fixed, predicateType, valid, vectorType, converted, vectorType, minimumVector)
	return "%" + fixed, nil
}
