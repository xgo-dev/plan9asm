package plan9asm

import (
	"fmt"
	"strings"
)

type amd64SingleSourceNarrowSpec struct {
	inputBits  int
	outputBits int
	saturating bool
	mode       amd64PackedNarrowMode
}

var amd64SingleSourceNarrowSpecs = map[string]amd64SingleSourceNarrowSpec{
	"VPMOVDB":   {inputBits: 32, outputBits: 8},
	"VPMOVDW":   {inputBits: 32, outputBits: 16},
	"VPMOVQB":   {inputBits: 64, outputBits: 8},
	"VPMOVQD":   {inputBits: 64, outputBits: 32},
	"VPMOVQW":   {inputBits: 64, outputBits: 16},
	"VPMOVWB":   {inputBits: 16, outputBits: 8},
	"VPMOVSDB":  {inputBits: 32, outputBits: 8, saturating: true, mode: amd64PackedNarrowSigned},
	"VPMOVSDW":  {inputBits: 32, outputBits: 16, saturating: true, mode: amd64PackedNarrowSigned},
	"VPMOVSQB":  {inputBits: 64, outputBits: 8, saturating: true, mode: amd64PackedNarrowSigned},
	"VPMOVSQD":  {inputBits: 64, outputBits: 32, saturating: true, mode: amd64PackedNarrowSigned},
	"VPMOVSQW":  {inputBits: 64, outputBits: 16, saturating: true, mode: amd64PackedNarrowSigned},
	"VPMOVSWB":  {inputBits: 16, outputBits: 8, saturating: true, mode: amd64PackedNarrowSigned},
	"VPMOVUSDB": {inputBits: 32, outputBits: 8, saturating: true, mode: amd64PackedNarrowUnsigned},
	"VPMOVUSDW": {inputBits: 32, outputBits: 16, saturating: true, mode: amd64PackedNarrowUnsigned},
	"VPMOVUSQB": {inputBits: 64, outputBits: 8, saturating: true, mode: amd64PackedNarrowUnsigned},
	"VPMOVUSQD": {inputBits: 64, outputBits: 32, saturating: true, mode: amd64PackedNarrowUnsigned},
	"VPMOVUSQW": {inputBits: 64, outputBits: 16, saturating: true, mode: amd64PackedNarrowUnsigned},
	"VPMOVUSWB": {inputBits: 16, outputBits: 8, saturating: true, mode: amd64PackedNarrowUnsigned},
}

// lowerSingleSourceIntegerNarrow implements the complete Go 1.27
// _yvpmovdb/_yvpmovdw family: truncating, signed-saturating, and
// signed-to-unsigned-saturating conversions from X/Y/Z into X/Y or memory.
func (c *amd64Ctx) lowerSingleSourceIntegerNarrow(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, handled := amd64SingleSourceNarrowSpecs[baseOp]
	if !handled {
		return false, false, nil
	}
	if suffix != "" && suffix != "Z" {
		return true, false, fmt.Errorf("%s %s suffix is absent from Go 1.27's _yvpmovdb/_yvpmovdw tables: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("%s %s expects vector source, [K1-K7 mask,] vector or memory destination: %q", c.goarch, baseOp, ins.Raw)
	}

	source := ins.Args[0]
	inputBytes := amd64VectorByteWidth(source.Reg)
	if source.Kind != OpReg || inputBytes != 16 && inputBytes != 32 && inputBytes != 64 || !c.isGoEVEXVectorRegister(source, inputBytes) {
		return true, false, fmt.Errorf("%s %s source must be an in-range X, Y, or Z register: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 3
	if suffix == "Z" && !masked {
		return true, false, fmt.Errorf("%s %s.Z requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	var mask string
	if masked {
		maskArg := ins.Args[1]
		if maskArg.Kind != OpReg {
			return true, false, fmt.Errorf("%s %s masked form expects K1-K7: %q", c.goarch, baseOp, ins.Raw)
		}
		index, valid := amd64ParseKReg(maskArg.Reg)
		if !valid || index == 0 {
			return true, false, fmt.Errorf("%s %s masked form expects K1-K7: %q", c.goarch, baseOp, ins.Raw)
		}
		mask, err = c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
	}
	destination := ins.Args[len(ins.Args)-1]
	lanes := inputBytes * 8 / spec.inputBits
	outputBytes := lanes * spec.outputBits / 8
	destinationBytes := 16
	if outputBytes > 16 {
		destinationBytes = 32
	}
	if destination.Kind == OpReg {
		if amd64VectorByteWidth(destination.Reg) != destinationBytes || !c.isGoEVEXVectorRegister(destination, destinationBytes) {
			return true, false, fmt.Errorf("%s %s destination must be an in-range %s register for a %s source: %q", c.goarch, baseOp, map[int]string{16: "X", 32: "Y"}[destinationBytes], strings.ToUpper(string(source.Reg))[0:1], ins.Raw)
		}
	} else if !isAMD64MemoryOperand(destination) {
		return true, false, fmt.Errorf("%s %s destination must be the matching X/Y register or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	sourceBytes, err := c.loadPackedCompareBytes(source, inputBytes)
	if err != nil {
		return true, false, err
	}
	sourceLanes := c.bitcastVectorBytesToIntegerLanes(inputBytes, lanes, spec.inputBits, sourceBytes)
	narrowed := c.emitSingleSourceIntegerNarrow(spec, lanes, sourceLanes)
	zeroing := suffix == "Z"
	if destination.Kind == OpReg {
		return true, false, c.storeSingleSourceNarrowRegister(destination.Reg, destinationBytes, lanes, spec.outputBits, narrowed, mask, zeroing)
	}
	return true, false, c.storeSingleSourceNarrowMemory(destination, outputBytes, lanes, spec.outputBits, narrowed, mask, zeroing)
}

func (c *amd64Ctx) emitSingleSourceIntegerNarrow(spec amd64SingleSourceNarrowSpec, lanes int, source string) string {
	inputType := fmt.Sprintf("<%d x i%d>", lanes, spec.inputBits)
	outputType := fmt.Sprintf("<%d x i%d>", lanes, spec.outputBits)
	if !spec.saturating {
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", result, inputType, source, outputType)
		return "%" + result
	}
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", value, inputType, source, lane)
		narrowed := c.saturatePackedInteger("%"+value, spec.inputBits, spec.outputBits, spec.mode)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %s, i32 %d\n", inserted, outputType, result, spec.outputBits, narrowed, lane)
		result = "%" + inserted
	}
	return result
}

func (c *amd64Ctx) storeSingleSourceNarrowRegister(destination Reg, destinationBytes, lanes, outputBits int, narrowed, mask string, zeroing bool) error {
	physicalLanes := destinationBytes * 8 / outputBits
	result := "zeroinitializer"
	var old string
	if mask != "" && !zeroing {
		oldBytes, err := c.loadPackedCompareBytes(Operand{Kind: OpReg, Reg: destination}, destinationBytes)
		if err != nil {
			return err
		}
		old = c.bitcastVectorBytesToIntegerLanes(destinationBytes, physicalLanes, outputBits, oldBytes)
	}
	for lane := 0; lane < lanes; lane++ {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", value, lanes, outputBits, narrowed, lane)
		selected := "%" + value
		if mask != "" {
			fallback := "0"
			if !zeroing {
				oldValue := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", oldValue, physicalLanes, outputBits, old, lane)
				fallback = "%" + oldValue
			}
			masked := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %s, i%d %s\n", masked, amd64MaskBitI1(c, mask, lane), outputBits, selected, outputBits, fallback)
			selected = "%" + masked
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %s, i32 %d\n", inserted, physicalLanes, outputBits, result, outputBits, selected, lane)
		result = "%" + inserted
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, physicalLanes, outputBits, result, destinationBytes)
	return c.storeVectorBytes(destination, destinationBytes, "%"+out)
}

func (c *amd64Ctx) storeSingleSourceNarrowMemory(destination Operand, outputBytes, lanes, outputBits int, narrowed, mask string, zeroing bool) error {
	result := narrowed
	if mask != "" {
		var old string
		if !zeroing {
			oldBytes, err := c.loadNarrowMemoryBytes(destination, outputBytes)
			if err != nil {
				return err
			}
			old = c.bitcastVectorBytesToIntegerLanes(outputBytes, lanes, outputBits, oldBytes)
		}
		result = "poison"
		for lane := 0; lane < lanes; lane++ {
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", value, lanes, outputBits, narrowed, lane)
			fallback := "0"
			if !zeroing {
				oldValue := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", oldValue, lanes, outputBits, old, lane)
				fallback = "%" + oldValue
			}
			selected := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %%%s, i%d %s\n", selected, amd64MaskBitI1(c, mask, lane), outputBits, value, outputBits, fallback)
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %%%s, i32 %d\n", inserted, lanes, outputBits, result, outputBits, selected, lane)
			result = "%" + inserted
		}
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, outputBits, result, outputBytes)
	return c.storeNarrowMemoryBytes(destination, outputBytes, "%"+out)
}

func (c *amd64Ctx) loadNarrowMemoryBytes(source Operand, byteWidth int) (string, error) {
	if byteWidth >= 16 {
		return c.loadPackedCompareBytes(source, byteWidth)
	}
	typ := amd64IntegerTypeForBits(byteWidth * 8)
	value, err := c.evalIntSized(source, typ)
	if err != nil {
		return "", err
	}
	bytesValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", bytesValue, typ, value, byteWidth)
	return "%" + bytesValue, nil
}

func (c *amd64Ctx) storeNarrowMemoryBytes(destination Operand, byteWidth int, value string) error {
	if byteWidth >= 16 {
		return c.storeVectorBytesOperand(destination, byteWidth, value)
	}
	typ := amd64IntegerTypeForBits(byteWidth * 8)
	integer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", integer, byteWidth, value, typ)
	return c.storeVectorScalarMemory(destination, byteWidth*8, "%"+integer, "")
}
