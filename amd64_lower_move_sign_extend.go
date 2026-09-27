package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedExtendMove struct {
	inputBits  int
	outputBits int
	vector     bool
	zeroExtend bool
}

// lowerPackedExtendMove implements all six signed and all six unsigned legacy
// and vector widening instructions exposed by Go 1.27. Ratio-two V forms use
// _yvcvtdq2pd; ratio-four and ratio-eight forms use _yvbroadcastss.
func (c *amd64Ctx) lowerPackedExtendMove(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	properties, ok := amd64PackedExtendMoveProperties(baseOp)
	if !ok {
		return false, false, nil
	}
	zeroing := false
	switch suffix {
	case "":
	case "Z":
		zeroing = true
	default:
		return true, false, fmt.Errorf("%s %s %s suffix is absent from Go 1.27's widening-move encodings: %q", c.goarch, baseOp, suffix, ins.Raw)
	}
	if !properties.vector && suffix != "" {
		return true, false, fmt.Errorf("%s %s legacy yxm_q4 form does not accept suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	wantArgs := 2
	if len(ins.Args) == 3 {
		wantArgs = 3
	}
	if len(ins.Args) != wantArgs || (!properties.vector && len(ins.Args) != 2) {
		return true, false, fmt.Errorf("%s %s expects source, [K mask,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 3
	if zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("%s %s masked form expects K1-K7 in the middle: %q", c.goarch, baseOp, ins.Raw)
	}

	src := ins.Args[0]
	dst := ins.Args[len(ins.Args)-1]
	if dst.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s destination must be a vector register: %q", c.goarch, baseOp, ins.Raw)
	}
	outputBytes := amd64VectorByteWidth(dst.Reg)
	if properties.vector {
		if !c.isGoPackedExtendDestination(dst, outputBytes) {
			return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's EVEX vector range: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if outputBytes != 16 || !c.isGoLegacyPackedExtendX(dst) {
		return true, false, fmt.Errorf("%s %s legacy destination must be an in-range X register: %q", c.goarch, baseOp, ins.Raw)
	}

	sourceRegisterBytes := 16
	if properties.vector && outputBytes == 64 && properties.outputBits == properties.inputBits*2 {
		sourceRegisterBytes = 32
	}
	if src.Kind == OpReg {
		if properties.vector {
			if !amd64EVEXVectorRegister(src, sourceRegisterBytes) {
				return true, false, fmt.Errorf("%s %s source register width does not match its Go 1.27 table: %q", c.goarch, baseOp, ins.Raw)
			}
		} else if !c.isGoLegacyPackedExtendX(src) {
			return true, false, fmt.Errorf("%s %s legacy source must be an in-range X register or memory: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(src) {
		return true, false, fmt.Errorf("%s %s source must be the table's vector register class or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	lanes := outputBytes * 8 / properties.outputBits
	inputs, err := c.loadPackedExtendInputs(src, sourceRegisterBytes, lanes, properties.inputBits)
	if err != nil {
		return true, false, err
	}
	result := "zeroinitializer"
	for lane := 0; lane < lanes; lane++ {
		input := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", input, lanes, properties.inputBits, inputs, lane)
		extended := c.newTmp()
		extension := "sext"
		if properties.zeroExtend {
			extension = "zext"
		}
		fmt.Fprintf(c.b, "  %%%s = %s i%d %%%s to i%d\n", extended, extension, properties.inputBits, input, properties.outputBits)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %%%s, i32 %d\n", inserted, lanes, properties.outputBits, result, properties.outputBits, extended, lane)
		result = "%" + inserted
	}
	if masked {
		mask, err := c.loadK(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		oldBytes, err := c.loadPackedCompareBytes(dst, outputBytes)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(outputBytes, lanes, properties.outputBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, properties.outputBits, result, old, mask, zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, properties.outputBits, result, outputBytes)
	return true, false, c.storeVectorBytes(dst.Reg, outputBytes, "%"+out)
}

func amd64PackedExtendMoveProperties(op string) (amd64PackedExtendMove, bool) {
	vector := strings.HasPrefix(op, "V")
	properties := amd64PackedExtendMove{vector: vector, zeroExtend: strings.Contains(op, "MOVZX")}
	switch op {
	case "PMOVSXBW", "VPMOVSXBW", "PMOVZXBW", "VPMOVZXBW":
		properties.inputBits, properties.outputBits = 8, 16
	case "PMOVSXBD", "VPMOVSXBD", "PMOVZXBD", "VPMOVZXBD":
		properties.inputBits, properties.outputBits = 8, 32
	case "PMOVSXBQ", "VPMOVSXBQ", "PMOVZXBQ", "VPMOVZXBQ":
		properties.inputBits, properties.outputBits = 8, 64
	case "PMOVSXWD", "VPMOVSXWD", "PMOVZXWD", "VPMOVZXWD":
		properties.inputBits, properties.outputBits = 16, 32
	case "PMOVSXWQ", "VPMOVSXWQ", "PMOVZXWQ", "VPMOVZXWQ":
		properties.inputBits, properties.outputBits = 16, 64
	case "PMOVSXDQ", "VPMOVSXDQ", "PMOVZXDQ", "VPMOVZXDQ":
		properties.inputBits, properties.outputBits = 32, 64
	default:
		return amd64PackedExtendMove{}, false
	}
	return properties, true
}

func (c *amd64Ctx) isGoLegacyPackedExtendX(arg Operand) bool {
	index, ok := amd64VectorRegisterIndex(arg.Reg, 16)
	if !ok || index >= 16 {
		return false
	}
	return c.goarch != "386" || index < 8
}

func (c *amd64Ctx) isGoPackedExtendDestination(arg Operand, outputBytes int) bool {
	if outputBytes != 16 && outputBytes != 32 && outputBytes != 64 {
		return false
	}
	if !amd64EVEXVectorRegister(arg, outputBytes) {
		return false
	}
	if c.goarch == "386" && outputBytes == 64 {
		index, _ := amd64VectorRegisterIndex(arg.Reg, outputBytes)
		return index < 8
	}
	return true
}

func (c *amd64Ctx) loadPackedExtendInputs(src Operand, registerBytes, lanes, inputBits int) (string, error) {
	if src.Kind == OpReg {
		bytesValue, err := c.loadPackedCompareBytes(src, registerBytes)
		if err != nil {
			return "", err
		}
		fullLanes := registerBytes * 8 / inputBits
		full := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i%d>\n", full, registerBytes, bytesValue, fullLanes, inputBits)
		if fullLanes == lanes {
			return "%" + full, nil
		}
		result := "zeroinitializer"
		for lane := 0; lane < lanes; lane++ {
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %%%s, i32 %d\n", value, fullLanes, inputBits, full, lane)
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %%%s, i32 %d\n", inserted, lanes, inputBits, result, inputBits, value, lane)
			result = "%" + inserted
		}
		return result, nil
	}
	vectorType := fmt.Sprintf("<%d x i%d>", lanes, inputBits)
	switch src.Kind {
	case OpMem:
		ptr, ptrType, err := c.ptrFromMem(src.Mem)
		if err != nil {
			return "", err
		}
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, %s %s, align 1\n", loaded, vectorType, ptrType, ptr)
		return "%" + loaded, nil
	case OpSym:
		ptr, err := c.ptrFromSB(src.Sym)
		if err != nil {
			return "", err
		}
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s, align 1\n", loaded, vectorType, ptr)
		return "%" + loaded, nil
	case OpFP:
		result := "zeroinitializer"
		for lane := 0; lane < lanes; lane++ {
			laneOperand := src
			laneOperand.FPOffset += int64(lane * inputBits / 8)
			value, err := c.evalIntSized(laneOperand, amd64IntegerTypeForBits(inputBits))
			if err != nil {
				return "", err
			}
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %s, i32 %d\n", inserted, vectorType, result, inputBits, value, lane)
			result = "%" + inserted
		}
		return result, nil
	default:
		return "", fmt.Errorf("expected packed extension register or memory source, got %s", src.String())
	}
}
