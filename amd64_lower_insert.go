package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedVectorInsertSpec struct {
	insertBytes int
	laneBits    int
	legacyVEX   bool
	allowY      bool
	allowZ      bool
}

// lowerPackedVectorInsert implements every Go 1.27 form in _yvinsertf128,
// _yvinsertf32x4, and _yvinsertf32x8. The floating and integer spellings have
// identical bit-level insert behavior; their lane type only changes EVEX mask
// granularity.
func (c *amd64Ctx) lowerPackedVectorInsert(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}

	var spec amd64PackedVectorInsertSpec
	switch baseOp {
	case "VINSERTF128", "VINSERTI128":
		spec = amd64PackedVectorInsertSpec{insertBytes: 16, laneBits: 64, legacyVEX: true, allowY: true}
	case "VINSERTF32X4", "VINSERTI32X4":
		spec = amd64PackedVectorInsertSpec{insertBytes: 16, laneBits: 32, allowY: true, allowZ: true}
	case "VINSERTF64X2", "VINSERTI64X2":
		spec = amd64PackedVectorInsertSpec{insertBytes: 16, laneBits: 64, allowY: true, allowZ: true}
	case "VINSERTF32X8", "VINSERTI32X8":
		spec = amd64PackedVectorInsertSpec{insertBytes: 32, laneBits: 32, allowZ: true}
	case "VINSERTF64X4", "VINSERTI64X4":
		spec = amd64PackedVectorInsertSpec{insertBytes: 32, laneBits: 64, allowZ: true}
	default:
		return false, false, nil
	}
	if c.goarch == "386" {
		return true, false, fmt.Errorf("386 %s exceeds the Go assembler frontend's operand limit: %q", baseOp, ins.Raw)
	}

	zeroing := false
	switch suffix {
	case "":
	case "Z":
		zeroing = true
	default:
		return true, false, fmt.Errorf("%s %s does not accept .%s in its Go 1.27 insert table: %q", c.goarch, baseOp, suffix, ins.Raw)
	}
	if spec.legacyVEX {
		if suffix != "" {
			return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
		}
		if len(ins.Args) != 4 {
			return true, false, fmt.Errorf("%s %s expects imm8, X/m source, Y base, Y destination: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if len(ins.Args) != 4 && len(ins.Args) != 5 {
		return true, false, fmt.Errorf("%s %s expects imm8, source, base, [K mask,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) < 4 || ins.Args[0].Kind != OpImm || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
		return true, false, fmt.Errorf("%s %s requires an unsigned 8-bit immediate: %q", c.goarch, baseOp, ins.Raw)
	}

	masked := !spec.legacyVEX && len(ins.Args) == 5
	if zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[3]) {
		return true, false, fmt.Errorf("%s %s masked form expects K1-K7 before the destination: %q", c.goarch, baseOp, ins.Raw)
	}

	source := ins.Args[1]
	base := ins.Args[2]
	destination := ins.Args[len(ins.Args)-1]
	if base.Kind != OpReg || destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s base and destination must be vector registers: %q", c.goarch, baseOp, ins.Raw)
	}
	outputBytes := amd64VectorByteWidth(base.Reg)
	validOutputWidth := outputBytes == 32 && spec.allowY || outputBytes == 64 && spec.allowZ
	if outputBytes == 0 || amd64VectorByteWidth(destination.Reg) != outputBytes ||
		!validOutputWidth {
		return true, false, fmt.Errorf("%s %s has incompatible base/destination widths: %q", c.goarch, baseOp, ins.Raw)
	}

	if spec.legacyVEX {
		if !amd64VEXVectorRegister(base, outputBytes) || !amd64VEXVectorRegister(destination, outputBytes) {
			return true, false, fmt.Errorf("%s %s requires in-range VEX Y base/destination registers: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !c.isGoPackedVectorMoveRegister(base, outputBytes) || !c.isGoPackedVectorMoveRegister(destination, outputBytes) {
		return true, false, fmt.Errorf("%s %s requires in-range EVEX base/destination registers: %q", c.goarch, baseOp, ins.Raw)
	}

	if source.Kind == OpReg {
		valid := amd64VectorByteWidth(source.Reg) == spec.insertBytes
		if spec.legacyVEX {
			valid = valid && amd64VEXVectorRegister(source, spec.insertBytes)
		} else {
			valid = valid && c.isGoPackedVectorMoveRegister(source, spec.insertBytes)
		}
		if !valid {
			return true, false, fmt.Errorf("%s %s source has the wrong vector width or register range: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s source must be a vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	inserted, err := c.loadPackedCompareBytes(source, spec.insertBytes)
	if err != nil {
		return true, false, err
	}
	baseValue, err := c.loadPackedCompareBytes(base, outputBytes)
	if err != nil {
		return true, false, err
	}
	insertWords := spec.insertBytes / 8
	outputWords := outputBytes / 8
	insertAsWords := c.newTmp()
	baseAsWords := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i64>\n", insertAsWords, spec.insertBytes, inserted, insertWords)
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i64>\n", baseAsWords, outputBytes, baseValue, outputWords)
	chunk := int(ins.Args[0].Imm) % (outputBytes / spec.insertBytes)
	resultWords := "%" + baseAsWords
	for i := 0; i < insertWords; i++ {
		word := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i64> %%%s, i32 %d\n", word, insertWords, insertAsWords, i)
		next := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i64> %s, i64 %%%s, i32 %d\n", next, outputWords, resultWords, word, chunk*insertWords+i)
		resultWords = "%" + next
	}
	computedName := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i64> %s to <%d x i8>\n", computedName, outputWords, resultWords, outputBytes)
	computed := "%" + computedName

	if masked {
		mask, err := c.loadK(ins.Args[3].Reg)
		if err != nil {
			return true, false, err
		}
		oldBytes, err := c.loadPackedCompareBytes(destination, outputBytes)
		if err != nil {
			return true, false, err
		}
		lanes := outputBytes * 8 / spec.laneBits
		computedLanes := c.bitcastVectorBytesToIntegerLanes(outputBytes, lanes, spec.laneBits, computed)
		oldLanes := c.bitcastVectorBytesToIntegerLanes(outputBytes, lanes, spec.laneBits, oldBytes)
		maskedLanes := amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, computedLanes, oldLanes, mask, zeroing)
		maskedBytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", maskedBytes, lanes, spec.laneBits, maskedLanes, outputBytes)
		computed = "%" + maskedBytes
	}
	return true, false, c.storeVectorBytesOperand(destination, outputBytes, computed)
}
