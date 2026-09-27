package plan9asm

import (
	"fmt"
	"strings"
)

// lowerDuplicateMove implements the complete Go x86 duplicate-move family.
// The legacy forms use yxm (X/m -> X), while all V-prefixed forms share
// _yvmovddup (X/Y/Z memory or matching register, with optional EVEX K mask).
func (c *amd64Ctx) lowerDuplicateMove(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := string(op)
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	switch baseOp {
	case "MOVDDUP", "VMOVDDUP", "MOVSHDUP", "VMOVSHDUP", "MOVSLDUP", "VMOVSLDUP":
		// handled below
	default:
		return false, false, nil
	}
	zeroMasking := false
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		for _, suffix := range strings.Split(rawOp[dot+1:], ".") {
			if suffix != "Z" || zeroMasking {
				return true, false, fmt.Errorf("amd64 %s has unsupported suffix .%s: %q", rawOp[:dot], suffix, ins.Raw)
			}
			zeroMasking = true
		}
		rawOp = baseOp
	}

	elemBits := 0
	duplicateOdd := false
	switch rawOp {
	case "MOVDDUP", "VMOVDDUP":
		elemBits = 64
	case "MOVSHDUP", "VMOVSHDUP":
		elemBits = 32
		duplicateOdd = true
	case "MOVSLDUP", "VMOVSLDUP":
		elemBits = 32
	default:
		panic("duplicate-move opcode precheck drift")
	}

	vectorForm := strings.HasPrefix(rawOp, "V")
	wantArgs := 2
	if vectorForm {
		wantArgs = 3
	}
	if len(ins.Args) != 2 && (!vectorForm || len(ins.Args) != wantArgs) {
		return true, false, fmt.Errorf("amd64 %s expects src, [K mask,] vector dst: %q", rawOp, ins.Raw)
	}
	masked := len(ins.Args) == 3
	if !vectorForm && (masked || zeroMasking) {
		return true, false, fmt.Errorf("amd64 %s legacy form does not accept EVEX masking: %q", rawOp, ins.Raw)
	}
	if zeroMasking && !masked {
		return true, false, fmt.Errorf("amd64 %s .Z form requires a K mask: %q", rawOp, ins.Raw)
	}

	dstArg := ins.Args[len(ins.Args)-1]
	if dstArg.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects vector destination: %q", rawOp, ins.Raw)
	}
	byteWidth := 0
	var loadOperand func(Operand) (string, error)
	var loadDst func() (string, error)
	var storeDst func(string) error
	switch {
	case isAMD64XReg(dstArg.Reg):
		byteWidth = 16
		loadOperand = c.loadXVecOperand
		loadDst = func() (string, error) { return c.loadX(dstArg.Reg) }
		storeDst = func(value string) error { return c.storeX(dstArg.Reg, value) }
	case vectorForm && isAMD64YReg(dstArg.Reg):
		byteWidth = 32
		loadOperand = c.loadYVecOperand
		loadDst = func() (string, error) { return c.loadY(dstArg.Reg) }
		storeDst = func(value string) error { return c.storeY(dstArg.Reg, value) }
	case vectorForm && isAMD64ZReg(dstArg.Reg):
		byteWidth = 64
		loadOperand = c.loadZVecOperand
		loadDst = func() (string, error) { return c.loadZ(dstArg.Reg) }
		storeDst = func(value string) error { return c.storeZ(dstArg.Reg, value) }
	default:
		return true, false, fmt.Errorf("amd64 %s has mismatched or non-vector destination: %q", rawOp, ins.Raw)
	}

	lanes := byteWidth * 8 / elemBits
	var sourceLanes string
	// MOVDDUP's 128-bit memory form reads one scalar double and duplicates it.
	// Wider memory forms read a full Y/Z vector and duplicate the low double of
	// each 128-bit lane. A register source always reads the full vector.
	if elemBits == 64 && byteWidth == 16 && ins.Args[0].Kind != OpReg {
		scalar, err := c.evalF64(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		bits := c.newTmp()
		seed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast double %s to i64\n", bits, scalar)
		fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> poison, i64 %%%s, i32 0\n", seed, bits)
		sourceLanes = "%" + seed
	} else {
		sourceBytes, err := loadOperand(ins.Args[0])
		if err != nil {
			return true, false, err
		}
		cast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i%d>\n", cast, byteWidth, sourceBytes, lanes, elemBits)
		sourceLanes = "%" + cast
	}

	indices := make([]int, lanes)
	for lane := range indices {
		if duplicateOdd {
			indices[lane] = lane | 1
		} else {
			indices[lane] = lane &^ 1
		}
	}
	shuffle := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %s, <%d x i%d> poison, <%d x i32> %s\n",
		shuffle, lanes, elemBits, sourceLanes, lanes, elemBits, lanes, llvmI32Mask(indices))
	result := "%" + shuffle

	if masked {
		maskArg := ins.Args[1]
		if maskArg.Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s masked form expects K register: %q", rawOp, ins.Raw)
		}
		if maskIndex, ok := amd64ParseKReg(maskArg.Reg); !ok || maskIndex == 0 {
			return true, false, fmt.Errorf("amd64 %s masked form expects K register: %q", rawOp, ins.Raw)
		}
		mask, err := c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
		oldBytes, err := loadDst()
		if err != nil {
			return true, false, err
		}
		old := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i%d>\n", old, byteWidth, oldBytes, lanes, elemBits)
		result = amd64ApplyIntegerLaneMask(c, lanes, elemBits, result, "%"+old, mask, zeroMasking)
	}

	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, elemBits, result, byteWidth)
	return true, false, storeDst("%" + out)
}

func llvmI32Mask(indices []int) string {
	var b strings.Builder
	b.WriteByte('<')
	for i, index := range indices {
		if i != 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "i32 %d", index)
	}
	b.WriteByte('>')
	return b.String()
}
