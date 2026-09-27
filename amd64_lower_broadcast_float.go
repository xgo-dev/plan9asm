package plan9asm

import (
	"fmt"
	"strings"
)

// lowerScalarFloatBroadcast implements all Go 1.27 _yvbroadcastss and
// _yvbroadcastsd operand forms, including EVEX mask merge and zeroing.
func (c *amd64Ctx) lowerScalarFloatBroadcast(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	laneBits := 0
	switch baseOp {
	case "VBROADCASTSS":
		laneBits = 32
	case "VBROADCASTSD":
		laneBits = 64
	default:
		return false, false, nil
	}
	zeroing := false
	switch suffix {
	case "":
	case "Z":
		zeroing = true
	default:
		return true, false, fmt.Errorf("amd64 %s accepts only the .Z suffix: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("amd64 %s expects X-or-memory source, [K mask,] vector destination: %q", baseOp, ins.Raw)
	}
	dst := ins.Args[len(ins.Args)-1]
	if dst.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects vector destination: %q", baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(dst.Reg)
	if byteWidth == 0 || laneBits == 64 && byteWidth == 16 || !c.isGoPackedVectorMoveRegister(dst, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s destination is outside its Go 1.27 table: %q", baseOp, ins.Raw)
	}
	source := ins.Args[0]
	if source.Kind == OpReg {
		if !isAMD64XReg(source.Reg) {
			return true, false, fmt.Errorf("amd64 %s source must be X or memory: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) && !(source.Kind == OpImm && ins.x86RIPLiteral) {
		return true, false, fmt.Errorf("amd64 %s source must be X or memory: %q", baseOp, ins.Raw)
	}

	masked := len(ins.Args) == 3
	if zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s .Z requires a K1-K7 mask: %q", baseOp, ins.Raw)
	}
	var mask string
	if masked {
		maskArg := ins.Args[1]
		if maskArg.Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		maskIndex, ok := amd64ParseKReg(maskArg.Reg)
		if !ok || maskIndex == 0 {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		mask, err = c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
	}

	var scalar string
	if source.Kind == OpReg {
		scalar, err = c.loadXLowInteger(source.Reg, laneBits)
	} else if source.Kind == OpImm {
		scalar, err = c.evalIntSized(source, amd64IntegerTypeForBits(laneBits))
	} else {
		if masked {
			// Broadcasting reads the scalar only if any destination lane is
			// active. High K bits outside this vector's lane count do not
			// enable the load; checking only mask bit zero is also incorrect.
			lanes := byteWidth * 8 / laneBits
			relevant, active := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", relevant, mask, uint64(1)<<uint(lanes)-1)
			fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", active, relevant)
			scalar, err = c.loadX86ScalarMemoryIf(source, laneBits, "%"+active)
		} else {
			scalar, err = c.evalIntSized(source, amd64IntegerTypeForBits(laneBits))
		}
	}
	if err != nil {
		return true, false, err
	}

	lanes := byteWidth * 8 / laneBits
	result := amd64SplatInteger(c, lanes, laneBits, scalar)
	if masked {
		oldBytes, err := c.loadPackedCompareBytes(dst, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, laneBits, result, old, mask, zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, laneBits, result, byteWidth)
	return true, false, c.storePackedMoveOperand(dst, byteWidth, "%"+out)
}
