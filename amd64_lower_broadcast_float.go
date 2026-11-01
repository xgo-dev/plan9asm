package plan9asm

import (
	"fmt"
)

// lowerScalarFloatBroadcast implements all Go 1.27 _yvbroadcastss and
// _yvbroadcastsd operand forms, including EVEX mask merge and zeroing.
func (c *amd64Ctx) lowerScalarFloatBroadcast(op Op, ins Instr) (ok bool, terminated bool, err error) {
	f, known, err := x86BroadcastProperties(op, ins, c.goarch)
	if !known || f.kind != x86BroadcastFloat {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	laneBits, byteWidth := f.laneBits, f.byteWidth
	source, dst := ins.Args[0], ins.Args[f.destination]
	masked, zeroing := f.mask >= 0, f.zeroing
	var mask string
	if masked {
		mask, err = c.loadK(ins.Args[f.mask].Reg)
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
			scalar, err = c.loadX86ScalarIf(laneBits, "%"+active, func() (string, error) {
				return c.loadPackedBroadcastScalar(source, laneBits, false)
			})
		} else {
			scalar, err = c.loadPackedBroadcastScalar(source, laneBits, false)
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
