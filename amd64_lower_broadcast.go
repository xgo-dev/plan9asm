package plan9asm

import (
	"fmt"
	"strings"
)

// lowerPackedScalarBroadcast implements the complete Go 1.27
// _yvpbroadcastb operand table shared by VPBROADCASTB/W/D/Q.
func (c *amd64Ctx) lowerPackedScalarBroadcast(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	laneBits := 0
	switch baseOp {
	case "VPBROADCASTB":
		laneBits = 8
	case "VPBROADCASTW":
		laneBits = 16
	case "VPBROADCASTD":
		laneBits = 32
	case "VPBROADCASTQ":
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
		return true, false, fmt.Errorf("amd64 %s accepts only the .Z suffix enabled by its Go 1.27 optab: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("amd64 %s expects scalar source, [K mask,] vector destination: %q", baseOp, ins.Raw)
	}
	dstArg := ins.Args[len(ins.Args)-1]
	if dstArg.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects an X, Y, or Z destination: %q", baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(dstArg.Reg)
	if byteWidth == 0 {
		return true, false, fmt.Errorf("amd64 %s expects an X, Y, or Z destination: %q", baseOp, ins.Raw)
	}

	masked := len(ins.Args) == 3
	if zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s zeroing requires a K1-K7 mask: %q", baseOp, ins.Raw)
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

	load := func() (string, error) {
		return c.loadPackedBroadcastScalar(ins.Args[0], laneBits, ins.x86Encoded)
	}
	var scalar string
	if masked && ins.Args[0].Kind != OpReg {
		// Any active destination lane enables the one scalar read. Irrelevant
		// high K bits must not turn a fully masked memory source into a load.
		lanes := byteWidth * 8 / laneBits
		relevant, active := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %d\n", relevant, mask, uint64(1)<<uint(lanes)-1)
		fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", active, relevant)
		scalar, err = c.loadX86ScalarIf(laneBits, "%"+active, load)
	} else {
		scalar, err = load()
	}
	if err != nil {
		return true, false, fmt.Errorf("amd64 %s source: %w", baseOp, err)
	}
	lanes := byteWidth * 8 / laneBits
	result := amd64SplatInteger(c, lanes, laneBits, scalar)
	if masked {
		oldBytes, err := c.loadPackedCompareBytes(dstArg, byteWidth)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, lanes, laneBits, result, old, mask, zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, laneBits, result, byteWidth)
	return true, false, c.storePackedMoveOperand(dstArg, byteWidth, "%"+out)
}

func (c *amd64Ctx) loadPackedBroadcastScalar(src Operand, laneBits int, rawEncoded bool) (string, error) {
	if src.Kind == OpImm && rawEncoded {
		value := src.Imm
		switch laneBits {
		case 8:
			value = int64(int8(value))
		case 16:
			value = int64(int16(value))
		case 32:
			value = int64(int32(value))
		}
		return fmt.Sprintf("%d", value), nil
	}
	if src.Kind == OpReg {
		if isAMD64XReg(src.Reg) {
			bytesValue, err := c.loadX(src.Reg)
			if err != nil {
				return "", err
			}
			lanes := 128 / laneBits
			laneVector := c.bitcastVectorBytesToIntegerLanes(16, lanes, laneBits, bytesValue)
			low := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 0\n", low, lanes, laneBits, laneVector)
			return "%" + low, nil
		}
		if !isAMD64YrlRegister(src.Reg) {
			return "", fmt.Errorf("expected an X register, GP register, or memory, got %s", src.String())
		}
		return c.evalIntSized(src, amd64IntegerTypeForBits(laneBits))
	}
	if src.Kind == OpSym {
		// A bare integer in Go's x86 syntax is absolute memory, not an
		// immediate (immediates carry a '$'). The parser keeps this spelling
		// as OpSym so distinguish it here before the generic symbol loader.
		if address, parseErr := parseInt(src.Sym); parseErr == nil {
			loaded := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = load i%d, ptr %s, align 1\n", loaded, laneBits, c.ptrFromAddrI64(fmt.Sprintf("%d", address)))
			return "%" + loaded, nil
		}
	}
	if !isAMD64MemoryOperand(src) {
		return "", fmt.Errorf("expected an X register, GP register, or memory, got %s", src.String())
	}
	return c.evalIntSized(src, amd64IntegerTypeForBits(laneBits))
}

// isAMD64YrlRegister mirrors Go's amd64 Yrl register class. Byte aliases,
// vector, mask, MMX, and x87 registers are deliberately excluded.
func isAMD64YrlRegister(r Reg) bool {
	switch strings.ToUpper(string(r)) {
	case "AX", "BX", "CX", "DX", "SP", "BP", "SI", "DI",
		"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15":
		return true
	default:
		return false
	}
}
