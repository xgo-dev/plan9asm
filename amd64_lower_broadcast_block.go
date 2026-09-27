package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedBlockBroadcastSpec struct {
	sourceBytes       int
	laneBits          int
	allowXSource      bool
	vexMemoryOnly     bool
	allowDestinations map[int]bool
}

var amd64PackedBlockBroadcastSpecs = map[string]amd64PackedBlockBroadcastSpec{
	"VBROADCASTF128":  {sourceBytes: 16, laneBits: 64, vexMemoryOnly: true, allowDestinations: map[int]bool{32: true}},
	"VBROADCASTI128":  {sourceBytes: 16, laneBits: 64, vexMemoryOnly: true, allowDestinations: map[int]bool{32: true}},
	"VBROADCASTF32X2": {sourceBytes: 8, laneBits: 32, allowXSource: true, allowDestinations: map[int]bool{32: true, 64: true}},
	"VBROADCASTI32X2": {sourceBytes: 8, laneBits: 32, allowXSource: true, allowDestinations: map[int]bool{16: true, 32: true, 64: true}},
	"VBROADCASTF32X4": {sourceBytes: 16, laneBits: 32, allowDestinations: map[int]bool{32: true, 64: true}},
	"VBROADCASTF64X2": {sourceBytes: 16, laneBits: 64, allowDestinations: map[int]bool{32: true, 64: true}},
	"VBROADCASTI32X4": {sourceBytes: 16, laneBits: 32, allowDestinations: map[int]bool{32: true, 64: true}},
	"VBROADCASTI64X2": {sourceBytes: 16, laneBits: 64, allowDestinations: map[int]bool{32: true, 64: true}},
	"VBROADCASTF32X8": {sourceBytes: 32, laneBits: 32, allowDestinations: map[int]bool{64: true}},
	"VBROADCASTF64X4": {sourceBytes: 32, laneBits: 64, allowDestinations: map[int]bool{64: true}},
	"VBROADCASTI32X8": {sourceBytes: 32, laneBits: 32, allowDestinations: map[int]bool{64: true}},
	"VBROADCASTI64X4": {sourceBytes: 32, laneBits: 64, allowDestinations: map[int]bool{64: true}},
}

// lowerPackedBlockBroadcast implements all Go 1.27 EVEX packed-block
// broadcast tables. The X2 forms copy the low 64 source bits; the X4 and X8
// forms accept only 128- and 256-bit memory sources respectively.
func (c *amd64Ctx) lowerPackedBlockBroadcast(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	zeroing := false
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
		suffix = rawOp[dot+1:]
		if suffix != "Z" {
			if _, known := amd64PackedBlockBroadcastSpecs[baseOp]; known {
				return true, false, fmt.Errorf("amd64 %s accepts only the .Z suffix: %q", baseOp, ins.Raw)
			}
			return false, false, nil
		}
		zeroing = true
	}
	spec, ok := amd64PackedBlockBroadcastSpecs[baseOp]
	if !ok {
		return false, false, nil
	}
	if spec.vexMemoryOnly {
		if suffix != "" || len(ins.Args) != 2 {
			return true, false, fmt.Errorf("%s %s expects Go 1.27's unsuffixed m128, Y form: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("amd64 %s expects block source, [K mask,] vector destination: %q", baseOp, ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	destinationBytes := 0
	if destination.Kind == OpReg {
		destinationBytes = amd64VectorByteWidth(destination.Reg)
	}
	validDestination := spec.allowDestinations[destinationBytes] && c.isGoPackedVectorMoveRegister(destination, destinationBytes)
	if validDestination && spec.vexMemoryOnly {
		index, isY := amd64ParseYReg(destination.Reg)
		validDestination = isY && index < 16
	}
	if !validDestination {
		return true, false, fmt.Errorf("amd64 %s destination is outside its Go 1.27 operand table: %q", baseOp, ins.Raw)
	}

	source := ins.Args[0]
	if source.Kind == OpReg {
		if spec.vexMemoryOnly || !spec.allowXSource || !amd64EVEXVectorRegister(source, 16) {
			return true, false, fmt.Errorf("amd64 %s requires a memory source for this block width: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("amd64 %s expects a memory source%s: %q", baseOp, amd64PackedBlockXSourceHint(spec.allowXSource), ins.Raw)
	}

	masked := !spec.vexMemoryOnly && len(ins.Args) == 3
	if zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s .Z requires a K1-K7 mask: %q", baseOp, ins.Raw)
	}
	mask := ""
	if masked {
		maskArg := ins.Args[1]
		maskIndex, validMask := amd64ParseKReg(maskArg.Reg)
		if maskArg.Kind != OpReg || !validMask || maskIndex == 0 {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		mask, err = c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
	}

	block, err := c.loadPackedBlockBroadcastSource(source, spec.sourceBytes)
	if err != nil {
		return true, false, err
	}
	broadcast := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> %s, <%d x i32> %s\n",
		broadcast, spec.sourceBytes, block, spec.sourceBytes, block, destinationBytes, llvmRepeatI8Mask(spec.sourceBytes, destinationBytes))
	result := "%" + broadcast

	if masked {
		lanes := destinationBytes * 8 / spec.laneBits
		computed := c.bitcastVectorBytesToIntegerLanes(destinationBytes, lanes, spec.laneBits, result)
		oldBytes, err := c.loadPackedCompareBytes(destination, destinationBytes)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(destinationBytes, lanes, spec.laneBits, oldBytes)
		maskedResult := amd64ApplyIntegerLaneMask(c, lanes, spec.laneBits, computed, old, mask, zeroing)
		cast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", cast, lanes, spec.laneBits, maskedResult, destinationBytes)
		result = "%" + cast
	}
	return true, false, c.storeVectorBytes(destination.Reg, destinationBytes, result)
}

func amd64PackedBlockXSourceHint(allowed bool) string {
	if allowed {
		return " or X-register source"
	}
	return ""
}

func (c *amd64Ctx) loadPackedBlockBroadcastSource(source Operand, sourceBytes int) (string, error) {
	if source.Kind == OpReg {
		value, err := c.loadX(source.Reg)
		if err != nil {
			return "", err
		}
		words := c.newTmp()
		low := c.newTmp()
		bytesValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", words, value)
		fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", low, words)
		fmt.Fprintf(c.b, "  %%%s = bitcast i64 %%%s to <8 x i8>\n", bytesValue, low)
		return "%" + bytesValue, nil
	}

	switch source.Kind {
	case OpMem:
		address, err := c.addrFromMem(source.Mem)
		if err != nil {
			return "", err
		}
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <%d x i8>, ptr %s, align 1\n", loaded, sourceBytes, c.ptrFromAddrI64(address))
		return "%" + loaded, nil
	case OpSym:
		pointer, err := c.ptrFromSB(source.Sym)
		if err != nil {
			return "", err
		}
		loaded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = load <%d x i8>, ptr %s, align 1\n", loaded, sourceBytes, pointer)
		return "%" + loaded, nil
	case OpFP:
		chunks := sourceBytes / 8
		words := "zeroinitializer"
		for chunk := 0; chunk < chunks; chunk++ {
			word, err := c.evalFPToI64(source.FPOffset + int64(chunk*8))
			if err != nil {
				return "", err
			}
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i64> %s, i64 %s, i32 %d\n", inserted, chunks, words, word, chunk)
			words = "%" + inserted
		}
		bytesValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i64> %s to <%d x i8>\n", bytesValue, chunks, words, sourceBytes)
		return "%" + bytesValue, nil
	default:
		return "", fmt.Errorf("expected packed-block broadcast memory source, got %s", source.String())
	}
}
