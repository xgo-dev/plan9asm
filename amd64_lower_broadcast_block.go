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
	f, known, err := x86BroadcastProperties(op, ins, c.goarch)
	if !known || f.kind != x86BroadcastBlock {
		return false, false, nil
	}
	if err != nil {
		return true, false, err
	}
	baseOp, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	spec := amd64PackedBlockBroadcastSpecs[baseOp]
	source, destination := ins.Args[0], ins.Args[f.destination]
	destinationBytes := f.byteWidth
	masked, zeroing := f.mask >= 0, f.zeroing
	mask := ""
	if masked {
		mask, err = c.loadK(ins.Args[f.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}

	var block string
	if mask != "" && source.Kind != OpReg {
		// E6 suppresses each source element unless at least one repeated
		// destination lane selects it. Fold the destination mask onto the
		// source tuple before reusing the exact guarded volatile lane reader.
		sourceLanes := spec.sourceBytes * 8 / spec.laneBits
		folded := mask
		for shift := sourceLanes; shift < destinationBytes*8/spec.laneBits; shift += sourceLanes {
			high, combined := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %d\n", high, mask, shift)
			fmt.Fprintf(c.b, "  %%%s = or i64 %s, %%%s\n", combined, folded, high)
			folded = "%" + combined
		}
		lanes, readErr := c.loadX86PackedShiftLanes(source, spec.sourceBytes, spec.laneBits, false, folded)
		err = readErr
		if err == nil {
			value := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n",
				value, sourceLanes, spec.laneBits, lanes, spec.sourceBytes)
			block = "%" + value
		}
	} else {
		block, err = c.loadPackedBlockBroadcastSource(source, spec.sourceBytes)
	}
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
	return true, false, c.storePackedMoveOperand(destination, destinationBytes, result)
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

	return c.loadX86PackedShiftBytes(source, sourceBytes, true)
}
