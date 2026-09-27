package plan9asm

import (
	"fmt"
	"strings"
)

var amd64ScatterSpecs = map[string]amd64GatherSpec{
	"VPSCATTERDD": {table: amd64GatherDPS, elemBits: 32, indexBits: 32},
	"VPSCATTERQQ": {table: amd64GatherDPS, elemBits: 64, indexBits: 64},
	"VSCATTERDPS": {table: amd64GatherDPS, elemBits: 32, indexBits: 32},
	"VSCATTERQPD": {table: amd64GatherDPS, elemBits: 64, indexBits: 64},
	"VPSCATTERDQ": {table: amd64GatherDPD, elemBits: 64, indexBits: 32},
	"VSCATTERDPD": {table: amd64GatherDPD, elemBits: 64, indexBits: 32},
	"VPSCATTERQD": {table: amd64GatherQPS, elemBits: 32, indexBits: 64},
	"VSCATTERQPS": {table: amd64GatherQPS, elemBits: 32, indexBits: 64},
}

// lowerScatter implements all Go 1.27 packed integer and floating scatter
// spellings. Values are kept as integer bit patterns, which is exact for the
// floating variants as well.
func (c *amd64Ctx) lowerScatter(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	if strings.Contains(rawOp, ".") {
		baseOp := strings.SplitN(rawOp, ".", 2)[0]
		if _, known := amd64ScatterSpecs[baseOp]; known {
			return true, false, fmt.Errorf("amd64 %s has no suffixes in its Go 1.27 table: %q", baseOp, ins.Raw)
		}
		return false, false, nil
	}
	spec, ok := amd64ScatterSpecs[rawOp]
	if !ok {
		return false, false, nil
	}
	if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpMem {
		return true, false, fmt.Errorf("amd64 %s expects data vector, K1-K7, VSIB memory: %q", rawOp, ins.Raw)
	}
	data, mask, memory := ins.Args[0], ins.Args[1], ins.Args[2].Mem
	maskIndex, validMask := amd64ParseKReg(mask.Reg)
	if !validMask || maskIndex == 0 {
		return true, false, fmt.Errorf("amd64 %s requires K1-K7: %q", rawOp, ins.Raw)
	}

	dataBytes := amd64VectorByteWidth(data.Reg)
	indexBytes := amd64VectorByteWidth(memory.Index)
	if dataBytes == 0 || indexBytes == 0 || !amd64GatherTableAllows(spec.table, true, dataBytes, indexBytes) {
		return true, false, fmt.Errorf("amd64 %s data/index widths are outside its Go 1.27 table: %q", rawOp, ins.Raw)
	}
	if err := c.validateGatherMemory(memory, indexBytes, true); err != nil {
		return true, false, fmt.Errorf("amd64 %s invalid VSIB memory: %q: %w", rawOp, ins.Raw, err)
	}
	if _, ok := amd64GatherRegisterIndex(data.Reg, dataBytes, true, c.goarch, false); !ok {
		return true, false, fmt.Errorf("amd64 %s data register is outside its Go 1.27 class: %q", rawOp, ins.Raw)
	}
	if _, ok := amd64GatherRegisterIndex(memory.Index, indexBytes, true, c.goarch, true); !ok {
		return true, false, fmt.Errorf("amd64 %s VSIB index is outside its Go 1.27 class: %q", rawOp, ins.Raw)
	}
	return true, false, c.emitScatter(spec, memory, mask.Reg, data.Reg, dataBytes, indexBytes)
}

func (c *amd64Ctx) emitScatter(spec amd64GatherSpec, memory MemRef, mask, data Reg, dataBytes, indexBytes int) error {
	dataValue, err := c.loadGatherVector(data, dataBytes)
	if err != nil {
		return err
	}
	dataLanes := dataBytes * 8 / spec.elemBits
	dataType := fmt.Sprintf("<%d x i%d>", dataLanes, spec.elemBits)
	dataValues := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", dataValues, dataBytes, dataValue, dataType)

	indexValue, err := c.loadGatherVector(memory.Index, indexBytes)
	if err != nil {
		return err
	}
	indexLanes := indexBytes * 8 / spec.indexBits
	indexType := fmt.Sprintf("<%d x i%d>", indexLanes, spec.indexBits)
	indexValues := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", indexValues, indexBytes, indexValue, indexType)
	activeLanes := dataLanes
	if indexLanes < activeLanes {
		activeLanes = indexLanes
	}

	maskValue, err := c.loadK(mask)
	if err != nil {
		return err
	}
	base, err := c.gatherBaseAddress(memory)
	if err != nil {
		return err
	}
	for lane := 0; lane < activeLanes; lane++ {
		indexLane := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", indexLane, indexType, indexValues, lane)
		wideIndex := "%" + indexLane
		if spec.indexBits == 32 {
			extended := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext i32 %%%s to i64\n", extended, indexLane)
			wideIndex = "%" + extended
		}
		if memory.Scale != 0 && memory.Scale != 1 {
			scaled := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = mul i64 %s, %d\n", scaled, wideIndex, memory.Scale)
			wideIndex = "%" + scaled
		}
		address := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", address, base, wideIndex)
		pointer, pointerType := c.gatherPointer(memory, "%"+address)

		condition := amd64MaskBitI1(c, maskValue, lane)
		dataLane := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %%%s, i32 %d\n", dataLane, dataType, dataValues, lane)
		storeLabel := c.newTmp() + "_scatter_store"
		skipLabel := c.newTmp() + "_scatter_skip"
		joinLabel := c.newTmp() + "_scatter_join"
		fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n", condition, storeLabel, skipLabel)
		fmt.Fprintf(c.b, "%s:\n", storeLabel)
		fmt.Fprintf(c.b, "  store i%d %%%s, %s %s, align 1\n", spec.elemBits, dataLane, pointerType, pointer)
		fmt.Fprintf(c.b, "  br label %%%s\n", joinLabel)
		fmt.Fprintf(c.b, "%s:\n", skipLabel)
		fmt.Fprintf(c.b, "  br label %%%s\n", joinLabel)
		fmt.Fprintf(c.b, "%s:\n", joinLabel)
	}
	// Like EVEX gather, scatter clears completed mask bits to support precise
	// restart after a fault. A normally completed instruction leaves zero.
	return c.storeK(mask, "0")
}
