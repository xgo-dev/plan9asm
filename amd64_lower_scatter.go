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
	name, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := amd64ScatterSpecs[name]; !known {
		return false, false, nil
	}
	local := ins
	local.Op = op
	form, _, err := x86VSIBProperties(local, c.goarch)
	if err != nil {
		return true, false, err
	}
	return true, false, c.emitScatter(form.spec, form.memory.Mem, form.mask.Reg, form.data.Reg, form.dataBytes, form.indexBytes)
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
