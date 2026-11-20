package plan9asm

import "fmt"

type amd64GatherTable uint8

const (
	amd64GatherDPS amd64GatherTable = iota
	amd64GatherDPD
	amd64GatherQPS
)

type amd64GatherSpec struct {
	table     amd64GatherTable
	elemBits  int
	indexBits int
}

// amd64GatherSpecs is the complete Go 1.27 data-gather family. The eight
// spellings share _yvgatherdps, _yvgatherdpd, and _yvgatherqps.
var amd64GatherSpecs = map[Op]amd64GatherSpec{
	"VGATHERDPS": {table: amd64GatherDPS, elemBits: 32, indexBits: 32},
	"VGATHERQPD": {table: amd64GatherDPS, elemBits: 64, indexBits: 64},
	"VPGATHERDD": {table: amd64GatherDPS, elemBits: 32, indexBits: 32},
	"VPGATHERQQ": {table: amd64GatherDPS, elemBits: 64, indexBits: 64},
	"VGATHERDPD": {table: amd64GatherDPD, elemBits: 64, indexBits: 32},
	"VPGATHERDQ": {table: amd64GatherDPD, elemBits: 64, indexBits: 32},
	"VGATHERQPS": {table: amd64GatherQPS, elemBits: 32, indexBits: 64},
	"VPGATHERQD": {table: amd64GatherQPS, elemBits: 32, indexBits: 64},
}

type amd64VSIBPrefetchDirection uint8

const (
	amd64VSIBPrefetchGather amd64VSIBPrefetchDirection = iota
	amd64VSIBPrefetchScatter
)

type amd64VSIBPrefetchSpec struct {
	direction  amd64VSIBPrefetchDirection
	hint       int
	elemBits   int
	indexBits  int
	indexBytes int
}

// amd64VSIBPrefetchSpecs is the complete Go 1.27 gather/scatter prefetch
// grammar. Direction, cache hint, element width, and VSIB index width are data;
// all sixteen opcodes share one exact operand validator. These instructions
// are architectural hints, so lowering has no observable IR side effect.
var amd64VSIBPrefetchSpecs = map[Op]amd64VSIBPrefetchSpec{
	"VGATHERPF0DPD":  {direction: amd64VSIBPrefetchGather, hint: 0, elemBits: 64, indexBits: 32, indexBytes: 32},
	"VGATHERPF0DPS":  {direction: amd64VSIBPrefetchGather, hint: 0, elemBits: 32, indexBits: 32, indexBytes: 64},
	"VGATHERPF0QPD":  {direction: amd64VSIBPrefetchGather, hint: 0, elemBits: 64, indexBits: 64, indexBytes: 64},
	"VGATHERPF0QPS":  {direction: amd64VSIBPrefetchGather, hint: 0, elemBits: 32, indexBits: 64, indexBytes: 64},
	"VGATHERPF1DPD":  {direction: amd64VSIBPrefetchGather, hint: 1, elemBits: 64, indexBits: 32, indexBytes: 32},
	"VGATHERPF1DPS":  {direction: amd64VSIBPrefetchGather, hint: 1, elemBits: 32, indexBits: 32, indexBytes: 64},
	"VGATHERPF1QPD":  {direction: amd64VSIBPrefetchGather, hint: 1, elemBits: 64, indexBits: 64, indexBytes: 64},
	"VGATHERPF1QPS":  {direction: amd64VSIBPrefetchGather, hint: 1, elemBits: 32, indexBits: 64, indexBytes: 64},
	"VSCATTERPF0DPD": {direction: amd64VSIBPrefetchScatter, hint: 0, elemBits: 64, indexBits: 32, indexBytes: 32},
	"VSCATTERPF0DPS": {direction: amd64VSIBPrefetchScatter, hint: 0, elemBits: 32, indexBits: 32, indexBytes: 64},
	"VSCATTERPF0QPD": {direction: amd64VSIBPrefetchScatter, hint: 0, elemBits: 64, indexBits: 64, indexBytes: 64},
	"VSCATTERPF0QPS": {direction: amd64VSIBPrefetchScatter, hint: 0, elemBits: 32, indexBits: 64, indexBytes: 64},
	"VSCATTERPF1DPD": {direction: amd64VSIBPrefetchScatter, hint: 1, elemBits: 64, indexBits: 32, indexBytes: 32},
	"VSCATTERPF1DPS": {direction: amd64VSIBPrefetchScatter, hint: 1, elemBits: 32, indexBits: 32, indexBytes: 64},
	"VSCATTERPF1QPD": {direction: amd64VSIBPrefetchScatter, hint: 1, elemBits: 64, indexBits: 64, indexBytes: 64},
	"VSCATTERPF1QPS": {direction: amd64VSIBPrefetchScatter, hint: 1, elemBits: 32, indexBits: 64, indexBytes: 64},
}

func (c *amd64Ctx) lowerGather(op Op, ins Instr) error {
	local := ins
	local.Op = op
	form, known, err := x86VSIBProperties(local, c.goarch)
	if err != nil {
		return err
	}
	if !known || form.scatter && !form.prefetch {
		return fmt.Errorf("amd64 %s is not a gather or VSIB prefetch: %q", op, ins.Raw)
	}
	if form.prefetch {
		return nil
	}
	return c.emitGather(form.spec, form.memory.Mem, form.mask, form.data.Reg, form.dataBytes, form.indexBytes, form.evex)
}

func amd64GatherTableAllows(table amd64GatherTable, evex bool, destinationBytes, indexBytes int) bool {
	allowed := false
	switch table {
	case amd64GatherDPS:
		allowed = (destinationBytes == 16 && indexBytes == 16) ||
			(destinationBytes == 32 && indexBytes == 32) ||
			(destinationBytes == 64 && indexBytes == 64)
	case amd64GatherDPD:
		allowed = (destinationBytes == 16 && indexBytes == 16) ||
			(destinationBytes == 32 && indexBytes == 16) ||
			(destinationBytes == 64 && indexBytes == 32)
	case amd64GatherQPS:
		allowed = (destinationBytes == 16 && (indexBytes == 16 || indexBytes == 32)) ||
			(destinationBytes == 32 && indexBytes == 64)
	}
	if !allowed {
		return false
	}
	if !evex {
		return destinationBytes != 64
	}
	return true
}

func amd64GatherRegisterIndex(register Reg, byteWidth int, evex bool, goarch string, index bool) (int, bool) {
	var registerIndex int
	var ok bool
	switch byteWidth {
	case 16:
		registerIndex, ok = amd64ParseXReg(register)
	case 32:
		registerIndex, ok = amd64ParseYReg(register)
	case 64:
		registerIndex, ok = amd64ParseZReg(register)
	}
	if !ok {
		return 0, false
	}
	limit := 15
	if evex {
		limit = 31
	}
	if goarch == "386" && (index || byteWidth == 64) {
		limit = 7
	}
	return registerIndex, registerIndex <= limit
}

func (c *amd64Ctx) emitGather(spec amd64GatherSpec, memory MemRef, mask Operand, destination Reg, destinationBytes, indexBytes int, evex bool) error {
	destinationValue, err := c.loadGatherVector(destination, destinationBytes)
	if err != nil {
		return err
	}
	destinationLanes := destinationBytes * 8 / spec.elemBits
	destinationType := fmt.Sprintf("<%d x i%d>", destinationLanes, spec.elemBits)
	destinationValues := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", destinationValues, destinationBytes, destinationValue, destinationType)
	result := "%" + destinationValues

	indexValue, err := c.loadGatherVector(memory.Index, indexBytes)
	if err != nil {
		return err
	}
	indexLanes := indexBytes * 8 / spec.indexBits
	indexType := fmt.Sprintf("<%d x i%d>", indexLanes, spec.indexBits)
	indexValues := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", indexValues, indexBytes, indexValue, indexType)
	activeLanes := destinationLanes
	if indexLanes < activeLanes {
		activeLanes = indexLanes
		// QPS/QD with an X index has two active dword lanes and architecturally
		// zeroes the upper two lanes of the X destination.
		for lane := activeLanes; lane < destinationLanes; lane++ {
			zeroed := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d 0, i32 %d\n", zeroed, destinationType, result, spec.elemBits, lane)
			result = "%" + zeroed
		}
	}

	var maskValues string
	var kMask string
	if evex {
		kMask, err = c.loadK(mask.Reg)
	} else {
		maskBytes, err := c.loadGatherVector(mask.Reg, destinationBytes)
		if err != nil {
			return err
		}
		maskValues = c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", maskValues, destinationBytes, maskBytes, destinationType)
		maskValues = "%" + maskValues
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

		condition := ""
		if evex {
			shifted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = lshr i64 %s, %d\n", shifted, kMask, lane)
			bit := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 1\n", bit, shifted)
			set := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %%%s, 0\n", set, bit)
			condition = "%" + set
		} else {
			maskLane := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", maskLane, destinationType, maskValues, lane)
			set := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp slt i%d %%%s, 0\n", set, spec.elemBits, maskLane)
			condition = "%" + set
		}

		oldLane := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", oldLane, destinationType, result, lane)
		loadLabel := c.newTmp() + "_gather_load"
		skipLabel := c.newTmp() + "_gather_skip"
		joinLabel := c.newTmp() + "_gather_join"
		loaded := c.newTmp()
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  br i1 %s, label %%%s, label %%%s\n", condition, loadLabel, skipLabel)
		fmt.Fprintf(c.b, "%s:\n", loadLabel)
		// An active architectural access still faults when its result is dead.
		// Keep the access inside its lane predicate so inactive lanes stay suppressed.
		fmt.Fprintf(c.b, "  %%%s = load volatile i%d, %s %s, align 1\n", loaded, spec.elemBits, pointerType, pointer)
		fmt.Fprintf(c.b, "  br label %%%s\n", joinLabel)
		fmt.Fprintf(c.b, "%s:\n", skipLabel)
		fmt.Fprintf(c.b, "  br label %%%s\n", joinLabel)
		fmt.Fprintf(c.b, "%s:\n", joinLabel)
		fmt.Fprintf(c.b, "  %%%s = phi i%d [ %%%s, %%%s ], [ %%%s, %%%s ]\n", selected, spec.elemBits, loaded, loadLabel, oldLane, skipLabel)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, i%d %%%s, i32 %d\n", inserted, destinationType, result, spec.elemBits, selected, lane)
		result = "%" + inserted
	}

	bytesResult := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", bytesResult, destinationType, result, destinationBytes)
	if err := c.storePackedMoveOperand(Operand{Kind: OpReg, Reg: destination}, destinationBytes, "%"+bytesResult); err != nil {
		return err
	}
	if evex {
		return c.storeK(mask.Reg, "0")
	}
	return c.storePackedMoveOperand(mask, destinationBytes, "zeroinitializer")
}

func (c *amd64Ctx) loadGatherVector(register Reg, byteWidth int) (string, error) {
	switch byteWidth {
	case 16:
		return c.loadX(register)
	case 32:
		return c.loadY(register)
	case 64:
		return c.loadZ(register)
	default:
		return "", fmt.Errorf("unsupported gather vector width %d", byteWidth)
	}
}

func (c *amd64Ctx) gatherBaseAddress(memory MemRef) (string, error) {
	base := "0"
	if memory.Base != "" {
		value, err := c.loadReg(memory.Base)
		if err != nil {
			return "", err
		}
		base = value
	}
	if memory.Off != 0 {
		adjusted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i64 %s, %d\n", adjusted, base, memory.Off)
		base = "%" + adjusted
	}
	return base, nil
}

func (c *amd64Ctx) gatherPointer(memory MemRef, address string) (string, string) {
	if memory.Segment == "" {
		return c.ptrFromAddrI64(address), "ptr"
	}
	addressSpace := 257
	if memory.Segment == GS {
		addressSpace = 256
	}
	pointerType := fmt.Sprintf("ptr addrspace(%d)", addressSpace)
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to %s\n", pointer, address, pointerType)
	return "%" + pointer, pointerType
}
