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
	if prefetch, ok := amd64VSIBPrefetchSpecs[op]; ok {
		return c.lowerVSIBPrefetch(op, prefetch, ins)
	}
	spec := amd64GatherSpecs[op]
	if len(ins.Args) != 3 {
		return fmt.Errorf("amd64 %s expects exactly three operands from its Go 1.27 gather table: %q", op, ins.Raw)
	}

	var memory Operand
	var mask Operand
	var destination Operand
	evex := false
	if ins.Args[0].Kind == OpMem {
		evex = true
		memory, mask, destination = ins.Args[0], ins.Args[1], ins.Args[2]
	} else {
		mask, memory, destination = ins.Args[0], ins.Args[1], ins.Args[2]
	}
	if memory.Kind != OpMem || destination.Kind != OpReg {
		return fmt.Errorf("amd64 %s expects vector-mask,memory,vector or memory,K-mask,vector: %q", op, ins.Raw)
	}
	destinationBytes := amd64VectorByteWidth(destination.Reg)
	indexBytes := amd64VectorByteWidth(memory.Mem.Index)
	if destinationBytes == 0 || indexBytes == 0 || !amd64GatherTableAllows(spec.table, evex, destinationBytes, indexBytes) {
		return fmt.Errorf("amd64 %s vector widths are outside its Go 1.27 gather table: %q", op, ins.Raw)
	}
	if err := c.validateGatherMemory(memory.Mem, indexBytes, evex); err != nil {
		return fmt.Errorf("amd64 %s invalid VSIB memory: %q: %w", op, ins.Raw, err)
	}
	destinationIndex, ok := amd64GatherRegisterIndex(destination.Reg, destinationBytes, evex, c.goarch, false)
	if !ok {
		return fmt.Errorf("amd64 %s destination is outside its Go 1.27 register class: %q", op, ins.Raw)
	}
	indexIndex, ok := amd64GatherRegisterIndex(memory.Mem.Index, indexBytes, evex, c.goarch, true)
	if !ok {
		return fmt.Errorf("amd64 %s VSIB index is outside its Go 1.27 register class: %q", op, ins.Raw)
	}
	if destinationIndex == indexIndex {
		return fmt.Errorf("amd64 %s index and destination registers must be distinct: %q", op, ins.Raw)
	}

	if evex {
		maskIndex, ok := amd64ParseKReg(mask.Reg)
		if mask.Kind != OpReg || !ok || maskIndex == 0 {
			return fmt.Errorf("amd64 %s EVEX form requires K1..K7: %q", op, ins.Raw)
		}
	} else {
		maskBytes := amd64VectorByteWidth(mask.Reg)
		maskIndex, ok := amd64GatherRegisterIndex(mask.Reg, destinationBytes, false, c.goarch, false)
		if mask.Kind != OpReg || !ok || maskBytes != destinationBytes {
			return fmt.Errorf("amd64 %s VEX form requires a destination-width vector mask: %q", op, ins.Raw)
		}
		if maskIndex == indexIndex || maskIndex == destinationIndex {
			return fmt.Errorf("amd64 %s mask, index, and destination registers must be distinct: %q", op, ins.Raw)
		}
	}

	return c.emitGather(spec, memory.Mem, mask, destination.Reg, destinationBytes, indexBytes, evex)
}

func (c *amd64Ctx) lowerVSIBPrefetch(op Op, spec amd64VSIBPrefetchSpec, ins Instr) error {
	if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpMem {
		return fmt.Errorf("amd64 %s expects K1..K7 and VSIB memory: %q", op, ins.Raw)
	}
	maskIndex, ok := amd64ParseKReg(ins.Args[0].Reg)
	if !ok || maskIndex == 0 {
		return fmt.Errorf("amd64 %s requires K1..K7: %q", op, ins.Raw)
	}
	indexBytes := spec.indexBytes
	if amd64VectorByteWidth(ins.Args[1].Mem.Index) != indexBytes {
		return fmt.Errorf("amd64 %s has the wrong VSIB index width: %q", op, ins.Raw)
	}
	if err := c.validateGatherMemory(ins.Args[1].Mem, indexBytes, true); err != nil {
		return fmt.Errorf("amd64 %s invalid VSIB memory: %q: %w", op, ins.Raw, err)
	}
	if _, ok := amd64GatherRegisterIndex(ins.Args[1].Mem.Index, indexBytes, true, c.goarch, true); !ok {
		return fmt.Errorf("amd64 %s VSIB index is outside its Go 1.27 register class: %q", op, ins.Raw)
	}
	return nil
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

func (c *amd64Ctx) validateGatherMemory(memory MemRef, indexBytes int, evex bool) error {
	if memory.Index == "" || amd64VectorByteWidth(memory.Index) != indexBytes {
		return fmt.Errorf("expected a VSIB vector index")
	}
	if memory.Scale == 0 {
		memory.Scale = 1
	}
	if memory.Scale != 1 && memory.Scale != 2 && memory.Scale != 4 && memory.Scale != 8 {
		return fmt.Errorf("VSIB scale must be 1, 2, 4, or 8")
	}
	if memory.Sym != "" {
		return fmt.Errorf("Go's x86 assembler does not accept an SB base with VSIB")
	}
	if memory.Base != "" && !isX86YrlRegisterForArch(memory.Base, c.goarch) {
		return fmt.Errorf("VSIB base is not a GP register for %s", c.goarch)
	}
	if memory.Segment != "" && memory.Segment != FS && memory.Segment != GS {
		return fmt.Errorf("unsupported VSIB segment %s", memory.Segment)
	}
	_ = evex
	return nil
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
		fmt.Fprintf(c.b, "  %%%s = load i%d, %s %s, align 1\n", loaded, spec.elemBits, pointerType, pointer)
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
	if err := c.storeVectorBytes(destination, destinationBytes, "%"+bytesResult); err != nil {
		return err
	}
	if evex {
		return c.storeK(mask.Reg, "0")
	}
	return c.storeVectorBytes(mask.Reg, destinationBytes, "zeroinitializer")
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
