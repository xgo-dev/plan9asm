package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVEFirstFaultMemorySpec struct {
	memoryBits int
	signed     bool
}

// arm64SVEFirstFaultMemorySpecs covers every Go 1.27 LDFF1 spelling,
// including its widening unsigned and sign-extending variants.
var arm64SVEFirstFaultMemorySpecs = map[Op]arm64SVEFirstFaultMemorySpec{
	"ZLDFF1B":  {memoryBits: 8},
	"ZLDFF1H":  {memoryBits: 16},
	"ZLDFF1W":  {memoryBits: 32},
	"ZLDFF1D":  {memoryBits: 64},
	"ZLDFF1SB": {memoryBits: 8, signed: true},
	"ZLDFF1SH": {memoryBits: 16, signed: true},
	"ZLDFF1SW": {memoryBits: 32, signed: true},
}

func (c *arm64Ctx) lowerARM64SVEFirstFaultMemory(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVEFirstFaultMemorySpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 || ins.Args[0].Kind != OpMem || ins.Args[2].Kind != OpRegList {
		return true, false, fmt.Errorf("arm64 %s expects memory, predicate, vector-list operands: %q", op, ins.Raw)
	}
	predicate, predicateOK := arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7)
	vectors, elementBits, vectorsOK := arm64ParseSVEConsecutiveVectorList(ins.Args[2])
	if !predicateOK || !vectorsOK || len(vectors) != 1 || elementBits < spec.memoryBits || spec.signed && elementBits == spec.memoryBits {
		return true, false, fmt.Errorf("arm64 %s has predicate or destination widths outside its Go 1.27 table: %q", op, ins.Raw)
	}

	memory := ins.Args[0].Mem
	if _, _, vectorOffset := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Index}); vectorOffset {
		return c.lowerARM64SVEFirstFaultVectorOffset(op, spec, memory, predicate, vectors[0], elementBits, ins)
	}
	if _, _, vectorBase := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Base}); vectorBase {
		return c.lowerARM64SVEFirstFaultVectorBase(op, spec, memory, predicate, vectors[0], elementBits, ins)
	}
	return c.lowerARM64SVEFirstFaultContiguous(op, spec, memory, predicate, vectors[0], elementBits, ins)
}

func (c *arm64Ctx) lowerARM64SVEFirstFaultContiguous(op Op, spec arm64SVEFirstFaultMemorySpec, memory MemRef, predicate, destination, elementBits int, ins Instr) (ok bool, terminated bool, err error) {
	address, err := c.arm64SVERegisterOffsetAddress(memory, int64(spec.memoryBits/8))
	if err != nil {
		return true, false, fmt.Errorf("arm64 %s: %w: %q", op, err, ins.Raw)
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, address)
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / elementBits
	loadedType := fmt.Sprintf("<vscale x %d x i%d>", lanes, spec.memoryBits)
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ldff1.nxv%di%d(%s %s, ptr %%%s)\n",
		loaded, loadedType, lanes, spec.memoryBits, predicateType, predicateValue, pointer)
	return c.finishARM64SVEFirstFaultLoad(spec, destination, elementBits, loadedType, "%"+loaded)
}

func (c *arm64Ctx) lowerARM64SVEFirstFaultVectorOffset(op Op, spec arm64SVEFirstFaultMemorySpec, memory MemRef, predicate, destination, elementBits int, ins Instr) (ok bool, terminated bool, err error) {
	if memory.Sym != "" || memory.Segment != "" || memory.Off != 0 || memory.OffRaw != "" {
		return true, false, fmt.Errorf("arm64 %s vector-offset form does not accept a displacement: %q", op, ins.Raw)
	}
	baseReg, baseOK := arm64SVEPhysicalMemoryBase(memory.Base)
	index, indexBits, indexOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Index})
	byteScale := int64(spec.memoryBits / 8)
	if !baseOK || !indexOK || indexBits != elementBits || (elementBits != 32 && elementBits != 64) || (memory.Scale != 1 && memory.Scale != byteScale) {
		return true, false, fmt.Errorf("arm64 %s vector offset has widths or scale outside its Go 1.27 table: %q", op, ins.Raw)
	}

	extension := ""
	switch memory.IndexExt {
	case "":
		if indexBits != 64 {
			return true, false, fmt.Errorf("arm64 %s unextended vector offset requires Zm.D: %q", op, ins.Raw)
		}
	case ExtendUXTW:
		extension = "uxtw"
	case ExtendSXTW:
		extension = "sxtw"
	default:
		return true, false, fmt.Errorf("arm64 %s vector offset only accepts UXTW or SXTW: %q", op, ins.Raw)
	}

	base, err := c.loadReg(baseReg)
	if err != nil {
		return true, false, err
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, base)
	indexValue, indexType, err := c.loadZRegElements(index, indexBits)
	if err != nil {
		return true, false, err
	}
	// Go accepts Zm.D.UXTW/SXTW. LLVM models the UXTW/SXTW gather intrinsics
	// with 32-bit lanes, so explicitly extend the low word of each D lane and
	// use the equivalent D-offset intrinsic.
	if extension != "" && indexBits == 64 {
		narrowType := "<vscale x 2 x i32>"
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", narrow, indexType, indexValue, narrowType)
		extended := c.newTmp()
		opcode := "zext"
		if extension == "sxtw" {
			opcode = "sext"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %%%s to %s\n", extended, opcode, narrowType, narrow, indexType)
		indexValue = "%" + extended
		extension = ""
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / elementBits
	loadedType := fmt.Sprintf("<vscale x %d x i%d>", lanes, spec.memoryBits)
	suffix := ""
	if extension != "" {
		suffix = "." + extension
	}
	if byteScale > 1 && memory.Scale == byteScale {
		suffix += ".index"
	}
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ldff1.gather%s.nxv%di%d(%s %s, ptr %%%s, %s %s)\n",
		loaded, loadedType, suffix, lanes, spec.memoryBits, predicateType, predicateValue, pointer, indexType, indexValue)
	return c.finishARM64SVEFirstFaultLoad(spec, destination, elementBits, loadedType, "%"+loaded)
}

func (c *arm64Ctx) lowerARM64SVEFirstFaultVectorBase(op Op, spec arm64SVEFirstFaultMemorySpec, memory MemRef, predicate, destination, elementBits int, ins Instr) (ok bool, terminated bool, err error) {
	base, baseBits, baseOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Base})
	alignment := int64(spec.memoryBits / 8)
	maximum := int64(31) * alignment
	if !baseOK || baseBits != elementBits || (elementBits != 32 && elementBits != 64) || memory.Index != "" || memory.IndexExt != "" || memory.Sym != "" || memory.Segment != "" || memory.OffRaw != "" || memory.Off < 0 || memory.Off > maximum || memory.Off%alignment != 0 {
		return true, false, fmt.Errorf("arm64 %s vector-base offset must match the destination width, be aligned to %d, and be in [0,%d]: %q", op, alignment, maximum, ins.Raw)
	}
	baseValue, baseType, err := c.loadZRegElements(base, baseBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / elementBits
	loadedType := fmt.Sprintf("<vscale x %d x i%d>", lanes, spec.memoryBits)
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ldff1.gather.scalar.offset.nxv%di%d.nxv%di%d(%s %s, %s %s, i64 %d)\n",
		loaded, loadedType, lanes, spec.memoryBits, lanes, elementBits, predicateType, predicateValue, baseType, baseValue, memory.Off)
	return c.finishARM64SVEFirstFaultLoad(spec, destination, elementBits, loadedType, "%"+loaded)
}

func (c *arm64Ctx) finishARM64SVEFirstFaultLoad(spec arm64SVEFirstFaultMemorySpec, destination, elementBits int, loadedType, loaded string) (ok bool, terminated bool, err error) {
	value := loaded
	if spec.memoryBits < elementBits {
		vectorType, _, err := arm64SVEVectorType(elementBits)
		if err != nil {
			return true, false, err
		}
		extended := c.newTmp()
		extension := "zext"
		if spec.signed {
			extension = "sext"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %s to %s\n", extended, extension, loadedType, value, vectorType)
		value = "%" + extended
	}
	return true, false, c.storeZRegElements(destination, elementBits, value)
}
