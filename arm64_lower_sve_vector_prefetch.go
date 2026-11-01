package plan9asm

import (
	"fmt"
	"strings"
)

var arm64SVEVectorPrefetchBits = map[Op]int{
	"ZPRFB": 8,
	"ZPRFH": 16,
	"ZPRFW": 32,
	"ZPRFD": 64,
}

func (c *arm64Ctx) lowerARM64SVEVectorPrefetch(op Op, ins Instr) (ok bool, terminated bool, err error) {
	elementBits, ok := arm64SVEVectorPrefetchBits[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 || ins.Args[0].Kind != OpMem {
		return true, false, fmt.Errorf("arm64 %s expects memory, Pg, prfop: %q", op, ins.Raw)
	}
	predicate, predicateOK := arm64ParseSVEPredicateBare(ins.Args[1], 7)
	hint, hintOK := arm64SVEPrefetchHint(ins.Args[2])
	if !predicateOK || !hintOK {
		return true, false, fmt.Errorf("arm64 %s requires P0..P7 and an SVE data prefetch operation: %q", op, ins.Raw)
	}
	memory := ins.Args[0].Mem
	if memory.Index != "" {
		return c.lowerARM64SVEVectorPrefetchScalarBase(op, elementBits, predicate, hint, memory, ins)
	}
	return c.lowerARM64SVEVectorPrefetchVectorBase(op, elementBits, predicate, hint, memory, ins)
}

func (c *arm64Ctx) lowerARM64SVEVectorPrefetchScalarBase(op Op, elementBits, predicate, hint int, memory MemRef, ins Instr) (ok bool, terminated bool, err error) {
	if memory.Sym != "" || memory.Segment != "" || memory.Off != 0 || memory.OffRaw != "" {
		return true, false, fmt.Errorf("arm64 %s scalar-base vector-offset address has an invalid displacement: %q", op, ins.Raw)
	}
	baseReg, baseOK := arm64SVEPhysicalMemoryBase(memory.Base)
	index, indexBits, indexOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Index})
	expectedScale := int64(elementBits / 8)
	if !baseOK || !indexOK || (indexBits != 32 && indexBits != 64) || memory.Scale != expectedScale {
		return true, false, fmt.Errorf("arm64 %s vector offset requires Zm.S/D and exact element shift: %q", op, ins.Raw)
	}
	extension := ""
	if memory.IndexExt == "" {
		if indexBits != 64 {
			return true, false, fmt.Errorf("arm64 %s unextended vector offset requires Zm.D: %q", op, ins.Raw)
		}
	} else if memory.IndexExt == ExtendUXTW {
		extension = "uxtw."
	} else if memory.IndexExt == ExtendSXTW {
		extension = "sxtw."
	} else {
		return true, false, fmt.Errorf("arm64 %s vector offset only accepts UXTW or SXTW: %q", op, ins.Raw)
	}
	base, err := c.loadReg(baseReg)
	if err != nil {
		return true, false, err
	}
	pointer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %s to ptr\n", pointer, base)
	indexValue, vectorType, err := c.loadZRegElements(index, indexBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, indexBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / indexBits
	letter := strings.ToLower(strings.TrimPrefix(string(op), "ZPRF"))
	fmt.Fprintf(c.b, "  call void @llvm.aarch64.sve.prf%s.gather.%sindex.nxv%di%d(%s %s, ptr %%%s, %s %s, i32 %d)\n",
		letter, extension, lanes, indexBits, predicateType, predicateValue, pointer, vectorType, indexValue, hint)
	return true, false, nil
}

func (c *arm64Ctx) lowerARM64SVEVectorPrefetchVectorBase(op Op, elementBits, predicate, hint int, memory MemRef, ins Instr) (ok bool, terminated bool, err error) {
	if memory.Sym != "" || memory.Segment != "" || memory.OffRaw != "" {
		return true, false, fmt.Errorf("arm64 %s vector-base address only accepts an unsigned byte offset: %q", op, ins.Raw)
	}
	base, baseBits, baseOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: memory.Base})
	alignment := int64(elementBits / 8)
	maximum := int64(31) * alignment
	if !baseOK || (baseBits != 32 && baseBits != 64) || memory.Off < 0 || memory.Off > maximum || memory.Off%alignment != 0 {
		return true, false, fmt.Errorf("arm64 %s vector-base offset must be aligned to %d and in [0,%d]: %q", op, alignment, maximum, ins.Raw)
	}
	baseValue, vectorType, err := c.loadZRegElements(base, baseBits)
	if err != nil {
		return true, false, err
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, baseBits)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / baseBits
	letter := strings.ToLower(strings.TrimPrefix(string(op), "ZPRF"))
	fmt.Fprintf(c.b, "  call void @llvm.aarch64.sve.prf%s.gather.scalar.offset.nxv%di%d(%s %s, %s %s, i64 %d, i32 %d)\n",
		letter, lanes, baseBits, predicateType, predicateValue, vectorType, baseValue, memory.Off, hint)
	return true, false, nil
}
