package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedScalarExtractSpec struct {
	bits         int
	vector       bool
	maxImmediate int64
	allowMMX     bool
}

// amd64PackedScalarExtractSpecs models the complete Go 1.27 yextractps,
// yextr/yextrw, and AVX _yvextractps family. Immediate domains, result widths,
// encoding generation, and the legacy encoded-MMX quirk are data rather than
// repeated opcode branches.
var amd64PackedScalarExtractSpecs = map[Op]amd64PackedScalarExtractSpec{
	"EXTRACTPS":  {bits: 32, maxImmediate: 3},
	"VEXTRACTPS": {bits: 32, vector: true, maxImmediate: 255},
	"PEXTRB":     {bits: 8, maxImmediate: 255, allowMMX: true},
	"PEXTRW":     {bits: 16, maxImmediate: 255},
	"PEXTRD":     {bits: 32, maxImmediate: 255, allowMMX: true},
	"PEXTRQ":     {bits: 64, maxImmediate: 255, allowMMX: true},
	"VPEXTRB":    {bits: 8, vector: true, maxImmediate: 255},
	"VPEXTRW":    {bits: 16, vector: true, maxImmediate: 255},
	"VPEXTRD":    {bits: 32, vector: true, maxImmediate: 255},
	"VPEXTRQ":    {bits: 64, vector: true, maxImmediate: 255},
}

// lowerPackedScalarExtract implements every Go 1.27 operand form from the
// legacy yextractps/yextr/yextrw tables and the AVX
// _yvextractps/_yvpextrw tables.
func (c *amd64Ctx) lowerPackedScalarExtract(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}

	spec, recognized := amd64PackedScalarExtractSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}

	if rawOp != baseOp {
		return true, false, fmt.Errorf("amd64 %s has no instruction suffixes in Go 1.27's optab: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects $imm8, X source, GP-or-memory destination: %q", baseOp, ins.Raw)
	}
	if c.goarch == "386" && spec.bits == 64 && !spec.vector {
		return true, false, fmt.Errorf("386 %s is absent from Go 1.27's 32-bit encoding tables: %q", baseOp, ins.Raw)
	}

	sourceIndex, sourceOK := amd64ParseXReg(ins.Args[1].Reg)
	maxSourceIndex := 15
	if spec.vector {
		maxSourceIndex = 31
	}
	if c.goarch == "386" {
		maxSourceIndex = 7
	}
	if !sourceOK || sourceIndex > maxSourceIndex {
		return true, false, fmt.Errorf("amd64 %s source is outside its Go 1.27 X-register class: %q", baseOp, ins.Raw)
	}

	// The VEX entries cover both Yi8 and Yu8, while the EVEX entries (which
	// are required for X16-X31) cover only Yu8. Legacy entries also use Yu8.
	minimumImmediate := int64(0)
	if spec.vector && sourceIndex <= 15 {
		minimumImmediate = -128
	}
	if immediate := ins.Args[0].Imm; immediate < minimumImmediate || immediate > spec.maxImmediate {
		return true, false, fmt.Errorf("amd64 %s immediate is outside its Go 1.27 encoding table: %q", baseOp, ins.Raw)
	}

	destination := ins.Args[2]
	destinationReg := Reg("")
	if destination.Kind == OpReg {
		if isX86YrlRegisterForArch(destination.Reg, c.goarch) {
			destinationReg = destination.Reg
		} else if mmxIndex, mmx := amd64ParseMReg(destination.Reg); mmx && spec.allowMMX {
			// The legacy B/D/Q yextr table uses Ymm. Go therefore accepts M0-M7
			// here and encodes their ModRM numbers as AX/CX/DX/BX/SP/BP/SI/DI.
			destinationReg = amd64MMXEncodingGP(mmxIndex)
		} else {
			return true, false, fmt.Errorf("amd64 %s register destination is outside its Go 1.27 table: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(destination) {
		return true, false, fmt.Errorf("amd64 %s destination must be a GP register or memory: %q", baseOp, ins.Raw)
	}
	if destination.Kind == OpMem && !x86MemoryRegistersValidForArch(destination.Mem, c.goarch) {
		return true, false, fmt.Errorf("%s %s memory destination uses an out-of-range address register: %q", c.goarch, baseOp, ins.Raw)
	}

	source, err := c.loadX(ins.Args[1].Reg)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / spec.bits
	laneVector := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <%d x i%d>\n", laneVector, source, lanes, spec.bits)
	extracted := c.newTmp()
	lane := int(uint64(ins.Args[0].Imm) & uint64(lanes-1))
	fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %%%s, i32 %d\n", extracted, lanes, spec.bits, laneVector, lane)
	value := "%" + extracted

	if destination.Kind == OpReg {
		if spec.bits < 32 {
			widened := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = zext i%d %s to i32\n", widened, spec.bits, value)
			return true, false, c.storeRegSized(destinationReg, I32, "%"+widened)
		}
		return true, false, c.storeRegSized(destinationReg, amd64IntegerTypeForBits(spec.bits), value)
	}
	return true, false, c.storePackedScalarExtractMemory(destination, amd64IntegerTypeForBits(spec.bits), value)
}

func amd64MMXEncodingGP(index int) Reg {
	return [...]Reg{AX, CX, DX, BX, SP, BP, SI, DI}[index]
}

func (c *amd64Ctx) storePackedScalarExtractMemory(destination Operand, typ LLVMType, value string) error {
	switch destination.Kind {
	case OpMem:
		pointer, pointerType, err := c.ptrFromMem(destination.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %s, %s %s, align 1\n", typ, value, pointerType, pointer)
		return nil
	case OpSym:
		pointer, err := c.ptrFromSB(destination.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store %s %s, ptr %s, align 1\n", typ, value, pointer)
		return nil
	case OpFP:
		return c.storeFPResult(destination.FPOffset, typ, value)
	default:
		return fmt.Errorf("expected packed scalar extract memory destination, got %s", destination.String())
	}
}
