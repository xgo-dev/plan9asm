package plan9asm

import (
	"fmt"
	"strings"
)

// lowerARM64VectorMove follows the six AVMOV rows in Go's ARM64 optab.
// A vector register's lane, scalar and arrangement spellings are distinct
// operand classes: parsing their common V-number must not imply a full copy.
func (c *arm64Ctx) lowerARM64VectorMove(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VMOV" {
		return false, false, nil
	}
	form, err := parseARM64VectorTransfer(op, ins)
	if err != nil {
		return true, false, err
	}
	defer c.recordMachineVectorTransfer(form)()
	if strings.ToUpper(string(ins.Op)) != "VMOV" || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 VMOV expects two registers and no opcode suffix: %q", ins.Raw)
	}
	src, dst := ins.Args[0].Reg, ins.Args[1].Reg
	_, sourceVector := arm64ParseVReg(src)
	_, destinationVector := arm64ParseVReg(dst)
	sourceKind, sourceLane, sourceElement := arm64ParseVRegLane(src)
	destinationKind, destinationLane, destinationElement := arm64ParseVRegLane(dst)
	sourceElement = sourceElement && sourceVector
	destinationElement = destinationElement && destinationVector
	bits := func(kind byte) int {
		return map[byte]int{'B': 8, 'H': 16, 'S': 32, 'D': 64}[kind]
	}

	if sourceElement {
		elementBits := bits(sourceKind)
		if destinationElement {
			// Go case 92: INS copies one equally sized lane, preserving all
			// other destination bits. Extract before loading/writing aliases.
			if sourceKind != destinationKind {
				return true, false, fmt.Errorf("arm64 VMOV lane element sizes must match: %q", ins.Raw)
			}
			element, err := c.arm64VDUPExtractLane(src, elementBits, sourceLane)
			if err != nil {
				return true, false, err
			}
			return true, false, c.arm64InsertVectorLane(dst, elementBits, destinationLane, element)
		}
		if isARM64GeneralOrZeroReg(dst) {
			// Go case 73: UMOV zero extends B/H/S to the GP register.
			element, err := c.arm64VDUPExtractLane(src, elementBits, sourceLane)
			if err != nil {
				return true, false, err
			}
			if elementBits < 64 {
				extended := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = zext i%d %s to i64\n", extended, elementBits, element)
				element = "%" + extended
			}
			return true, false, c.storeReg(dst, element)
		}
		if destinationVector && !strings.Contains(string(dst), ".") {
			// Go case 80 shares the scalar lane-copy encoding with VDUP.
			// It writes the selected element to the low lane and zeros the
			// remainder, rather than duplicating or copying the whole source.
			return c.lowerARM64VectorDuplicate("VDUP", Instr{Op: "VDUP", Args: ins.Args, Raw: ins.Raw})
		}
		return true, false, fmt.Errorf("arm64 VMOV lane source requires R/ZR, a bare V register or a matching lane: %q", ins.Raw)
	}

	if isARM64GeneralOrZeroReg(src) {
		if destinationElement {
			// Go case 78: INS consumes the low GP element, preserving the
			// complete remainder of the 128-bit destination register.
			elementBits := bits(destinationKind)
			value, err := c.loadRegisterWidth(src, elementBits)
			if err != nil {
				return true, false, err
			}
			if elementBits < 64 {
				truncated := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", truncated, value, elementBits)
				value = "%" + truncated
			}
			return true, false, c.arm64InsertVectorLane(dst, elementBits, destinationLane, value)
		}
		arrangement, valid := parseARM64VectorArrangement(dst)
		if !destinationVector || !valid || !arm64VDUPArrangementAllowed(arrangement) {
			return true, false, fmt.Errorf("arm64 VMOV GP source requires a valid arranged vector or lane destination: %q", ins.Raw)
		}
		// Go case 82 is identical to VDUP's GP-to-arrangement form.
		return true, false, c.lowerARM64GPVectorDuplicate(src, dst, arrangement)
	}

	// Go case 83 is the ORR byte-vector alias, only B8 and B16. Q=0
	// clears the high 64 bits; a full load/store would wrongly preserve them.
	sourceArrangement, sourceArranged := parseARM64VectorArrangement(src)
	destinationArrangement, destinationArranged := parseARM64VectorArrangement(dst)
	if !sourceVector || !destinationVector || !sourceArranged || !destinationArranged ||
		sourceArrangement != destinationArrangement || sourceArrangement.elementBits != 8 ||
		(sourceArrangement.lanes != 8 && sourceArrangement.lanes != 16) {
		return true, false, fmt.Errorf("arm64 VMOV vector copy requires matching B8 or B16 arrangements: %q", ins.Raw)
	}
	value, err := c.loadARM64VectorInteger(src, sourceArrangement)
	if err != nil {
		return true, false, err
	}
	return true, false, c.storeARM64VectorInteger(dst, destinationArrangement, value)
}

func (c *arm64Ctx) arm64InsertVectorLane(dst Reg, bits, lane int, element string) error {
	value, err := c.loadARM64VectorInteger(dst, arm64VectorArrangement{elementBits: bits, lanes: 128 / bits})
	if err != nil {
		return err
	}
	inserted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %s, i32 %d\n", inserted, 128/bits, bits, value, bits, element, lane)
	return c.storeARM64VectorInteger(dst, arm64VectorArrangement{elementBits: bits, lanes: 128 / bits}, "%"+inserted)
}
