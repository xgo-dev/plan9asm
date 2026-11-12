package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedIntegerInsertSpec struct {
	laneBits int
	legacy   bool
}

var amd64PackedIntegerInsertSpecs = map[string]amd64PackedIntegerInsertSpec{
	"PINSRB":  {laneBits: 8, legacy: true},
	"PINSRW":  {laneBits: 16, legacy: true},
	"PINSRD":  {laneBits: 32, legacy: true},
	"PINSRQ":  {laneBits: 64, legacy: true},
	"VPINSRB": {laneBits: 8},
	"VPINSRW": {laneBits: 16},
	"VPINSRD": {laneBits: 32},
	"VPINSRQ": {laneBits: 64},
}

func (c *amd64Ctx) lowerPackedIntegerInsert(op Op, ins Instr) (ok bool, terminated bool, err error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := amd64PackedIntegerInsertSpecs[base]; !known {
		return false, false, nil
	}
	ins, f, _, err := c.bindScalarLaneForm(op, ins)
	if err != nil {
		return true, false, err
	}
	source := ins.Args[f.source]
	if source.Kind == OpReg {
		source.Reg = f.transferReg
	}
	// Exact native m8/m16/m32/m64 reads remain volatile; FP uses the
	// independent complete-byte-span helper, not the first scalar slot.
	var scalar string
	if source.Kind == OpFP {
		scalar, err = c.loadScalarLaneFPBits(source.FPOffset, f.bits)
	} else {
		scalar, err = c.loadGPSIMDTransferSource(source, f.bits)
	}
	if err != nil {
		return true, false, err
	}
	baseBytes, err := c.loadX(ins.Args[f.base].Reg)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / f.bits
	baseLanes, inserted, out := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <%d x i%d>\n", baseLanes, baseBytes, lanes, f.bits)
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %%%s, i%d %s, i32 %d\n", inserted, lanes, f.bits, baseLanes, f.bits, scalar, f.offset/(f.bits/8))
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <16 x i8>\n", out, lanes, f.bits, inserted)
	if f.legacy {
		return true, false, c.storeX(ins.Args[f.destination].Reg, "%"+out)
	}
	return true, false, c.storePackedMoveOperand(ins.Args[f.destination], 16, "%"+out)
}

func amd64IsExtendedGPRegister(reg Reg) bool {
	switch strings.ToUpper(string(reg)) {
	case "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15":
		return true
	default:
		return false
	}
}
