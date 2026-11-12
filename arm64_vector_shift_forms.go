package plan9asm

import (
	"fmt"
	"strings"
)

type arm64VectorShiftRightSpec struct {
	signed, rounding, accumulate bool
}

var arm64VectorShiftRightSpecs = map[Op]arm64VectorShiftRightSpec{
	"VSSHR": {signed: true}, "VSSRA": {signed: true, accumulate: true},
	"VSRSHR": {signed: true, rounding: true}, "VSRSRA": {signed: true, rounding: true, accumulate: true},
	"VUSHR": {}, "VUSRA": {accumulate: true},
	"VURSHR": {rounding: true}, "VURSRA": {rounding: true, accumulate: true},
}

type arm64VectorShiftForm struct {
	arrangement         arm64VectorArrangement
	source, destination Reg
	shift               int64
	scalar              bool
}

func parseARM64VectorShift(op Op, ins Instr) (arm64VectorShiftForm, error) {
	f := arm64VectorShiftForm{}
	_, right := arm64VectorShiftRightSpecs[op]
	if (op != "VSHL" && !right) || !strings.EqualFold(string(ins.Op), string(op)) || len(ins.Args) != 3 ||
		ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat ||
		ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
		return f, fmt.Errorf("arm64 %s expects a resolved integer shift and matching vector operands: %q", op, ins.Raw)
	}
	f.source, f.destination, f.shift = ins.Args[1].Reg, ins.Args[2].Reg, ins.Args[0].Imm
	source, sourceValid := parseARM64VectorArrangement(f.source)
	destination, destinationValid := parseARM64VectorArrangement(f.destination)
	f.scalar = right && !strings.Contains(string(f.source), ".") && !strings.Contains(string(f.destination), ".")
	if f.scalar {
		_, sourceValid = arm64ParseVReg(f.source)
		_, destinationValid = arm64ParseVReg(f.destination)
		source = arm64VectorArrangement{elementBits: 64, lanes: 1}
		destination = source
	}
	if !sourceValid || !destinationValid || source != destination || !f.scalar && !arm64VDUPArrangementAllowed(source) {
		return f, fmt.Errorf("arm64 %s requires matching Go vector arrangements: %q", op, ins.Raw)
	}
	minimum, maximum := int64(0), int64(source.elementBits-1)
	if right {
		minimum, maximum = 1, int64(source.elementBits)
	}
	if f.shift < minimum || f.shift > maximum {
		return f, fmt.Errorf("arm64 %s shift must be in [%d,%d]: %q", op, minimum, maximum, ins.Raw)
	}
	f.arrangement = source
	return f, nil
}
