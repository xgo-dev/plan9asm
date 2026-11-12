package plan9asm

import (
	"fmt"
	"strings"
)

type arm64VectorTransferForm struct {
	source, destination Reg
	bits, lanes         int
	sourceLane          int
	destinationLane     int
	sourceGP            bool
	destinationGP       bool
	splat               bool
	copy                bool
	preserve            bool
}

// VMOV's six rows and VDUP's three rows are distinct operand classes. The
// physical element width of VDUP's arranged destination selects its source
// lane width, including the mixed-suffix spellings accepted by Go case 79.
func parseARM64VectorTransfer(op Op, ins Instr) (arm64VectorTransferForm, error) {
	f := arm64VectorTransferForm{}
	invalid := func() (arm64VectorTransferForm, error) {
		return f, fmt.Errorf("arm64 %s operands are outside the complete Go vector transfer rows: %q", op, ins.Raw)
	}
	if (op != "VMOV" && op != "VDUP") || !strings.EqualFold(string(ins.Op), string(op)) || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return invalid()
	}
	f.source, f.destination = ins.Args[0].Reg, ins.Args[1].Reg
	sourceKind, sourceLane, sourceElement := arm64ParseVRegLane(f.source)
	destinationKind, destinationLane, destinationElement := arm64ParseVRegLane(f.destination)
	_, sourceVector := arm64ParseVReg(f.source)
	_, destinationVector := arm64ParseVReg(f.destination)
	destination, arranged := parseARM64VectorArrangement(f.destination)
	bits := func(kind byte) int {
		switch kind {
		case 'B':
			return 8
		case 'H':
			return 16
		case 'S':
			return 32
		case 'D':
			return 64
		}
		return 0
	}
	if op == "VDUP" {
		if arranged {
			// Go case79 checks the index against the destination's physical
			// width. The source suffix is an ELEM class, not its lane bound.
			sourceLane, sourceElement = arm64VDUPPhysicalLaneIndex(f.source)
		}
		if sourceElement && sourceVector {
			f.bits, f.sourceLane = bits(sourceKind), sourceLane
			if arranged && arm64VDUPArrangementAllowed(destination) {
				f.bits, f.lanes, f.splat = destination.elementBits, destination.lanes, true
				if sourceLane < 128/f.bits {
					return f, nil
				}
			} else if destinationVector && !strings.Contains(string(f.destination), ".") {
				f.lanes = 1
				return f, nil
			}
			return invalid()
		}
		if isARM64GeneralOrZeroReg(f.source) && arranged && arm64VDUPArrangementAllowed(destination) {
			f.bits, f.lanes, f.sourceGP, f.splat = destination.elementBits, destination.lanes, true, true
			return f, nil
		}
		return invalid()
	}
	if sourceElement && sourceVector {
		f.bits, f.sourceLane = bits(sourceKind), sourceLane
		switch {
		case destinationElement && destinationVector && sourceKind == destinationKind:
			f.destinationLane, f.preserve, f.lanes = destinationLane, true, 1
		case isARM64GeneralOrZeroReg(f.destination):
			f.destinationGP, f.lanes = true, 1
		case destinationVector && !strings.Contains(string(f.destination), "."):
			f.lanes = 1
		default:
			return invalid()
		}
		return f, nil
	}
	if isARM64GeneralOrZeroReg(f.source) {
		f.sourceGP = true
		if destinationElement && destinationVector {
			f.bits, f.destinationLane, f.preserve, f.lanes = bits(destinationKind), destinationLane, true, 1
			return f, nil
		}
		if arranged && arm64VDUPArrangementAllowed(destination) {
			f.bits, f.lanes, f.splat = destination.elementBits, destination.lanes, true
			return f, nil
		}
		return invalid()
	}
	source, sourceArranged := parseARM64VectorArrangement(f.source)
	if sourceVector && destinationVector && sourceArranged && arranged && source == destination &&
		source.elementBits == 8 && (source.lanes == 8 || source.lanes == 16) {
		f.bits, f.lanes, f.copy = 8, source.lanes, true
		return f, nil
	}
	return invalid()
}

// This syntax-only element parser is restricted to VDUP's arranged case79.
// VMOV and scalar VDUP retain their own suffix-selected lane bounds.
func arm64VDUPPhysicalLaneIndex(reg Reg) (int, bool) {
	if _, valid := arm64ParseVReg(reg); !valid {
		return 0, false
	}
	text := strings.ToUpper(strings.TrimSpace(string(reg)))
	dot := strings.IndexByte(text, '.')
	if dot < 0 {
		return 0, false
	}
	suffix := text[dot+1:]
	if len(suffix) < 4 || !strings.ContainsRune("BHSD", rune(suffix[0])) || suffix[1] != '[' || suffix[len(suffix)-1] != ']' {
		return 0, false
	}
	index, valid := arm64ParseLaneDecimalToken(suffix[2 : len(suffix)-1])
	return index, valid && index < 16
}
