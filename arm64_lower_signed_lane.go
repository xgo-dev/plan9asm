package plan9asm

import "fmt"

// ARM64's SMOV family extracts a signed vector lane into a general register.
// The 32-bit destination form accepts byte and halfword lanes; the 64-bit
// destination form also accepts word lanes. A W-register write clears the
// upper half of the physical X register after sign-extending within 32 bits.
func (c *arm64Ctx) lowerARM64SignedLaneExtract(op Op, ins Instr) (bool, bool, error) {
	wide := false
	switch op {
	case "SMOV":
		wide = true
	case "SMOVW":
	default:
		return false, false, nil
	}

	if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects a vector lane and general register: %q", op, ins.Raw)
	}
	source, destination := ins.Args[0].Reg, ins.Args[1].Reg
	if _, ok := arm64ParseVReg(source); !ok || !isARM64GeneralOrZeroReg(destination) {
		return true, false, fmt.Errorf("arm64 %s requires a vector lane and general register: %q", op, ins.Raw)
	}
	kind, lane, ok := arm64ParseVRegLane(source)
	if !ok {
		return true, false, fmt.Errorf("arm64 %s requires a valid vector lane: %q", op, ins.Raw)
	}
	bits := 0
	lanes := 0
	switch kind {
	case 'B':
		bits, lanes = 8, 16
	case 'H':
		bits, lanes = 16, 8
	case 'S':
		if wide {
			bits, lanes = 32, 4
		}
	}
	if bits == 0 {
		return true, false, fmt.Errorf("arm64 %s has an invalid lane width: %q", op, ins.Raw)
	}

	vector, err := c.loadVReg(source)
	if err != nil {
		return true, false, err
	}
	lanesValue := vector
	if bits != 8 {
		bitcast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <%d x i%d>\n", bitcast, vector, lanes, bits)
		lanesValue = "%" + bitcast
	}
	extracted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", extracted, lanes, bits, lanesValue, lane)

	value := "%" + extracted
	if wide {
		extended := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext i%d %s to i64\n", extended, bits, value)
		value = "%" + extended
	} else {
		signedWord := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext i%d %s to i32\n", signedWord, bits, value)
		clearedUpper := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", clearedUpper, signedWord)
		value = "%" + clearedUpper
	}
	return true, false, c.storeReg(destination, value)
}
