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

// lowerPackedIntegerInsert implements Go 1.27's yinsr/yinsrw and
// _yvpinsrb tables. The legacy forms update their X destination in place;
// the VEX/EVEX forms take a separate X base and destination.
func (c *amd64Ctx) lowerPackedIntegerInsert(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, handled := amd64PackedIntegerInsertSpecs[baseOp]
	if !handled {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && (!spec.legacy || spec.laneBits == 64) {
		return true, false, fmt.Errorf("386 %s is absent from Go 1.27's assembler tables: %q", baseOp, ins.Raw)
	}

	wantArgs := 3
	if !spec.legacy {
		wantArgs = 4
	}
	if len(ins.Args) != wantArgs || ins.Args[0].Kind != OpImm || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
		return true, false, fmt.Errorf("%s %s expects unsigned imm8, GP/memory source, %s: %q", c.goarch, baseOp, map[bool]string{true: "X destination", false: "X base, X destination"}[spec.legacy], ins.Raw)
	}

	source := ins.Args[1]
	base := ins.Args[2]
	destination := ins.Args[2]
	if !spec.legacy {
		destination = ins.Args[3]
	}
	if source.Kind == OpReg {
		if !isAMD64YrlRegister(source.Reg) || c.goarch == "386" && amd64IsExtendedGPRegister(source.Reg) {
			return true, false, fmt.Errorf("%s %s source must be an in-range general register or memory: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s source must be a general register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	if base.Kind != OpReg || destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s base and destination must be X registers: %q", c.goarch, baseOp, ins.Raw)
	}
	if spec.legacy {
		if !c.isGoLegacyXReg(destination.Reg) {
			return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's legacy X register class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !amd64EVEXVectorRegister(base, 16) || !amd64EVEXVectorRegister(destination, 16) {
		return true, false, fmt.Errorf("amd64 %s base/destination is outside Go 1.27's VEX/EVEX X register class: %q", baseOp, ins.Raw)
	}

	scalarType := amd64IntegerTypeForBits(spec.laneBits)
	scalar, err := c.evalIntSized(source, scalarType)
	if err != nil {
		return true, false, err
	}
	baseBytes, err := c.loadX(base.Reg)
	if err != nil {
		return true, false, err
	}
	lanes := 128 / spec.laneBits
	baseLanes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <%d x i%d>\n", baseLanes, baseBytes, lanes, spec.laneBits)
	inserted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %%%s, i%d %s, i32 %d\n", inserted, lanes, spec.laneBits, baseLanes, spec.laneBits, scalar, int(ins.Args[0].Imm)%lanes)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <16 x i8>\n", out, lanes, spec.laneBits, inserted)
	return true, false, c.storeX(destination.Reg, "%"+out)
}

func amd64IsExtendedGPRegister(reg Reg) bool {
	switch strings.ToUpper(string(reg)) {
	case "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15":
		return true
	default:
		return false
	}
}
