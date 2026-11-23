package plan9asm

import (
	"fmt"
	"math/bits"
	"strconv"
	"strings"
)

const (
	arm64SVELUTIOneLaneBit    = 0x00800000
	arm64SVELUTITwoLaneBits   = 0x00c00000
	arm64SVELUTIThreeLaneBits = 0x00c01000
)

type arm64SVELUTISpec struct {
	op          Op
	elementBits int
	tableCount  int
	rawBase     uint32
	laneMask    uint32
}

var arm64SVELUTISpecs = [...]arm64SVELUTISpec{
	{"ZLUTI2", 8, 1, 0x4520b000, arm64SVELUTITwoLaneBits},
	{"ZLUTI2", 16, 1, 0x4520a800, arm64SVELUTIThreeLaneBits},
	{"ZLUTI4", 8, 1, 0x4560a400, arm64SVELUTIOneLaneBit},
	{"ZLUTI4", 16, 1, 0x4520bc00, arm64SVELUTITwoLaneBits},
	{"ZLUTI4", 16, 2, 0x4520b400, arm64SVELUTITwoLaneBits},
	{"ZLUTI6", 8, 2, 0x4520ac00, 0},
	{"ZLUTI6", 16, 2, 0x4560ac00, arm64SVELUTIOneLaneBit},
}

type arm64SVELUTIForm struct {
	spec        arm64SVELUTISpec
	index       int
	lane        int // -1 for an unindexed source register.
	destination int
	table       int // The second table, if present, follows this register.
}

func arm64SVELUTIFeatures(op Op) []string {
	switch op {
	case "ZLUTI2", "ZLUTI4":
		return []string{"+lut", "+sve", "+sve2"}
	case "ZLUTI6":
		return []string{"+sve", "+sve2p3"}
	default:
		return nil
	}
}

func decodeARM64RawSVELUTI(word uint32) (arm64SVELUTIForm, bool) {
	const registers = 0x001f03ff // Zm, first Zn, Zd.
	if word&0xff200000 != 0x45200000 {
		return arm64SVELUTIForm{}, false
	}
	for _, spec := range arm64SVELUTISpecs {
		if word&^(registers|spec.laneMask) != spec.rawBase {
			continue
		}
		lane := -1
		switch spec.laneMask {
		case arm64SVELUTIThreeLaneBits:
			// ZLUTI2.H carries the least significant lane bit in bit 12.
			lane = int(word>>21&6 | word>>12&1)
		case arm64SVELUTIOneLaneBit, arm64SVELUTITwoLaneBits:
			lane = int(word&spec.laneMask) >> bits.TrailingZeros32(spec.laneMask)
		}
		return arm64SVELUTIForm{
			spec: spec, index: int(word>>16) & 31, lane: lane,
			destination: int(word) & 31, table: int(word>>5) & 31,
		}, true
	}
	return arm64SVELUTIForm{}, false
}

func arm64ParseSVERawIndexedReg(operand Operand) (register, lane int, ok bool) {
	if operand.Kind != OpReg {
		return 0, 0, false
	}
	name := strings.ToUpper(strings.TrimSpace(string(operand.Reg)))
	open := strings.IndexByte(name, '[')
	if !strings.HasPrefix(name, "Z") || open <= 1 || !strings.HasSuffix(name, "]") || strings.Contains(name[:open], ".") {
		return 0, 0, false
	}
	register, registerErr := strconv.Atoi(name[1:open])
	lane, laneErr := strconv.Atoi(name[open+1 : len(name)-1])
	return register, lane, registerErr == nil && laneErr == nil && register >= 0 && register <= 31 && lane >= 0
}

func (c *arm64Ctx) lowerARM64SVELUTI(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if arm64SVELUTIFeatures(op) == nil {
		return false, false, nil
	}
	if !strings.EqualFold(string(ins.Op), string(op)) || len(ins.Args) != 3 || ins.Args[1].Kind != OpRegList {
		return true, false, fmt.Errorf("arm64 %s expects an index source, table register list, and destination without a suffix: %q", op, ins.Raw)
	}
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !destinationOK {
		return true, false, fmt.Errorf("arm64 %s requires a typed Z destination: %q", op, ins.Raw)
	}
	tableOperands := ins.Args[1].RegList
	for _, spec := range arm64SVELUTISpecs {
		if spec.op == op && spec.elementBits == destinationBits && spec.tableCount == len(tableOperands) {
			form, err := parseARM64SVELUTIForm(spec, destination, ins)
			if err != nil {
				return true, false, err
			}
			return true, false, c.lowerARM64SVELUTIForm(form)
		}
	}
	return true, false, fmt.Errorf("arm64 %s table count or destination width is outside the Go encoder forms: %q", op, ins.Raw)
}

func parseARM64SVELUTIForm(spec arm64SVELUTISpec, destination int, ins Instr) (arm64SVELUTIForm, error) {
	form := arm64SVELUTIForm{spec: spec, destination: destination, lane: -1}
	var indexOK bool
	if spec.laneMask == 0 {
		form.index, indexOK = arm64ParseSVEBareZReg(ins.Args[0])
	} else {
		form.index, form.lane, indexOK = arm64ParseSVERawIndexedReg(ins.Args[0])
		if form.lane >= 1<<bits.OnesCount32(spec.laneMask) {
			indexOK = false
		}
	}
	if !indexOK {
		return form, fmt.Errorf("arm64 %s index source or lane is outside the Go encoder form: %q", spec.op, ins.Raw)
	}
	for ordinal, tableOperand := range ins.Args[1].RegList {
		table, tableBits, tableOK := arm64ParseSVEZElementReg(Operand{Kind: OpReg, Reg: tableOperand})
		if !tableOK || tableBits != spec.elementBits {
			return form, fmt.Errorf("arm64 %s table and destination widths must match: %q", spec.op, ins.Raw)
		}
		if ordinal == 0 {
			form.table = table
		} else if table != (form.table+1)%32 {
			return form, fmt.Errorf("arm64 %s table pair must be consecutive, including Z31-to-Z0 wrapping: %q", spec.op, ins.Raw)
		}
	}
	return form, nil
}

func (c *arm64Ctx) lowerARM64SVELUTIForm(form arm64SVELUTIForm) error {
	spec := form.spec
	index, indexType, err := c.loadZRegElements(form.index, 8)
	if err != nil {
		return err
	}
	table, vectorType, err := c.loadZRegElements(form.table, spec.elementBits)
	if err != nil {
		return err
	}
	lanes := 128 / spec.elementBits
	mnemonic := strings.ToLower(string(spec.op)[1:])
	result := c.newTmp()
	if spec.tableCount == 1 {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.lane.nxv%di%d(%s %s, %s %s, i32 %d)\n",
			result, vectorType, mnemonic, lanes, spec.elementBits, vectorType, table, indexType, index, form.lane)
		return c.storeZRegElements(form.destination, spec.elementBits, "%"+result)
	}
	second, _, err := c.loadZRegElements((form.table+1)%32, spec.elementBits)
	if err != nil {
		return err
	}
	if spec.op == "ZLUTI6" {
		// LLVM 22 has no LUTI6 intrinsic. Fixed input constraints supply a
		// consecutive native pair, even for a wrapping source pair or when
		// the destination aliases one of its source operands.
		suffix := strings.ToLower(arm64SVEElementLetter(spec.elementBits))
		indexOperand := "$3"
		if form.lane >= 0 {
			indexOperand = fmt.Sprintf("$3[%d]", form.lane)
		}
		assembly := fmt.Sprintf("luti6 $0.%[1]s, { $1.%[1]s, $2.%[1]s }, %[2]s", suffix, indexOperand)
		fmt.Fprintf(c.b, "  %%%s = call %s asm %q, %q(%s %s, %s %s, %s %s)\n",
			result, vectorType, assembly, "=w,{z30},{z31},w", vectorType, table, vectorType, second, indexType, index)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.lane.x2.nxv%di%d(%s %s, %s %s, %s %s, i32 %d)\n",
			result, vectorType, mnemonic, lanes, spec.elementBits, vectorType, table, vectorType, second, indexType, index, form.lane)
	}
	return c.storeZRegElements(form.destination, spec.elementBits, "%"+result)
}
