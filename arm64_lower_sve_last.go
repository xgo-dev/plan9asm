package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVELastSpec struct {
	intrinsic string
	baseSize  int
	vectorDst bool
}

var arm64SVELastSpecs = map[Op]arm64SVELastSpec{
	"ZLASTA":  {intrinsic: "lasta", baseSize: 3},
	"ZLASTAW": {intrinsic: "lasta"},
	"ZLASTAB": {intrinsic: "lasta", vectorDst: true},
	"ZLASTAH": {intrinsic: "lasta", baseSize: 1, vectorDst: true},
	"ZLASTAS": {intrinsic: "lasta", baseSize: 2, vectorDst: true},
	"ZLASTAD": {intrinsic: "lasta", baseSize: 3, vectorDst: true},
	"ZLASTB":  {intrinsic: "lastb", baseSize: 3},
	"ZLASTBW": {intrinsic: "lastb"},
	"ZLASTBB": {intrinsic: "lastb", vectorDst: true},
	"ZLASTBH": {intrinsic: "lastb", baseSize: 1, vectorDst: true},
	"ZLASTBS": {intrinsic: "lastb", baseSize: 2, vectorDst: true},
	"ZLASTBD": {intrinsic: "lastb", baseSize: 3, vectorDst: true},
}

// decodeARM64RawSVELast canonicalizes all Go 1.27 LASTA/LASTB aliases into
// four opcode classes. Size bits select B/H/S/D; the named lowering preserves
// the scalar or vector destination semantics of each class.
func decodeARM64RawSVELast(word uint32) (Instr, bool) {
	const variableBits = uint32(0x00c01fff)
	forms := [...]struct {
		op        Op
		base      uint32
		vectorDst bool
	}{
		{"ZLASTAW", 0x0520a000, false},
		{"ZLASTAB", 0x05228000, true},
		{"ZLASTBW", 0x0521a000, false},
		{"ZLASTBB", 0x05238000, true},
	}
	for _, form := range forms {
		if word&^variableBits != form.base {
			continue
		}
		width := [...]string{"B", "H", "S", "D"}[word>>22&3]
		source := int(word>>5) & 31
		predicate := int(word>>10) & 7
		destination := int(word) & 31
		register := Reg(fmt.Sprintf("R%d", destination))
		if form.vectorDst {
			register = Reg(fmt.Sprintf("V%d", destination))
		} else if destination == 31 {
			register = ZR
		}
		args := []Operand{
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%s", source, width))},
			{Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d", predicate))},
			{Kind: OpReg, Reg: register},
		}
		return Instr{Op: form.op, Args: args, Raw: fmt.Sprintf("WORD $%#08x", word)}, true
	}
	return Instr{}, false
}

func (c *arm64Ctx) lowerARM64SVELast(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVELastSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Zn.B/H/S/D, Pg, scalar destination without a suffix: %q", op, ins.Raw)
	}
	source, writtenBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
	predicate, predicateOK := arm64ParseSVEPredicateBare(ins.Args[1], 7)
	if !sourceOK || !predicateOK {
		return true, false, fmt.Errorf("arm64 %s requires a Z source and P0..P7: %q", op, ins.Raw)
	}
	writtenSize := map[int]int{8: 0, 16: 1, 32: 2, 64: 3}[writtenBits]
	elementBits := 8 << (spec.baseSize | writtenSize)

	var destination Reg
	if spec.vectorDst {
		var destinationOK bool
		destination, destinationOK = arm64SVEInsertVRegister(ins.Args[2])
		if !destinationOK {
			return true, false, fmt.Errorf("arm64 %s destination must be a bare V0..V31 register: %q", op, ins.Raw)
		}
	} else {
		if !arm64SVEIndexScalarRegister(ins.Args[2]) {
			return true, false, fmt.Errorf("arm64 %s destination must be R0..R30 or ZR: %q", op, ins.Raw)
		}
		destination = ins.Args[2].Reg
	}

	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return true, false, err
	}
	vectorValue, vectorType, err := c.loadZRegElements(source, elementBits)
	if err != nil {
		return true, false, err
	}
	_, lanes, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return true, false, err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i%d @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s)\n",
		result, elementBits, spec.intrinsic, lanes, elementBits, predicateType, predicateValue, vectorType, vectorValue)
	if spec.vectorDst {
		return true, false, c.storeARM64ScalarToVReg(destination, elementBits, "%"+result)
	}
	value := "%" + result
	if elementBits != 64 {
		extended := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i%d %s to i64\n", extended, elementBits, value)
		value = "%" + extended
	}
	return true, false, c.storeReg(destination, value)
}

func (c *arm64Ctx) storeARM64ScalarToVReg(register Reg, elementBits int, value string) error {
	vectorType := fmt.Sprintf("<%d x i%d>", 128/elementBits, elementBits)
	inserted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement %s zeroinitializer, i%d %s, i64 0\n", inserted, vectorType, elementBits, value)
	bytes := "%" + inserted
	if elementBits != 8 {
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", converted, vectorType, inserted)
		bytes = "%" + converted
	}
	return c.storeVReg(register, bytes)
}
