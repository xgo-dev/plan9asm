package plan9asm

import (
	"fmt"
	"strings"
)

// lowerInsertPackedSingle implements all forms in Go 1.27's yxshuf and
// _yvinsertps tables. The imm8 selects the register-source lane in bits 7:6,
// the destination lane in bits 5:4, and lanes to clear in bits 3:0.
func (c *amd64Ctx) lowerInsertPackedSingle(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	if baseOp != "INSERTPS" && baseOp != "VINSERTPS" {
		return false, false, nil
	}
	var bindingErr error
	ins, _, _, bindingErr = c.bindInsertExtractForm(op, ins)
	if bindingErr != nil {
		return true, false, bindingErr
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", baseOp, ins.Raw)
	}
	wantArgs := 3
	if baseOp == "VINSERTPS" {
		wantArgs = 4
	}
	if len(ins.Args) != wantArgs || ins.Args[0].Kind != OpImm || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
		return true, false, fmt.Errorf("amd64 %s expects unsigned imm8, X/m32 source, %s: %q", baseOp, map[bool]string{false: "X destination", true: "X base, X destination"}[baseOp == "VINSERTPS"], ins.Raw)
	}

	source := ins.Args[1]
	base := ins.Args[2]
	destination := ins.Args[2]
	if baseOp == "VINSERTPS" {
		destination = ins.Args[3]
	}
	if base.Kind != OpReg || destination.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects X base/destination registers: %q", baseOp, ins.Raw)
	}
	if baseOp == "INSERTPS" {
		if !c.isGoLegacyXReg(base.Reg) {
			return true, false, fmt.Errorf("%s INSERTPS destination is outside Go 1.27's X register class: %q", c.goarch, ins.Raw)
		}
	} else if !amd64EVEXVectorRegister(base, 16) || !amd64EVEXVectorRegister(destination, 16) {
		return true, false, fmt.Errorf("%s VINSERTPS base/destination is outside Go 1.27's VEX/EVEX X register class: %q", c.goarch, ins.Raw)
	}

	var inserted string
	if source.Kind == OpReg {
		valid := c.isGoLegacyXReg(source.Reg)
		if baseOp == "VINSERTPS" {
			valid = amd64EVEXVectorRegister(source, 16)
		}
		if !valid {
			return true, false, fmt.Errorf("%s %s source is outside Go 1.27's X register class: %q", c.goarch, baseOp, ins.Raw)
		}
		sourceBytes, err := c.loadX(source.Reg)
		if err != nil {
			return true, false, err
		}
		sourceLanes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", sourceLanes, sourceBytes)
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <4 x i32> %%%s, i32 %d\n", selected, sourceLanes, (ins.Args[0].Imm>>6)&3)
		inserted = "%" + selected
	} else if source.Kind == OpFP {
		// An original m32 FP span can comprise four independent ABI0
		// shadow fields. It is not a contiguous load from the first alloca.
		value, err := c.loadFPVectorBytes(source.FPOffset, 4)
		if err != nil {
			return true, false, err
		}
		bits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i8> %s to i32\n", bits, value)
		inserted = "%" + bits
	} else {
		if !isAMD64MemoryOperand(source) {
			return true, false, fmt.Errorf("amd64 %s expects an X register or memory source: %q", baseOp, ins.Raw)
		}
		pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
		if err != nil {
			return true, false, err
		}
		bits := c.newTmp()
		// INSERTPS always reads m32, even when imm8 subsequently clears it.
		fmt.Fprintf(c.b, "  %%%s = load volatile i32, %s %s, align 1\n", bits, pointerType, pointer)
		inserted = "%" + bits
	}

	baseBytes, err := c.loadX(base.Reg)
	if err != nil {
		return true, false, err
	}
	baseLanes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <4 x i32>\n", baseLanes, baseBytes)
	placed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> %%%s, i32 %s, i32 %d\n", placed, baseLanes, inserted, (ins.Args[0].Imm>>4)&3)
	result := "%" + placed
	for lane := 0; lane < 4; lane++ {
		if ins.Args[0].Imm&(1<<lane) == 0 {
			continue
		}
		cleared := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <4 x i32> %s, i32 0, i32 %d\n", cleared, result, lane)
		result = "%" + cleared
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %s to <16 x i8>\n", out, result)
	if baseOp == "VINSERTPS" {
		return true, false, c.storePackedMoveOperand(destination, 16, "%"+out)
	}
	return true, false, c.storeLegacyPackedLogical(destination, "%"+out)
}
