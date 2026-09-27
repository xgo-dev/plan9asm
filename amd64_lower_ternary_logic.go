package plan9asm

import (
	"fmt"
	"strings"
)

// amd64TernaryLogicSpecs is the complete Go 1.27 VPTERNLOG family. Both
// opcodes use _yvalignd; the only difference is the D/Q mask-lane and
// broadcast width.
var amd64TernaryLogicSpecs = map[Op]int{
	"VPTERNLOGD": 32,
	"VPTERNLOGQ": 64,
}

func (c *amd64Ctx) lowerTernaryLogic(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	laneBits, recognized := amd64TernaryLogicSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	// The 386 obj assembler rejects this family's required four/five source
	// operands before it reaches _yvalignd. Mirror that frontend behavior.
	if c.goarch != "amd64" {
		return true, false, fmt.Errorf("%s %s is rejected by Go 1.27's x86 assembler operand limit: %q", c.goarch, baseOp, ins.Raw)
	}

	broadcast, zeroing := false, false
	switch suffix {
	case "":
	case "Z":
		zeroing = true
	case "BCST":
		broadcast = true
	case "BCST.Z":
		broadcast, zeroing = true, true
	default:
		return true, false, fmt.Errorf("amd64 %s has a suffix absent from Go 1.27's EVEX encoding: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 4 && len(ins.Args) != 5 {
		return true, false, fmt.Errorf("amd64 %s expects unsigned-imm8, src1, src2, [K mask,] destination: %q", baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 5
	if zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s zeroing requires a K1-K7 mask: %q", baseOp, ins.Raw)
	}
	if ins.Args[0].Kind != OpImm || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
		return true, false, fmt.Errorf("amd64 %s first operand must be Go 1.27's unsigned-imm8 class: %q", baseOp, ins.Raw)
	}

	dstArg := ins.Args[len(ins.Args)-1]
	if dstArg.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s destination must be an X, Y, or Z register: %q", baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(dstArg.Reg)
	if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 || !amd64EVEXVectorRegister(dstArg, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s destination is outside Go 1.27's EVEX vector class: %q", baseOp, ins.Raw)
	}
	if !amd64EVEXVectorRegister(ins.Args[2], byteWidth) {
		return true, false, fmt.Errorf("amd64 %s second source must be a same-width EVEX vector register: %q", baseOp, ins.Raw)
	}
	if broadcast {
		if !isAMD64MemoryOperand(ins.Args[1]) {
			return true, false, fmt.Errorf("amd64 %s.BCST requires a memory first source: %q", baseOp, ins.Raw)
		}
	} else if ins.Args[1].Kind == OpReg {
		if !amd64EVEXVectorRegister(ins.Args[1], byteWidth) {
			return true, false, fmt.Errorf("amd64 %s first source must match the destination width: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("amd64 %s first source must be a vector register or memory: %q", baseOp, ins.Raw)
	}

	var mask string
	if masked {
		if !amd64NonzeroKOperand(ins.Args[3]) {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		mask, err = c.loadK(ins.Args[3].Reg)
		if err != nil {
			return true, false, err
		}
	}

	var firstBytes string
	if broadcast {
		lanes := byteWidth * 8 / laneBits
		scalar, loadErr := c.evalIntSized(ins.Args[1], amd64IntegerTypeForBits(laneBits))
		if loadErr != nil {
			return true, false, loadErr
		}
		firstLanes := amd64SplatInteger(c, lanes, laneBits, scalar)
		cast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", cast, lanes, laneBits, firstLanes, byteWidth)
		firstBytes = "%" + cast
	} else {
		firstBytes, err = c.loadPackedCompareBytes(ins.Args[1], byteWidth)
		if err != nil {
			return true, false, err
		}
	}
	secondBytes, err := c.loadPackedCompareBytes(ins.Args[2], byteWidth)
	if err != nil {
		return true, false, err
	}
	oldBytes, err := c.loadPackedCompareBytes(dstArg, byteWidth)
	if err != nil {
		return true, false, err
	}

	// Intel names the inputs A=old destination, B=EVEX.vvvv, C=EVEX.r/m.
	// Go's Zevex_i_rm_v_r source order is therefore imm, C, B, A.
	resultBytes := c.emitTernaryLogicBytes(byteWidth, uint8(ins.Args[0].Imm), oldBytes, secondBytes, firstBytes)
	if masked {
		lanes := byteWidth * 8 / laneBits
		computed := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, resultBytes)
		old := c.bitcastVectorBytesToIntegerLanes(byteWidth, lanes, laneBits, oldBytes)
		result := amd64ApplyIntegerLaneMask(c, lanes, laneBits, computed, old, mask, zeroing)
		cast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", cast, lanes, laneBits, result, byteWidth)
		resultBytes = "%" + cast
	}
	return true, false, c.storeVectorBytes(dstArg.Reg, byteWidth, resultBytes)
}

// emitTernaryLogicBytes evaluates all 256 bitwise Boolean truth tables. The
// immediate bit selected for an input tuple is (A<<2)|(B<<1)|C, matching the
// Intel/Clang _MM_TERNLOG_A/B/C constants F0/CC/AA.
func (c *amd64Ctx) emitTernaryLogicBytes(byteWidth int, immediate uint8, a, b, third string) string {
	switch immediate {
	case 0x00:
		return "zeroinitializer"
	case 0xff:
		return llvmAllOnesI8Vec(byteWidth)
	case 0xf0:
		return a
	case 0xcc:
		return b
	case 0xaa:
		return third
	}

	inputs := []string{a, b, third}
	inverted := make([]string, len(inputs))
	for index, input := range inputs {
		name := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor <%d x i8> %s, %s\n", name, byteWidth, input, llvmAllOnesI8Vec(byteWidth))
		inverted[index] = "%" + name
	}

	result := ""
	for truthIndex := 0; truthIndex < 8; truthIndex++ {
		truthA := truthIndex&4 != 0
		truthB := truthIndex&2 != 0
		truthC := truthIndex&1 != 0
		if !amd64TernaryLogicBit(immediate, truthA, truthB, truthC) {
			continue
		}
		termInputs := make([]string, 3)
		for inputIndex := range inputs {
			truthBit := 2 - inputIndex
			if truthIndex&(1<<truthBit) != 0 {
				termInputs[inputIndex] = inputs[inputIndex]
			} else {
				termInputs[inputIndex] = inverted[inputIndex]
			}
		}
		firstAnd := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and <%d x i8> %s, %s\n", firstAnd, byteWidth, termInputs[0], termInputs[1])
		term := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and <%d x i8> %%%s, %s\n", term, byteWidth, firstAnd, termInputs[2])
		if result == "" {
			result = "%" + term
			continue
		}
		merged := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or <%d x i8> %s, %%%s\n", merged, byteWidth, result, term)
		result = "%" + merged
	}
	return result
}

func amd64TernaryLogicBit(immediate uint8, a, b, third bool) bool {
	truthIndex := 0
	if a {
		truthIndex |= 4
	}
	if b {
		truthIndex |= 2
	}
	if third {
		truthIndex |= 1
	}
	return immediate&(1<<truthIndex) != 0
}
