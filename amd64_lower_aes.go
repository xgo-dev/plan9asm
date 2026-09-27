package plan9asm

import (
	"fmt"
	"strings"
)

var amd64AESRoundIntrinsics = map[Op]string{
	"AESENC":     "@llvm.x86.aesni.aesenc",
	"AESENCLAST": "@llvm.x86.aesni.aesenclast",
	"AESDEC":     "@llvm.x86.aesni.aesdec",
	"AESDECLAST": "@llvm.x86.aesni.aesdeclast",
}

// lowerAES implements the complete Go 1.27 AES/VAES family. Wide VAES round
// instructions apply the corresponding 128-bit AES operation independently
// to every lane.
func (c *amd64Ctx) lowerAES(rawOp Op, ins Instr) (ok bool, terminated bool, err error) {
	raw := strings.ToUpper(string(rawOp))
	parts := strings.Split(raw, ".")
	baseOp := Op(parts[0])
	switch baseOp {
	case "AESENC", "AESENCLAST", "AESDEC", "AESDECLAST", "AESIMC", "AESKEYGENASSIST",
		"VAESENC", "VAESENCLAST", "VAESDEC", "VAESDECLAST", "VAESIMC", "VAESKEYGENASSIST":
		// handled below; keep the literal family visible to supported-op extraction
	default:
		return false, false, nil
	}
	legacyOp := baseOp
	vector := strings.HasPrefix(string(baseOp), "V")
	if vector {
		legacyOp = Op(strings.TrimPrefix(string(baseOp), "V"))
	}
	_, round := amd64AESRoundIntrinsics[legacyOp]
	if len(parts) != 1 {
		return true, false, fmt.Errorf("amd64 %s does not accept instruction suffixes in Go 1.27: %q", baseOp, ins.Raw)
	}

	if round {
		return c.lowerAESRound(baseOp, legacyOp, vector, ins)
	}
	if legacyOp == "AESIMC" {
		return c.lowerAESInverseMixColumns(baseOp, ins)
	}
	return c.lowerAESKeygenAssist(baseOp, vector, ins)
}

func (c *amd64Ctx) lowerAESRound(baseOp, legacyOp Op, vector bool, ins Instr) (bool, bool, error) {
	if !vector {
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 %s expects X/m128, X: %q", baseOp, ins.Raw)
		}
		key, destination := ins.Args[0], ins.Args[1]
		if !c.isGoVEXVectorRegister(key, 16, true) || !c.isGoVEXVectorRegister(destination, 16, false) {
			return true, false, fmt.Errorf("amd64 %s operands are outside Go 1.27's X/m128, X classes: %q", baseOp, ins.Raw)
		}
		keyBytes, err := c.loadPackedCompareBytes(key, 16)
		if err != nil {
			return true, false, err
		}
		stateBytes, err := c.loadX(destination.Reg)
		if err != nil {
			return true, false, err
		}
		result := c.emitAESRound(16, stateBytes, keyBytes, amd64AESRoundIntrinsics[legacyOp])
		return true, false, c.storeX(destination.Reg, result)
	}

	if len(ins.Args) != 3 {
		return true, false, fmt.Errorf("amd64 %s expects X|Y|Z/mem, X|Y|Z, X|Y|Z: %q", baseOp, ins.Raw)
	}
	key, state, destination := ins.Args[0], ins.Args[1], ins.Args[2]
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if destination.Kind != OpReg || byteWidth != 16 && byteWidth != 32 && byteWidth != 64 || !c.isGoEVEXVectorRegister(destination, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s destination is outside Go 1.27's X/Y/Z classes: %q", baseOp, ins.Raw)
	}
	if !c.isGoEVEXVectorRegister(state, byteWidth) {
		return true, false, fmt.Errorf("amd64 %s state source must match the destination width: %q", baseOp, ins.Raw)
	}
	if key.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(key, byteWidth) {
			return true, false, fmt.Errorf("amd64 %s key source must match the destination width: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(key) {
		return true, false, fmt.Errorf("amd64 %s key source must be a vector register or memory: %q", baseOp, ins.Raw)
	}
	keyBytes, err := c.loadPackedCompareBytes(key, byteWidth)
	if err != nil {
		return true, false, err
	}
	stateBytes, err := c.loadPackedCompareBytes(state, byteWidth)
	if err != nil {
		return true, false, err
	}
	result := c.emitAESRound(byteWidth, stateBytes, keyBytes, amd64AESRoundIntrinsics[legacyOp])
	return true, false, c.storeVectorBytes(destination.Reg, byteWidth, result)
}

func (c *amd64Ctx) lowerAESInverseMixColumns(baseOp Op, ins Instr) (bool, bool, error) {
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("amd64 %s expects X/m128, X: %q", baseOp, ins.Raw)
	}
	source, destination := ins.Args[0], ins.Args[1]
	if !c.isGoVEXVectorRegister(source, 16, true) || !c.isGoVEXVectorRegister(destination, 16, false) {
		return true, false, fmt.Errorf("amd64 %s operands are outside Go 1.27's VEX X/m128, X classes: %q", baseOp, ins.Raw)
	}
	sourceBytes, err := c.loadPackedCompareBytes(source, 16)
	if err != nil {
		return true, false, err
	}
	sourceI64 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", sourceI64, sourceBytes)
	call := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <2 x i64> @llvm.x86.aesni.aesimc(<2 x i64> %%%s)\n", call, sourceI64)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", result, call)
	return true, false, c.storeX(destination.Reg, "%"+result)
}

func (c *amd64Ctx) lowerAESKeygenAssist(baseOp Op, vector bool, ins Instr) (bool, bool, error) {
	validImmediate := len(ins.Args) == 3 && amd64UnsignedImmediate(ins.Args[0], 8)
	if vector {
		validImmediate = len(ins.Args) == 3 && amd64VectorByteShiftImmediate(ins.Args[0])
	}
	if !validImmediate {
		return true, false, fmt.Errorf("amd64 %s expects $imm8, X/m128, X: %q", baseOp, ins.Raw)
	}
	source, destination := ins.Args[1], ins.Args[2]
	if !c.isGoVEXVectorRegister(source, 16, true) || !c.isGoVEXVectorRegister(destination, 16, false) {
		return true, false, fmt.Errorf("amd64 %s operands are outside Go 1.27's VEX X/m128, X classes: %q", baseOp, ins.Raw)
	}
	sourceBytes, err := c.loadPackedCompareBytes(source, 16)
	if err != nil {
		return true, false, err
	}
	sourceI64 := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", sourceI64, sourceBytes)
	call := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <2 x i64> @llvm.x86.aesni.aeskeygenassist(<2 x i64> %%%s, i8 %d)\n", call, sourceI64, uint8(ins.Args[0].Imm))
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", result, call)
	return true, false, c.storeX(destination.Reg, "%"+result)
}

func (c *amd64Ctx) emitAESRound(byteWidth int, stateBytes, keyBytes, intrinsic string) string {
	qwords := byteWidth / 8
	state := c.newTmp()
	key := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i64>\n", state, byteWidth, stateBytes, qwords)
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i64>\n", key, byteWidth, keyBytes, qwords)
	result := "zeroinitializer"
	for lane := 0; lane < byteWidth/16; lane++ {
		laneState := c.newTmp()
		laneKey := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i64> %%%s, <%d x i64> poison, <2 x i32> <i32 %d, i32 %d>\n", laneState, qwords, state, qwords, lane*2, lane*2+1)
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i64> %%%s, <%d x i64> poison, <2 x i32> <i32 %d, i32 %d>\n", laneKey, qwords, key, qwords, lane*2, lane*2+1)
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <2 x i64> %s(<2 x i64> %%%s, <2 x i64> %%%s)\n", call, intrinsic, laneState, laneKey)
		for word := 0; word < 2; word++ {
			extracted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 %d\n", extracted, call, word)
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i64> %s, i64 %%%s, i32 %d\n", inserted, qwords, result, extracted, lane*2+word)
			result = "%" + inserted
		}
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i64> %s to <%d x i8>\n", bytes, qwords, result, byteWidth)
	return "%" + bytes
}
