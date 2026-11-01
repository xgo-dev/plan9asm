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
	f, known, err := x86AESProperties(rawOp, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	source, destination := f.sourceOperand, ins.Args[f.destination]
	for _, slot := range c.fpResults {
		if c.fixedLocal != nil {
			break
		} // its independent whole-source proof owns native local reads/results
		if slot.Type == I8 || slot.Type == I16 || slot.Type == I32 || slot.Type == I64 || slot.Type == LLVMType("float") || slot.Type == LLVMType("double") {
			// An intervening X→GP move, unrelated FP store or RET fallback
			// cannot bypass the whole original-source must-initialized proof.
			if err := c.scalarFPResultInitialized(); err != nil {
				return true, false, err
			}
			break
		}
	}
	if f.memory >= 0 {
		// Native stack bytes need their independent exact backing certificate.
		// Type 4 retains a 16-byte alignment exception for legacy SSE. A
		// logical FP value is not the original physical address and cannot
		// preserve that exception. VAES has no corresponding alignment fault.
		if !f.spec.vector && source.Kind == OpFP {
			return true, false, fmt.Errorf("%w: legacy AES FP source needs its original native storage and alignment", ErrProbeNeedsContext)
		}
		if source.Kind == OpMem &&
			!x86OrdinaryNativeMemoryOperand(source, c.goarch) &&
			!x86CallerMemoryCertified(ins, f.memory) && !c.fixedLocalMemoryCertified(ins, f.memory) {
			return true, false, fmt.Errorf("%w: AES native stack source has no original storage certificate", ErrProbeNeedsContext)
		}
		if source.Kind == OpFP {
			if err := c.validateX86PackedShiftFPSpan(source.FPOffset, f.byteWidth); err != nil {
				return true, false, err
			}
			readResult := false
			for offset := source.FPOffset; offset < source.FPOffset+int64(f.byteWidth); offset++ {
				slot, result, _ := c.fpVectorSlot(offset)
				if slot.Type != I8 && slot.Type != I16 && slot.Type != I32 && slot.Type != I64 && slot.Type != LLVMType("float") && slot.Type != LLVMType("double") {
					return true, false, fmt.Errorf("%w: AES FP byte is not declared numerical storage", ErrProbeNeedsContext)
				}
				readResult = readResult || result
			}
			if readResult {
				if err := c.scalarFPResultInitialized(); err != nil {
					return true, false, err
				}
			}
		}
	}
	var value string
	if f.memory >= 0 && !f.spec.vector && source.Kind != OpFP {
		value, err = c.emitAESNativeMemory(ins, f)
	} else {
		// VAES has no fault-suppression rows. Even a dead key-assist result
		// reads all m128 bytes, not only its numerical dwords 1 and 3.
		var key string
		key, err = c.loadX86PackedShiftBytes(source, f.byteWidth, true)
		if err == nil && f.spec.operation < x86AESInverseMix {
			var state string
			state, err = c.loadPackedCompareBytes(ins.Args[f.state], f.byteWidth)
			if err == nil {
				legacyOp := Op(strings.TrimPrefix(strings.ToUpper(string(rawOp)), "V"))
				value = c.emitAESRound(f.byteWidth, state, key, amd64AESRoundIntrinsics[legacyOp])
			}
		} else if err == nil {
			carrier, call, bytes := c.newTmp(), c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", carrier, key)
			if f.spec.operation == x86AESInverseMix {
				fmt.Fprintf(c.b, "  %%%s = call <2 x i64> @llvm.x86.aesni.aesimc(<2 x i64> %%%s)\n", call, carrier)
			} else {
				fmt.Fprintf(c.b, "  %%%s = call <2 x i64> @llvm.x86.aesni.aeskeygenassist(<2 x i64> %%%s, i8 %d)\n", call, carrier, uint8(ins.Args[0].Imm))
			}
			fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", bytes, call)
			value = "%" + bytes
		}
	}
	if err != nil {
		return true, false, err
	}
	if !f.spec.vector {
		return true, false, c.storeLegacyPackedLogical(destination, value)
	}
	return true, false, c.storePackedMoveOperand(destination, f.byteWidth, value)
}

// Retain the original legacy opcode and its complete memory envelope even
// when the result is dead, including legacy SSE's Type 4 alignment exception.
func (c *amd64Ctx) emitAESNativeMemory(ins Instr, f x86AESForm) (string, error) {
	source := f.sourceOperand
	if f.spec.operation < x86AESInverseMix {
		data, err := c.loadPackedCompareLanes(ins.Args[f.state], 16, 64, false)
		if err != nil {
			return "", err
		}
		result, err := c.emitPackedBinaryNativeMemory(source, 64, data, strings.ToLower(string(ins.Op)))
		if err != nil {
			return "", err
		}
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %s to <16 x i8>\n", value, result)
		return "%" + value, nil
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return "", err
	}
	segment := ""
	if pointerType == "ptr addrspace(256)" {
		segment = "%gs:"
	} else if pointerType == "ptr addrspace(257)" {
		segment = "%fs:"
	}
	assembly := strings.ToLower(string(ins.Op)) + " " + segment + "($1), $0"
	if f.spec.operation == x86AESKeyAssist {
		assembly = fmt.Sprintf("aeskeygenassist $$%d, %s($1), $0", uint8(ins.Args[0].Imm), segment)
	}
	call, value := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <4 x i32> asm sideeffect %q, \"=x,r,~{memory}\"(%s %s)\n", call, assembly, pointerType, pointer)
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x i32> %%%s to <16 x i8>\n", value, call)
	return "%" + value, nil
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
