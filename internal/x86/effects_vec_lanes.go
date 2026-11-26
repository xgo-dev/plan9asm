package x86

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// x86VecByteShiftCount normalizes the immediate byte-shift count for
// PSLLDQ/PSRLDQ/PSLLO/PSRLO/VPSLLDQ/VPSRLDQ so the ABI0 checker and all
// lowerers share one exact Intel SDM imm8 rule: accept [-128, 255], interpret
// as unsigned imm8 (uint8(imm)), and saturate counts > 16 to 16 (full zero).
func x86VecByteShiftCount(op asm.Op, imm int64) (int64, error) {
	if imm < -128 || imm > 255 {
		return 0, fmt.Errorf("amd64 %s invalid imm %d", op, imm)
	}
	n := int64(uint8(imm))
	if n > 16 {
		n = 16
	}
	return n, nil
}

// handleX86VecLaneOp models lane-selecting, lane-inserting, half-register move,
// and byte-shift vector instructions with exact per-byte initialization,
// per-bit definedness, and per-byte SP-taint tracking so unselected vector
// lanes containing undefined bits do not spuriously poison valid extracts.
func handleX86VecLaneOp(
	st *abi0State,
	op asm.Op,
	ins asm.Instr,
	goarch string,
	wordMask uint8,
	wordBitMask uint64,
	checkGPRead func(*abi0State, asm.Reg, uint8, string) error,
	evalOperand func(*abi0State, asm.Operand, int64, bool, asm.Op, string) (opEvalResult, error),
	evalOperandTaintSP func(*abi0State, asm.Operand, int64, bool, asm.Op) (uint64, bool),
	writeDstMask func(*abi0State, asm.Operand, int64, uint64, uint64, [64]uint8, asm.Op, asm.OpSpec, bool, bool, uint64, bool, bool) error,
) (bool, error) {
	name := strings.ToUpper(string(op))
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	ptrBytes := int64(8)
	if goarch == "386" {
		ptrBytes = 4
	}
	checkDstMemAddr := func(dst asm.Operand) error {
		if dst.Kind != asm.OpMem {
			return nil
		}
		if dst.Mem.Base != "" && dst.Mem.Base != asm.SP && dst.Mem.Base != asm.PC {
			if err := checkGPRead(st, dst.Mem.Base, wordMask, ins.Raw); err != nil {
				return err
			}
		}
		if dst.Mem.Index != "" {
			if err := checkGPRead(st, dst.Mem.Index, wordMask, ins.Raw); err != nil {
				return err
			}
		}
		return nil
	}

	readVecSlice := func(srcIdx int, byteOff, width int64) (valMask, valBitDef uint64, fullBD [64]uint8, taintMask uint64, anyTaint bool) {
		srcInit := st.vecBytesInit[srcIdx]
		srcBD := st.vecByteBitDef[srcIdx]
		srcTaint := st.vecBytesTaintedSP[srcIdx]
		for b := int64(0); b < width && byteOff+b < 64; b++ {
			sb := byteOff + b
			if (srcInit & (uint64(1) << uint(sb))) != 0 {
				valMask |= uint64(1) << uint(b)
				bd := srcBD[sb]
				fullBD[b] = bd
				if b < 8 {
					valBitDef |= uint64(bd) << uint(b*8)
				}
			}
			if (srcTaint & (uint64(1) << uint(sb))) != 0 {
				taintMask |= uint64(1) << uint(b)
				anyTaint = true
			}
		}
		return
	}

	// 1. Element extracts: PEXTR{B,W,D,Q} / VPEXTR{B,W,D,Q} / EXTRACTPS / VEXTRACTPS.
	var extWidth, extLaneMask int64
	switch name {
	case "PEXTRB", "VPEXTRB":
		extWidth, extLaneMask = 1, 15
	case "PEXTRW", "VPEXTRW":
		extWidth, extLaneMask = 2, 7
	case "PEXTRD", "VPEXTRD", "EXTRACTPS", "VEXTRACTPS":
		extWidth, extLaneMask = 4, 3
	case "PEXTRQ", "VPEXTRQ":
		extWidth, extLaneMask = 8, 1
	}
	if extWidth > 0 && len(ins.Args) == 3 && ins.Args[0].Kind == asm.OpImm && ins.Args[1].Kind == asm.OpReg {
		if srcIdx, ok := anyVecRegIndex(ins.Args[1].Reg); ok {
			dst := ins.Args[2]
			if err := checkDstMemAddr(dst); err != nil {
				return true, err
			}
			byteOff := (ins.Args[0].Imm & extLaneMask) * extWidth
			valMask, valBitDef, fullBD, taintMask, anyTaint := readVecSlice(srcIdx, byteOff, extWidth)
			writeW := extWidth
			if dst.Kind == asm.OpReg {
				if _, isVec := anyVecRegIndex(dst.Reg); !isVec && !isAMD64KReg(dst.Reg) && !isAMD64MReg(dst.Reg) {
					// GP destinations of PEXTRB/PEXTRW/PEXTRD/EXTRACTPS zero-extend
					// upper bytes to 32/64 bits (known 0 = initialized & bit-defined).
					if extWidth < ptrBytes {
						for b := extWidth; b < ptrBytes; b++ {
							valMask |= uint64(1) << uint(b)
							fullBD[b] = 0xff
							if b < 8 {
								valBitDef |= uint64(0xff) << uint(b*8)
							}
						}
						writeW = ptrBytes
					}
				}
			}
			specExt := asm.OpSpec{Op: op, Width: uint16(writeW * 8), Effect: asm.EffectWriteOnly}
			return true, writeDstMask(st, dst, writeW, valMask, valBitDef, fullBD, op, specExt, true, st.vecFromRaw[srcIdx], taintMask, anyTaint, true)
		}
	}

	// 2. Subvector extracts: VEXTRACT{F,I}128 / VEXTRACT{F,I}{32X4,64X2,32X8,64X4}.
	var subExtWidth int64
	switch name {
	case "VEXTRACTF128", "VEXTRACTI128", "VEXTRACTF32X4", "VEXTRACTI32X4", "VEXTRACTF64X2", "VEXTRACTI64X2":
		subExtWidth = 16
	case "VEXTRACTF32X8", "VEXTRACTI32X8", "VEXTRACTF64X4", "VEXTRACTI64X4":
		subExtWidth = 32
	}
	if subExtWidth > 0 && len(ins.Args) == 3 && ins.Args[0].Kind == asm.OpImm && ins.Args[1].Kind == asm.OpReg {
		if srcIdx, ok := anyVecRegIndex(ins.Args[1].Reg); ok {
			dst := ins.Args[2]
			if err := checkDstMemAddr(dst); err != nil {
				return true, err
			}
			laneMask := int64(1)
			if isAMD64ZReg(ins.Args[1].Reg) && subExtWidth == 16 {
				laneMask = 3
			}
			byteOff := (ins.Args[0].Imm & laneMask) * subExtWidth
			valMask, valBitDef, fullBD, taintMask, anyTaint := readVecSlice(srcIdx, byteOff, subExtWidth)
			specExt := asm.OpSpec{Op: op, Width: uint16(subExtWidth * 8), Effect: asm.EffectWriteZeroUpper}
			return true, writeDstMask(st, dst, subExtWidth, valMask, valBitDef, fullBD, op, specExt, true, st.vecFromRaw[srcIdx], taintMask, anyTaint, true)
		}
	}

	// 3. Element & subvector inserts: PINSR{B,W,D,Q}, VPINSR{B,W,D,Q}, VINSERT*.
	var insWidth, insLaneMask int64
	isVEXIns := strings.HasPrefix(name, "V")
	switch name {
	case "PINSRB", "VPINSRB":
		insWidth, insLaneMask = 1, 15
	case "PINSRW", "VPINSRW":
		insWidth, insLaneMask = 2, 7
	case "PINSRD", "VPINSRD":
		insWidth, insLaneMask = 4, 3
	case "PINSRQ", "VPINSRQ":
		insWidth, insLaneMask = 8, 1
	case "VINSERTF128", "VINSERTI128", "VINSERTF32X4", "VINSERTI32X4", "VINSERTF64X2", "VINSERTI64X2":
		insWidth, insLaneMask = 16, 1
	case "VINSERTF32X8", "VINSERTI32X8", "VINSERTF64X4", "VINSERTI64X4":
		insWidth, insLaneMask = 32, 1
	}
	if insWidth > 0 && len(ins.Args) >= 3 && ins.Args[0].Kind == asm.OpImm {
		var srcOp asm.Operand
		var baseIdx, dstIdx int
		var dstReg asm.Reg
		valid := false
		if !isVEXIns && len(ins.Args) == 3 && ins.Args[2].Kind == asm.OpReg {
			if di, ok := anyVecRegIndex(ins.Args[2].Reg); ok {
				srcOp = ins.Args[1]
				baseIdx, dstIdx = di, di
				dstReg = ins.Args[2].Reg
				valid = true
			}
		} else if isVEXIns && len(ins.Args) == 4 && ins.Args[2].Kind == asm.OpReg && ins.Args[3].Kind == asm.OpReg {
			bi, okB := anyVecRegIndex(ins.Args[2].Reg)
			di, okD := anyVecRegIndex(ins.Args[3].Reg)
			if okB && okD {
				srcOp = ins.Args[1]
				baseIdx, dstIdx = bi, di
				dstReg = ins.Args[3].Reg
				valid = true
			}
		}
		if valid {
			if isAMD64ZReg(dstReg) && insWidth == 16 {
				insLaneMask = 3
			}
			ev, err := evalOperand(st, srcOp, insWidth, false, op, ins.Raw)
			if err != nil {
				return true, err
			}
			srcTaint, _ := evalOperandTaintSP(st, srcOp, insWidth, false, op)
			dstWidth := int64(16)
			if isAMD64ZReg(dstReg) {
				dstWidth = 64
			} else if isAMD64YReg(dstReg) {
				dstWidth = 32
			}
			nextInit := st.vecBytesInit[baseIdx]
			nextBD := st.vecByteBitDef[baseIdx]
			nextTaint := st.vecBytesTaintedSP[baseIdx]
			if isVEXIns {
				keepMask := abi0ByteMaskN(dstWidth)
				nextInit = (nextInit & keepMask) | ^keepMask
				nextTaint &= keepMask
				for b := dstWidth; b < 64; b++ {
					nextBD[b] = 0xff
				}
			}
			byteOff := (ins.Args[0].Imm & insLaneMask) * insWidth
			for b := int64(0); b < insWidth && byteOff+b < 64; b++ {
				db := byteOff + b
				bit := uint64(1) << uint(db)
				if (ev.byteMask & (uint64(1) << uint(b))) != 0 {
					nextInit |= bit
					nextBD[db] = ev.fullBitDef[b]
				} else {
					nextInit &^= bit
					nextBD[db] = 0
				}
				if (srcTaint & (uint64(1) << uint(b))) != 0 {
					nextTaint |= bit
				} else {
					nextTaint &^= bit
				}
			}
			st.vecBytesInit[dstIdx] = nextInit
			st.vecByteBitDef[dstIdx] = nextBD
			if nextTaint != 0 {
				st.vecBytesTaintedSP[dstIdx] = nextTaint
			} else {
				delete(st.vecBytesTaintedSP, dstIdx)
			}
			srcRaw := false
			if srcOp.Kind == asm.OpReg {
				if si, ok := anyVecRegIndex(srcOp.Reg); ok && st.vecFromRaw[si] {
					srcRaw = true
				}
			}
			st.vecFromRaw[dstIdx] = st.vecFromRaw[baseIdx] || srcRaw
			return true, nil
		}
	}

	// 4. Half-register moves: MOVHPS/MOVHPD/MOVLPS/MOVLPD/MOVHLPS/MOVLHPS (and V* variants).
	switch name {
	case "MOVHPS", "MOVHPD", "VMOVHPS", "VMOVHPD", "MOVLPS", "MOVLPD", "VMOVLPS", "VMOVLPD":
		isHigh := strings.Contains(name, "MOVH")
		isVEX := strings.HasPrefix(name, "V")
		if len(ins.Args) == 2 && ins.Args[0].Kind == asm.OpReg && ins.Args[1].Kind != asm.OpReg {
			// Store half of Xsrc to mem.
			if srcIdx, ok := anyVecRegIndex(ins.Args[0].Reg); ok {
				if err := checkDstMemAddr(ins.Args[1]); err != nil {
					return true, err
				}
				off := int64(0)
				if isHigh {
					off = 8
				}
				valMask, valBitDef, fullBD, taintMask, anyTaint := readVecSlice(srcIdx, off, 8)
				specSt := asm.OpSpec{Op: op, Width: 64, Effect: asm.EffectWriteOnly}
				return true, writeDstMask(st, ins.Args[1], 8, valMask, valBitDef, fullBD, op, specSt, true, st.vecFromRaw[srcIdx], taintMask, anyTaint, true)
			}
		}
		if (!isVEX && len(ins.Args) == 2 && ins.Args[0].Kind != asm.OpReg && ins.Args[1].Kind == asm.OpReg) ||
			(isVEX && len(ins.Args) == 3 && ins.Args[0].Kind != asm.OpReg && ins.Args[1].Kind == asm.OpReg && ins.Args[2].Kind == asm.OpReg) {
			var baseIdx, dstIdx int
			var okB, okD bool
			if !isVEX {
				dstIdx, okD = anyVecRegIndex(ins.Args[1].Reg)
				baseIdx, okB = dstIdx, okD
			} else {
				baseIdx, okB = anyVecRegIndex(ins.Args[1].Reg)
				dstIdx, okD = anyVecRegIndex(ins.Args[2].Reg)
			}
			if okB && okD {
				ev, err := evalOperand(st, ins.Args[0], 8, false, op, ins.Raw)
				if err != nil {
					return true, err
				}
				srcTaint, _ := evalOperandTaintSP(st, ins.Args[0], 8, false, op)
				nextInit := st.vecBytesInit[baseIdx]
				nextBD := st.vecByteBitDef[baseIdx]
				nextTaint := st.vecBytesTaintedSP[baseIdx]
				if isVEX {
					nextInit = (nextInit & 0xffff) | ^uint64(0xffff)
					nextTaint &= 0xffff
					for b := 16; b < 64; b++ {
						nextBD[b] = 0xff
					}
				}
				dstOff := int64(0)
				if isHigh {
					dstOff = 8
				}
				for b := int64(0); b < 8; b++ {
					db := dstOff + b
					bit := uint64(1) << uint(db)
					if (ev.byteMask & (uint64(1) << uint(b))) != 0 {
						nextInit |= bit
						nextBD[db] = ev.fullBitDef[b]
					} else {
						nextInit &^= bit
						nextBD[db] = 0
					}
					if (srcTaint & (uint64(1) << uint(b))) != 0 {
						nextTaint |= bit
					} else {
						nextTaint &^= bit
					}
				}
				st.vecBytesInit[dstIdx] = nextInit
				st.vecByteBitDef[dstIdx] = nextBD
				if nextTaint != 0 {
					st.vecBytesTaintedSP[dstIdx] = nextTaint
				} else {
					delete(st.vecBytesTaintedSP, dstIdx)
				}
				st.vecFromRaw[dstIdx] = st.vecFromRaw[baseIdx]
				return true, nil
			}
		}

	case "MOVHLPS", "MOVLHPS", "VMOVHLPS", "VMOVLHPS":
		isHL := strings.Contains(name, "HLPS")
		isVEX := strings.HasPrefix(name, "V")
		var srcIdx, baseIdx, dstIdx int
		valid := false
		if !isVEX && len(ins.Args) == 2 && ins.Args[0].Kind == asm.OpReg && ins.Args[1].Kind == asm.OpReg {
			si, okS := anyVecRegIndex(ins.Args[0].Reg)
			di, okD := anyVecRegIndex(ins.Args[1].Reg)
			if okS && okD {
				srcIdx, baseIdx, dstIdx = si, di, di
				valid = true
			}
		} else if isVEX && len(ins.Args) == 3 && ins.Args[0].Kind == asm.OpReg && ins.Args[1].Kind == asm.OpReg && ins.Args[2].Kind == asm.OpReg {
			si, okS := anyVecRegIndex(ins.Args[0].Reg)
			bi, okB := anyVecRegIndex(ins.Args[1].Reg)
			di, okD := anyVecRegIndex(ins.Args[2].Reg)
			if okS && okB && okD {
				srcIdx, baseIdx, dstIdx = si, bi, di
				valid = true
			}
		}
		if valid {
			srcOff, dstOff := int64(0), int64(8)
			if isHL {
				srcOff, dstOff = 8, 0
			}
			valMask, _, fullBD, taintMask, _ := readVecSlice(srcIdx, srcOff, 8)
			nextInit := st.vecBytesInit[baseIdx]
			nextBD := st.vecByteBitDef[baseIdx]
			nextTaint := st.vecBytesTaintedSP[baseIdx]
			if isVEX {
				nextInit = (nextInit & 0xffff) | ^uint64(0xffff)
				nextTaint &= 0xffff
				for b := 16; b < 64; b++ {
					nextBD[b] = 0xff
				}
			}
			for b := int64(0); b < 8; b++ {
				db := dstOff + b
				bit := uint64(1) << uint(db)
				if (valMask & (uint64(1) << uint(b))) != 0 {
					nextInit |= bit
					nextBD[db] = fullBD[b]
				} else {
					nextInit &^= bit
					nextBD[db] = 0
				}
				if (taintMask & (uint64(1) << uint(b))) != 0 {
					nextTaint |= bit
				} else {
					nextTaint &^= bit
				}
			}
			st.vecBytesInit[dstIdx] = nextInit
			st.vecByteBitDef[dstIdx] = nextBD
			if nextTaint != 0 {
				st.vecBytesTaintedSP[dstIdx] = nextTaint
			} else {
				delete(st.vecBytesTaintedSP, dstIdx)
			}
			st.vecFromRaw[dstIdx] = st.vecFromRaw[baseIdx] || st.vecFromRaw[srcIdx]
			return true, nil
		}
	}

	// 5. Byte shifts within 128-bit lanes: PSRLDQ/PSLLDQ/PSRLO/PSLLO (2-arg) and VPSRLDQ/VPSLLDQ (3-arg).
	if (name == "PSRLDQ" || name == "PSLLDQ" || name == "PSRLO" || name == "PSLLO" || name == "VPSRLDQ" || name == "VPSLLDQ") &&
		len(ins.Args) >= 2 && ins.Args[0].Kind == asm.OpImm {
		isRight := strings.HasSuffix(name, "RLDQ") || name == "PSRLO"
		isVEX := strings.HasPrefix(name, "V")
		var srcIdx, dstIdx int
		var dstReg asm.Reg
		valid := false
		if !isVEX && len(ins.Args) == 2 && ins.Args[1].Kind == asm.OpReg {
			if di, ok := anyVecRegIndex(ins.Args[1].Reg); ok {
				srcIdx, dstIdx, dstReg = di, di, ins.Args[1].Reg
				valid = true
			}
		} else if isVEX && len(ins.Args) == 3 && ins.Args[1].Kind == asm.OpReg && ins.Args[2].Kind == asm.OpReg {
			si, okS := anyVecRegIndex(ins.Args[1].Reg)
			di, okD := anyVecRegIndex(ins.Args[2].Reg)
			if okS && okD {
				srcIdx, dstIdx, dstReg = si, di, ins.Args[2].Reg
				valid = true
			}
		}
		if valid {
			shift, err := x86VecByteShiftCount(op, ins.Args[0].Imm)
			if err != nil {
				return true, err
			}
			lanes := int64(1)
			if isAMD64ZReg(dstReg) {
				lanes = 4
			} else if isAMD64YReg(dstReg) {
				lanes = 2
			}
			srcInit := st.vecBytesInit[srcIdx]
			srcBD := st.vecByteBitDef[srcIdx]
			srcTaint := st.vecBytesTaintedSP[srcIdx]
			nextInit := st.vecBytesInit[dstIdx]
			nextBD := st.vecByteBitDef[dstIdx]
			nextTaint := st.vecBytesTaintedSP[dstIdx]
			if isVEX {
				nextInit = ^uint64(0)
				nextTaint = 0
				for b := 0; b < 64; b++ {
					nextBD[b] = 0xff
				}
			}
			for lane := int64(0); lane < lanes; lane++ {
				base := lane * 16
				for b := int64(0); b < 16; b++ {
					db := base + b
					bit := uint64(1) << uint(db)
					var sb int64
					if isRight {
						sb = b + shift
					} else {
						sb = b - shift
					}
					if sb < 0 || sb >= 16 {
						// Shifted-in zero byte is known 0 (initialized, defined, untainted).
						nextInit |= bit
						nextBD[db] = 0xff
						nextTaint &^= bit
					} else {
						sbit := uint64(1) << uint(base+sb)
						if (srcInit & sbit) != 0 {
							nextInit |= bit
							nextBD[db] = srcBD[base+sb]
						} else {
							nextInit &^= bit
							nextBD[db] = 0
						}
						if (srcTaint & sbit) != 0 {
							nextTaint |= bit
						} else {
							nextTaint &^= bit
						}
					}
				}
			}
			st.vecBytesInit[dstIdx] = nextInit
			st.vecByteBitDef[dstIdx] = nextBD
			if nextTaint != 0 {
				st.vecBytesTaintedSP[dstIdx] = nextTaint
			} else {
				delete(st.vecBytesTaintedSP, dstIdx)
			}
			st.vecFromRaw[dstIdx] = st.vecFromRaw[srcIdx]
			return true, nil
		}
	}

	return false, nil
}
