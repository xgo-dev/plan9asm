package plan9asm

import (
	"fmt"
	"strings"
)

type amd64VectorExtractProperties struct {
	outputBytes int
	laneBits    int
	legacy      bool
	allowY      bool
	allowZ      bool
}

// lowerVectorLaneExtract implements all Go 1.27 forms in _yvextractf128,
// _yvextractf32x4, and _yvextractf32x8 for their F/I lane-extract mnemonics.
func (c *amd64Ctx) lowerVectorLaneExtract(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	suffix := ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	properties, ok := amd64VectorExtractOpProperties(baseOp)
	if !ok {
		return false, false, nil
	}
	zeroing := false
	switch suffix {
	case "":
	case "Z":
		zeroing = true
	default:
		return true, false, fmt.Errorf("amd64 %s accepts only the .Z suffix enabled by its Go 1.27 optab: %q", baseOp, ins.Raw)
	}
	if properties.legacy && suffix != "" {
		return true, false, fmt.Errorf("amd64 %s VEX form has no suffix: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("amd64 %s expects $imm, source, [K mask,] destination: %q", baseOp, ins.Raw)
	}
	if ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects an immediate and vector-register source: %q", baseOp, ins.Raw)
	}
	inputBytes := amd64VectorByteWidth(ins.Args[1].Reg)
	if (inputBytes == 32 && !properties.allowY) || (inputBytes == 64 && !properties.allowZ) || (inputBytes != 32 && inputBytes != 64) {
		return true, false, fmt.Errorf("amd64 %s source has a width absent from its Go 1.27 optab: %q", baseOp, ins.Raw)
	}
	dstArg := ins.Args[len(ins.Args)-1]
	if dstArg.Kind == OpReg {
		if !amd64VectorRegisterHasWidth(dstArg, properties.outputBytes) {
			return true, false, fmt.Errorf("amd64 %s register destination must be %d bytes: %q", baseOp, properties.outputBytes, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(dstArg) {
		return true, false, fmt.Errorf("amd64 %s destination must be a vector register or memory: %q", baseOp, ins.Raw)
	}

	masked := len(ins.Args) == 4
	if properties.legacy && masked {
		return true, false, fmt.Errorf("amd64 %s VEX form has no mask: %q", baseOp, ins.Raw)
	}
	if zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s zeroing requires a K1-K7 mask: %q", baseOp, ins.Raw)
	}
	if zeroing && dstArg.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s zeroing is invalid for a memory destination: %q", baseOp, ins.Raw)
	}
	var mask string
	if masked {
		maskArg := ins.Args[2]
		if maskArg.Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		maskIndex, ok := amd64ParseKReg(maskArg.Reg)
		if !ok || maskIndex == 0 {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		mask, err = c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
	}

	source, err := c.loadPackedCompareBytes(ins.Args[1], inputBytes)
	if err != nil {
		return true, false, err
	}
	chunkCount := inputBytes / properties.outputBytes
	chunk := int(uint64(ins.Args[0].Imm) & uint64(chunkCount-1))
	extracted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i8> %s, <%d x i8> poison, <%d x i32> %s\n", extracted, inputBytes, source, inputBytes, properties.outputBytes, llvmI32RangeMask(chunk*properties.outputBytes, properties.outputBytes))
	result := "%" + extracted
	if masked {
		lanes := properties.outputBytes * 8 / properties.laneBits
		computed := c.bitcastVectorBytesToIntegerLanes(properties.outputBytes, lanes, properties.laneBits, result)
		oldBytes, err := c.loadPackedCompareBytes(dstArg, properties.outputBytes)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(properties.outputBytes, lanes, properties.laneBits, oldBytes)
		computed = amd64ApplyIntegerLaneMask(c, lanes, properties.laneBits, computed, old, mask, zeroing)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, properties.laneBits, computed, properties.outputBytes)
		result = "%" + out
	}
	return true, false, c.storeVectorBytesOperand(dstArg, properties.outputBytes, result)
}

func amd64VectorExtractOpProperties(op string) (amd64VectorExtractProperties, bool) {
	switch op {
	case "VEXTRACTF128", "VEXTRACTI128":
		return amd64VectorExtractProperties{outputBytes: 16, laneBits: 8, legacy: true, allowY: true}, true
	case "VEXTRACTF32X4", "VEXTRACTI32X4":
		return amd64VectorExtractProperties{outputBytes: 16, laneBits: 32, allowY: true, allowZ: true}, true
	case "VEXTRACTF64X2", "VEXTRACTI64X2":
		return amd64VectorExtractProperties{outputBytes: 16, laneBits: 64, allowY: true, allowZ: true}, true
	case "VEXTRACTF32X8", "VEXTRACTI32X8":
		return amd64VectorExtractProperties{outputBytes: 32, laneBits: 32, allowZ: true}, true
	case "VEXTRACTF64X4", "VEXTRACTI64X4":
		return amd64VectorExtractProperties{outputBytes: 32, laneBits: 64, allowZ: true}, true
	default:
		return amd64VectorExtractProperties{}, false
	}
}

func (c *amd64Ctx) storeVectorBytesOperand(dst Operand, byteWidth int, value string) error {
	return c.storeVectorBytesOperandWithMetadata(dst, byteWidth, value, "")
}

func (c *amd64Ctx) storeVectorBytesOperandWithMetadata(dst Operand, byteWidth int, value, metadata string) error {
	if dst.Kind == OpReg {
		if metadata != "" {
			return fmt.Errorf("vector register destination cannot carry store metadata: %s", dst.String())
		}
		if !amd64VectorRegisterHasWidth(dst, byteWidth) {
			return fmt.Errorf("expected %d-byte vector register, got %s", byteWidth, dst.String())
		}
		return c.storeVectorBytes(dst.Reg, byteWidth, value)
	}
	switch dst.Kind {
	case OpMem:
		addr, err := c.addrFromMem(dst.Mem)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store <%d x i8> %s, ptr %s, align 1%s\n", byteWidth, value, c.ptrFromAddrI64(addr), metadata)
		return nil
	case OpSym:
		p, err := c.ptrFromSB(dst.Sym)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  store <%d x i8> %s, ptr %s, align 1%s\n", byteWidth, value, p, metadata)
		return nil
	case OpFP:
		chunks := byteWidth / 8
		words := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i64>\n", words, byteWidth, value, chunks)
		for i := 0; i < chunks; i++ {
			word := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i64> %%%s, i32 %d\n", word, chunks, words, i)
			if err := c.storeFPResultWithMetadata(dst.FPOffset+int64(i*8), I64, "%"+word, metadata); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("expected vector register or memory destination, got %s", dst.String())
	}
}
