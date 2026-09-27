package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedDotProductSpec struct {
	inputBits int
	saturate  bool
	bfloat    bool
}

var amd64PackedDotProductSpecs = map[Op]amd64PackedDotProductSpec{
	"VPDPBUSD":  {inputBits: 8},
	"VPDPBUSDS": {inputBits: 8, saturate: true},
	"VPDPWSSD":  {inputBits: 16},
	"VPDPWSSDS": {inputBits: 16, saturate: true},
	"VDPBF16PS": {inputBits: 16, bfloat: true},
}

// lowerPackedDotProduct implements the four VNNI dot-product opcodes sharing
// Go 1.27's _yvblendmpd table. Plan 9 lists the signed r/m source first and
// the encoded V source second; VPDPBUSD treats that second source as unsigned.
func (c *amd64Ctx) lowerPackedDotProduct(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp, suffix := rawOp, ""
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp, suffix = rawOp[:dot], rawOp[dot+1:]
	}
	spec, recognized := amd64PackedDotProductSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if spec.bfloat && !ins.x86Encoded {
		return true, false, fmt.Errorf("%s has no named Go encoder form; raw encoding required", baseOp)
	}

	properties, validSuffix := parseAMD64BinaryFloatingSuffix(suffix)
	if !validSuffix || properties.sae || properties.rounding != "" {
		return true, false, fmt.Errorf("%s %s suffix is absent from Go 1.27's _yvblendmpd encodings: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("%s %s expects source2, source1, [K mask,] accumulator: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked && !ins.x86Encoded {
		return true, false, fmt.Errorf("386 %s mask forms exceed the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if properties.zeroing && !masked {
		return true, false, fmt.Errorf("%s %s zeroing requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[2]) {
		return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7 as its third operand: %q", baseOp, ins.Raw)
	}

	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("%s %s accumulator must be X, Y, or Z: %q", c.goarch, baseOp, ins.Raw)
	}
	byteWidth := amd64VectorByteWidth(destination.Reg)
	if byteWidth != 16 && byteWidth != 32 && byteWidth != 64 ||
		!c.isGoPackedVectorMoveRegister(destination, byteWidth) ||
		!c.isGoPackedVectorMoveRegister(ins.Args[1], byteWidth) {
		return true, false, fmt.Errorf("%s %s source1 and accumulator must be matching Go vector registers: %q", c.goarch, baseOp, ins.Raw)
	}
	rmSource := ins.Args[0]
	if properties.broadcast {
		if !isAMD64MemoryOperand(rmSource) {
			return true, false, fmt.Errorf("%s %s.BCST requires a scalar memory source2: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if rmSource.Kind == OpReg {
		if !c.isGoPackedVectorMoveRegister(rmSource, byteWidth) {
			return true, false, fmt.Errorf("%s %s source2 register must match the accumulator width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(rmSource) {
		return true, false, fmt.Errorf("%s %s source2 must be a matching vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}

	dwordLanes := byteWidth / 4
	inputLanes := byteWidth * 8 / spec.inputBits
	mask := ""
	if masked {
		mask, err = c.loadK(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
	}
	// One mask bit controls a complete output dword and its input pair/group.
	rmDwords, err := c.loadMaskedPackedCompareLanes(rmSource, byteWidth, 32, properties.broadcast, mask)
	if err != nil {
		return true, false, err
	}
	rmValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i32> %s to <%d x i%d>\n", rmValue, dwordLanes, rmDwords, inputLanes, spec.inputBits)
	vBytes, err := c.loadPackedCompareBytes(ins.Args[1], byteWidth)
	if err != nil {
		return true, false, err
	}
	oldBytes, err := c.loadPackedCompareBytes(destination, byteWidth)
	if err != nil {
		return true, false, err
	}
	rm := "%" + rmValue
	v := c.bitcastVectorBytesToIntegerLanes(byteWidth, inputLanes, spec.inputBits, vBytes)
	old := c.bitcastVectorBytesToIntegerLanes(byteWidth, dwordLanes, 32, oldBytes)
	computed := c.emitPackedDotProduct(spec, dwordLanes, rm, v, old)
	if masked {
		computed = amd64ApplyI32LaneMask(c, dwordLanes, computed, old, mask, properties.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i32> %s to <%d x i8>\n", out, dwordLanes, computed, byteWidth)
	return true, false, c.storePackedMoveOperand(destination, byteWidth, "%"+out)
}

// LLVM's dedicated intrinsic preserves the instruction's RNE, DAZ/FTZ and
// NaN-priority semantics independently of MXCSR. Generic fmul/fadd cannot.
func (c *amd64Ctx) emitBF16DotProduct(lanes int, rm, v, accumulator string) string {
	left, right, old := c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i16> %s to <%d x bfloat>\n", left, lanes*2, v, lanes*2)
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i16> %s to <%d x bfloat>\n", right, lanes*2, rm, lanes*2)
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i32> %s to <%d x float>\n", old, lanes, accumulator, lanes)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <%d x float> @llvm.x86.avx512bf16.dpbf16ps.%d(<%d x float> %%%s, <%d x bfloat> %%%s, <%d x bfloat> %%%s)\n",
		result, lanes, lanes*32, lanes, old, lanes*2, left, lanes*2, right)
	bits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x float> %%%s to <%d x i32>\n", bits, lanes, result, lanes)
	return "%" + bits
}

func (c *amd64Ctx) emitPackedDotProduct(spec amd64PackedDotProductSpec, dwordLanes int, rm, v, accumulator string) string {
	if spec.bfloat {
		return c.emitBF16DotProduct(dwordLanes, rm, v, accumulator)
	}
	inputsPerDword := 32 / spec.inputBits
	result := "poison"
	for lane := 0; lane < dwordLanes; lane++ {
		accumulatorLane := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i32> %s, i32 %d\n", accumulatorLane, dwordLanes, accumulator, lane)
		wideAccumulator := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext i32 %%%s to i64\n", wideAccumulator, accumulatorLane)
		total := "%" + wideAccumulator
		for item := 0; item < inputsPerDword; item++ {
			inputLane := lane*inputsPerDword + item
			rmLane := c.newTmp()
			vLane := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", rmLane, dwordLanes*inputsPerDword, spec.inputBits, rm, inputLane)
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", vLane, dwordLanes*inputsPerDword, spec.inputBits, v, inputLane)
			wideRM := c.newTmp()
			wideV := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = sext i%d %%%s to i64\n", wideRM, spec.inputBits, rmLane)
			if spec.inputBits == 8 {
				fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i64\n", wideV, vLane)
			} else {
				fmt.Fprintf(c.b, "  %%%s = sext i16 %%%s to i64\n", wideV, vLane)
			}
			product := c.newTmp()
			next := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, %%%s\n", product, wideRM, wideV)
			fmt.Fprintf(c.b, "  %%%s = add i64 %s, %%%s\n", next, total, product)
			total = "%" + next
		}
		if spec.saturate {
			above := c.newTmp()
			below := c.newTmp()
			capped := c.newTmp()
			bounded := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp sgt i64 %s, 2147483647\n", above, total)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 2147483647, i64 %s\n", capped, above, total)
			fmt.Fprintf(c.b, "  %%%s = icmp slt i64 %%%s, -2147483648\n", below, capped)
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 -2147483648, i64 %%%s\n", bounded, below, capped)
			total = "%" + bounded
		}
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", narrow, total)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i32> %s, i32 %%%s, i32 %d\n", inserted, dwordLanes, result, narrow, lane)
		result = "%" + inserted
	}
	return result
}
