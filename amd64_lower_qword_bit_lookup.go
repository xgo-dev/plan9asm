package plan9asm

import (
	"fmt"
	"strings"
)

type amd64QwordBitLookupOutput uint8

const (
	amd64QwordBitLookupBytes amd64QwordBitLookupOutput = iota
	amd64QwordBitLookupMask
)

type amd64QwordBitLookupSpec struct {
	output    amd64QwordBitLookupOutput
	broadcast bool
}

// amd64QwordBitLookupSpecs groups the two AVX-512 byte-control operations
// that select bits inside corresponding qword lanes. They share the same core
// rotate/lookup grammar but produce either bytes or a packed K mask.
var amd64QwordBitLookupSpecs = map[Op]amd64QwordBitLookupSpec{
	"VPMULTISHIFTQB": {output: amd64QwordBitLookupBytes, broadcast: true},
	"VPSHUFBITQMB":   {output: amd64QwordBitLookupMask},
}

func (c *amd64Ctx) lowerQwordBitLookup(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64QwordBitLookupSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}

	suffixes, err := amd64ParseTwoSourcePermuteSuffixes(rawOp, baseOp)
	if err != nil {
		return true, false, fmt.Errorf("%w: %q", err, ins.Raw)
	}
	if spec.output == amd64QwordBitLookupMask && (suffixes.broadcast || suffixes.zeroing) {
		return true, false, fmt.Errorf("%s %s has no instruction suffixes in Go 1.27: %q", c.goarch, baseOp, ins.Raw)
	}
	if suffixes.broadcast && !spec.broadcast {
		return true, false, fmt.Errorf("%s %s does not support broadcast: %q", c.goarch, baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 && len(ins.Args) != 4 {
		return true, false, fmt.Errorf("%s %s expects first source, second source, [K mask,] destination: %q", c.goarch, baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 4
	if c.goarch == "386" && masked {
		return true, false, fmt.Errorf("386 %s masked form exceeds the Go assembler frontend's three-operand limit: %q", baseOp, ins.Raw)
	}
	if suffixes.zeroing && !masked {
		return true, false, fmt.Errorf("%s %s.Z requires a K1-K7 mask: %q", c.goarch, baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[2]) {
		return true, false, fmt.Errorf("%s %s masked form requires K1-K7: %q", c.goarch, baseOp, ins.Raw)
	}

	first, second := ins.Args[0], ins.Args[1]
	destination := ins.Args[len(ins.Args)-1]
	byteWidth := 0
	switch spec.output {
	case amd64QwordBitLookupBytes:
		if destination.Kind != OpReg {
			return true, false, fmt.Errorf("%s %s destination must be X, Y, or Z: %q", c.goarch, baseOp, ins.Raw)
		}
		byteWidth = amd64VectorByteWidth(destination.Reg)
		if byteWidth == 0 || !c.isGoPackedVectorMoveRegister(destination, byteWidth) {
			return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's vector class: %q", c.goarch, baseOp, ins.Raw)
		}
	case amd64QwordBitLookupMask:
		if destination.Kind != OpReg {
			return true, false, fmt.Errorf("%s %s destination must be K0-K7: %q", c.goarch, baseOp, ins.Raw)
		}
		if _, valid := amd64ParseKReg(destination.Reg); !valid {
			return true, false, fmt.Errorf("%s %s destination must be K0-K7: %q", c.goarch, baseOp, ins.Raw)
		}
		if second.Kind == OpReg {
			byteWidth = amd64VectorByteWidth(second.Reg)
		}
	}
	if byteWidth == 0 || !c.isGoPackedVectorMoveRegister(second, byteWidth) {
		return true, false, fmt.Errorf("%s %s second source must be an in-range X, Y, or Z register: %q", c.goarch, baseOp, ins.Raw)
	}
	if first.Kind == OpReg {
		if !c.isGoPackedVectorMoveRegister(first, byteWidth) {
			return true, false, fmt.Errorf("%s %s first source register must match the vector width: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(first) {
		return true, false, fmt.Errorf("%s %s first source must be a matching vector register or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	if suffixes.broadcast && !isAMD64MemoryOperand(first) {
		return true, false, fmt.Errorf("%s %s.BCST requires a memory qword source: %q", c.goarch, baseOp, ins.Raw)
	}

	var dataQwords, controls string
	switch spec.output {
	case amd64QwordBitLookupBytes:
		dataQwords, err = c.loadPackedCompareLanes(first, byteWidth, 64, suffixes.broadcast)
		if err == nil {
			controls, err = c.loadPackedCompareBytes(second, byteWidth)
		}
	case amd64QwordBitLookupMask:
		dataQwords, err = c.loadPackedCompareLanes(second, byteWidth, 64, false)
		if err == nil {
			controls, err = c.loadPackedCompareBytes(first, byteWidth)
		}
	}
	if err != nil {
		return true, false, err
	}
	selectedBytes := c.emitQwordBitLookupBytes(byteWidth, dataQwords, controls)

	var writeMask string
	if masked {
		writeMask, err = c.loadK(ins.Args[2].Reg)
		if err != nil {
			return true, false, err
		}
	}
	if spec.output == amd64QwordBitLookupBytes {
		if masked {
			old, loadErr := c.loadPackedCompareBytes(destination, byteWidth)
			if loadErr != nil {
				return true, false, loadErr
			}
			selectedBytes = amd64ApplyIntegerLaneMask(c, byteWidth, 8, selectedBytes, old, writeMask, suffixes.zeroing)
		}
		return true, false, c.storeVectorBytes(destination.Reg, byteWidth, selectedBytes)
	}

	ones := c.newTmp()
	predicates := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and <%d x i8> %s, %s\n", ones, byteWidth, selectedBytes, llvmSplatInteger(byteWidth, 8, 1))
	fmt.Fprintf(c.b, "  %%%s = icmp ne <%d x i8> %%%s, zeroinitializer\n", predicates, byteWidth, ones)
	packedType := fmt.Sprintf("i%d", byteWidth)
	packed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i1> %%%s to %s\n", packed, byteWidth, predicates, packedType)
	result := "%" + packed
	if byteWidth < 64 {
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext %s %s to i64\n", wide, packedType, result)
		result = "%" + wide
	}
	if masked {
		maskedResult := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and i64 %s, %s\n", maskedResult, result, writeMask)
		result = "%" + maskedResult
	}
	return true, false, c.storeK(destination.Reg, result)
}

// emitQwordBitLookupBytes rotates each corresponding data qword right by the
// low six bits of a control byte. Its low byte is VPMULTISHIFTQB's result;
// its low bit is VPSHUFBITQMB's gathered mask bit.
func (c *amd64Ctx) emitQwordBitLookupBytes(byteWidth int, dataQwords, controls string) string {
	result := "zeroinitializer"
	qwords := byteWidth / 8
	for lane := 0; lane < byteWidth; lane++ {
		data := c.newTmp()
		controlByte := c.newTmp()
		controlWide := c.newTmp()
		control := c.newTmp()
		right := c.newTmp()
		negated := c.newTmp()
		wrappedLeftCount := c.newTmp()
		left := c.newTmp()
		rotated := c.newTmp()
		selected := c.newTmp()
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i64> %s, i32 %d\n", data, qwords, dataQwords, lane/8)
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i8> %s, i32 %d\n", controlByte, byteWidth, controls, lane)
		fmt.Fprintf(c.b, "  %%%s = zext i8 %%%s to i64\n", controlWide, controlByte)
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 63\n", control, controlWide)
		fmt.Fprintf(c.b, "  %%%s = lshr i64 %%%s, %%%s\n", right, data, control)
		fmt.Fprintf(c.b, "  %%%s = sub i64 0, %%%s\n", negated, control)
		fmt.Fprintf(c.b, "  %%%s = and i64 %%%s, 63\n", wrappedLeftCount, negated)
		fmt.Fprintf(c.b, "  %%%s = shl i64 %%%s, %%%s\n", left, data, wrappedLeftCount)
		fmt.Fprintf(c.b, "  %%%s = or i64 %%%s, %%%s\n", rotated, right, left)
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %%%s to i8\n", selected, rotated)
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i8> %s, i8 %%%s, i32 %d\n", inserted, byteWidth, result, selected, lane)
		result = "%" + inserted
	}
	return result
}
