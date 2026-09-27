package plan9asm

import (
	"fmt"
	"strings"
)

var amd64BF16ConvertSourceBytes = map[Op]int{
	"VCVTNEPS2BF16X": 16,
	"VCVTNEPS2BF16Y": 32,
	"VCVTNEPS2BF16":  64,
}

func (c *amd64Ctx) lowerBF16Convert(op Op, ins Instr) (ok bool, terminated bool, err error) {
	base := Op(strings.SplitN(string(op), ".", 2)[0])
	sourceBytes := amd64BF16ConvertSourceBytes[base]
	if sourceBytes == 0 {
		return false, false, nil
	}
	if !ins.x86Encoded {
		return true, false, fmt.Errorf("%s has no named Go 1.27 encoder form: %q", base, ins.Raw)
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("%s expects source, [K mask,] destination: %q", base, ins.Raw)
	}
	broadcast := strings.Contains(string(op), ".BCST")
	zeroing := strings.HasSuffix(string(op), ".Z")
	masked := len(ins.Args) == 3
	if zeroing && !masked || broadcast && !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("%s has invalid mask or broadcast operands: %q", base, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("%s requires K1-K7 for masking: %q", base, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	destinationBytes := sourceBytes / 2
	if destinationBytes < 16 {
		destinationBytes = 16
	}
	if destination.Kind != OpReg || amd64VectorByteWidth(destination.Reg) != destinationBytes {
		return true, false, fmt.Errorf("%s requires a %d-byte destination register: %q", base, destinationBytes, ins.Raw)
	}
	source := ins.Args[0]
	if source.Kind == OpReg && amd64VectorByteWidth(source.Reg) != sourceBytes ||
		source.Kind != OpReg && !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s requires a %d-byte vector or memory source: %q", base, sourceBytes, ins.Raw)
	}

	lanes := sourceBytes / 4
	mask := ""
	if masked {
		mask, err = c.loadK(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
	}
	inputBits, err := c.loadMaskedPackedCompareLanes(source, sourceBytes, 32, broadcast, mask)
	if err != nil {
		return true, false, err
	}
	input := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i32> %s to <%d x float>\n", input, lanes, inputBits, lanes)
	resultLanes := lanes
	if resultLanes < 8 {
		resultLanes = 8
	}
	intrinsic := map[int]string{
		16: "llvm.x86.vcvtneps2bf16128",
		32: "llvm.x86.vcvtneps2bf16256",
		64: "llvm.x86.avx512bf16.cvtneps2bf16.512",
	}[sourceBytes]
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <%d x bfloat> @%s(<%d x float> %%%s)\n",
		converted, resultLanes, intrinsic, lanes, input)
	computed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x bfloat> %%%s to <%d x i16>\n",
		computed, resultLanes, converted, resultLanes)
	result := "%" + computed
	if lanes < resultLanes {
		low := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i16> %s, <%d x i16> poison, <%d x i32> <",
			low, resultLanes, result, resultLanes, lanes)
		for lane := 0; lane < lanes; lane++ {
			if lane != 0 {
				c.b.WriteString(", ")
			}
			fmt.Fprintf(c.b, "i32 %d", lane)
		}
		c.b.WriteString(">\n")
		result = "%" + low
	}
	if masked {
		old, loadErr := c.loadPackedExtendInputs(destination, destinationBytes, lanes, 16)
		if loadErr != nil {
			return true, false, loadErr
		}
		result = amd64ApplyIntegerLaneMask(c, lanes, 16, result, old, mask, zeroing)
	}
	outputBytes := lanes * 2
	bytesValue := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i16> %s to <%d x i8>\n",
		bytesValue, lanes, result, outputBytes)
	return true, false, c.storePackedHalfResult(destination, destinationBytes, outputBytes, "%"+bytesValue)
}
