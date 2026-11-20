package plan9asm

import (
	"fmt"
)

type x86SingleSourceNarrowDomain uint8

const (
	x86NarrowTruncate x86SingleSourceNarrowDomain = iota
	x86NarrowSigned
	x86NarrowUnsigned
)

type amd64SingleSourceNarrowSpec struct {
	inputBits, outputBits int
	domain                x86SingleSourceNarrowDomain
}

var amd64SingleSourceNarrowSpecs = map[string]amd64SingleSourceNarrowSpec{
	"VPMOVDB":   {inputBits: 32, outputBits: 8},
	"VPMOVDW":   {inputBits: 32, outputBits: 16},
	"VPMOVQB":   {inputBits: 64, outputBits: 8},
	"VPMOVQD":   {inputBits: 64, outputBits: 32},
	"VPMOVQW":   {inputBits: 64, outputBits: 16},
	"VPMOVWB":   {inputBits: 16, outputBits: 8},
	"VPMOVSDB":  {inputBits: 32, outputBits: 8, domain: x86NarrowSigned},
	"VPMOVSDW":  {inputBits: 32, outputBits: 16, domain: x86NarrowSigned},
	"VPMOVSQB":  {inputBits: 64, outputBits: 8, domain: x86NarrowSigned},
	"VPMOVSQD":  {inputBits: 64, outputBits: 32, domain: x86NarrowSigned},
	"VPMOVSQW":  {inputBits: 64, outputBits: 16, domain: x86NarrowSigned},
	"VPMOVSWB":  {inputBits: 16, outputBits: 8, domain: x86NarrowSigned},
	"VPMOVUSDB": {inputBits: 32, outputBits: 8, domain: x86NarrowUnsigned},
	"VPMOVUSDW": {inputBits: 32, outputBits: 16, domain: x86NarrowUnsigned},
	"VPMOVUSQB": {inputBits: 64, outputBits: 8, domain: x86NarrowUnsigned},
	"VPMOVUSQD": {inputBits: 64, outputBits: 32, domain: x86NarrowUnsigned},
	"VPMOVUSQW": {inputBits: 64, outputBits: 16, domain: x86NarrowUnsigned},
	"VPMOVUSWB": {inputBits: 16, outputBits: 8, domain: x86NarrowUnsigned},
}

// lowerSingleSourceIntegerNarrow implements the complete Go 1.27
// _yvpmovdb/_yvpmovdw family: truncating, signed-saturating, and
// unsigned-saturating conversions from X/Y/Z into X/Y or memory.
func (c *amd64Ctx) lowerSingleSourceIntegerNarrow(op Op, ins Instr) (bool, bool, error) {
	form, known, err := x86SingleSourceNarrowProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if form.undefinedOpcode() {
		return c.lowerX86UndefinedTrap(op, ins)
	}
	mask := ""
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	sourceBytes, err := c.loadPackedCompareBytes(ins.Args[0], form.inputBytes)
	if err != nil {
		return true, false, err
	}
	lanes := form.inputBytes * 8 / form.spec.inputBits
	source := c.bitcastVectorBytesToIntegerLanes(form.inputBytes, lanes, form.spec.inputBits, sourceBytes)
	narrowed := c.emitSingleSourceIntegerNarrow(form.spec, lanes, source)
	destination := ins.Args[form.destination]
	if form.memory < 0 {
		return true, false, c.storeSingleSourceNarrowRegister(destination.Reg, form.carrierBytes,
			lanes, form.spec.outputBits, narrowed, mask, form.zeroing)
	}
	return true, false, c.storeSingleSourceNarrowMemory(destination, form.outputBytes,
		lanes, form.spec.outputBits, narrowed, mask)
}

func (c *amd64Ctx) emitSingleSourceIntegerNarrow(spec amd64SingleSourceNarrowSpec, lanes int, source string) string {
	inputType := fmt.Sprintf("<%d x i%d>", lanes, spec.inputBits)
	outputType := fmt.Sprintf("<%d x i%d>", lanes, spec.outputBits)
	if spec.domain != x86NarrowTruncate {
		// Single-source US conversions consume unsigned inputs. PACKUS has
		// signed inputs and deliberately keeps its separate saturation rule.
		predicate := "ugt"
		maximum := uint64(1)<<spec.outputBits - 1
		if spec.domain == x86NarrowSigned {
			predicate = "sgt"
			maximum >>= 1
		}
		limit := llvmSplatInteger(lanes, spec.inputBits, maximum)
		above, capped := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp %s %s %s, %s\n", above, predicate, inputType, source, limit)
		fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", capped, lanes, above, inputType, limit, inputType, source)
		source = "%" + capped
		if spec.domain == x86NarrowSigned {
			minimum := llvmSplatIntegerText(lanes, spec.inputBits, fmt.Sprint(-int64(maximum)-1))
			below, floored := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp slt %s %s, %s\n", below, inputType, source, minimum)
			fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", floored, lanes, below, inputType, minimum, inputType, source)
			source = "%" + floored
		}
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = trunc %s %s to %s\n", result, inputType, source, outputType)
	return "%" + result
}

func (c *amd64Ctx) storeSingleSourceNarrowRegister(destination Reg, destinationBytes, lanes, outputBits int, narrowed, mask string, zeroing bool) error {
	physicalLanes := destinationBytes * 8 / outputBits
	result := "zeroinitializer"
	var old string
	if mask != "" && !zeroing {
		oldBytes, err := c.loadPackedCompareBytes(Operand{Kind: OpReg, Reg: destination}, destinationBytes)
		if err != nil {
			return err
		}
		old = c.bitcastVectorBytesToIntegerLanes(destinationBytes, physicalLanes, outputBits, oldBytes)
	}
	for lane := 0; lane < lanes; lane++ {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", value, lanes, outputBits, narrowed, lane)
		selected := "%" + value
		if mask != "" {
			fallback := "0"
			if !zeroing {
				oldValue := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", oldValue, physicalLanes, outputBits, old, lane)
				fallback = "%" + oldValue
			}
			masked := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %s, i%d %s, i%d %s\n", masked, amd64MaskBitI1(c, mask, lane), outputBits, selected, outputBits, fallback)
			selected = "%" + masked
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> %s, i%d %s, i32 %d\n", inserted, physicalLanes, outputBits, result, outputBits, selected, lane)
		result = "%" + inserted
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, physicalLanes, outputBits, result, destinationBytes)
	return c.storePackedMoveOperand(Operand{Kind: OpReg, Reg: destination}, destinationBytes, "%"+out)
}

func (c *amd64Ctx) storeSingleSourceNarrowMemory(destination Operand, outputBytes, lanes, outputBits int, narrowed, mask string) error {
	if mask != "" {
		pointer, pointerType, suffix, err := c.packedVectorMemoryPointer(destination)
		if err != nil {
			return err
		}
		if suffix == "" {
			suffix = ".p0"
		}
		predicate := amd64IntegerMaskVector(c, lanes, mask)
		fmt.Fprintf(c.b, "  call void @llvm.masked.store.v%di%d%s(<%d x i%d> %s, %s align 1 %s, <%d x i1> %s)\n", lanes, outputBits, suffix, lanes, outputBits, narrowed, pointerType, pointer, lanes, predicate)
		return nil
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", out, lanes, outputBits, narrowed, outputBytes)
	return c.storeNarrowMemoryBytes(destination, outputBytes, "%"+out)
}

func (c *amd64Ctx) storeNarrowMemoryBytes(destination Operand, byteWidth int, value string) error {
	if byteWidth >= 16 {
		return c.storeVectorBytesOperand(destination, byteWidth, value)
	}
	typ := amd64IntegerTypeForBits(byteWidth * 8)
	integer := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", integer, byteWidth, value, typ)
	return c.storeVectorScalarMemory(destination, byteWidth*8, "%"+integer, "")
}
