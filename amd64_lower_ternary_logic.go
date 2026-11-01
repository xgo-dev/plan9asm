package plan9asm

import "fmt"

// Both Go _yvalignd opcodes have the same forms; D/Q changes mask lanes and
// the scalar broadcast tuple, not the bitwise Boolean truth table.
var amd64TernaryLogicSpecs = map[Op]int{"VPTERNLOGD": 32, "VPTERNLOGQ": 64}

func (c *amd64Ctx) lowerTernaryLogic(op Op, ins Instr) (bool, bool, error) {
	form, recognized, err := x86TernaryLogicProperties(op, ins, c.goarch)
	if !recognized || err != nil {
		return recognized, false, err
	}
	if form.memory >= 0 && ins.Args[form.memory].Kind == OpFP {
		if err := c.validateX86PackedShiftFPSpan(ins.Args[form.memory].FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	var mask string
	if form.mask >= 0 {
		mask, err = c.loadK(ins.Args[form.mask].Reg)
		if err != nil {
			return true, false, err
		}
	}
	dependencies := form.dependencies()
	if form.mask >= 0 && !form.zeroing {
		dependencies |= 1
	}
	inputs := [3]string{"zeroinitializer", "zeroinitializer", "zeroinitializer"}
	for role, argument := range form.inputs {
		if argument == form.memory {
			// E4 reads are observable even if the truth table ignores C.
			// Only active mask lanes suppress faults; never LLVM DCE.
			// Intel SDM Vol.2A 2.8.4, Tables 2-43/2-49 (E4, not E4NF):
			// https://cdrdv2-public.intel.com/789573/252046-sdm-change-document.pdf
			lanes, err := c.loadX86PackedShiftLanes(ins.Args[argument], form.byteWidth, form.laneBits, form.broadcast, mask)
			if err != nil {
				return true, false, err
			}
			bytes := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", bytes, form.byteWidth*8/form.laneBits, form.laneBits, lanes, form.byteWidth)
			inputs[role] = "%" + bytes
		} else if dependencies>>uint(role)&1 != 0 {
			inputs[role], err = c.loadPackedCompareBytes(ins.Args[argument], form.byteWidth)
			if err != nil {
				return true, false, err
			}
		}
	}
	result := c.emitTernaryLogicTerms(form.byteWidth, form.terms, inputs)
	if form.mask >= 0 {
		lanes := form.byteWidth * 8 / form.laneBits
		computed := c.bitcastVectorBytesToIntegerLanes(form.byteWidth, lanes, form.laneBits, result)
		old := c.bitcastVectorBytesToIntegerLanes(form.byteWidth, lanes, form.laneBits, inputs[0])
		masked := amd64ApplyIntegerLaneMask(c, lanes, form.laneBits, computed, old, mask, form.zeroing)
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <%d x i8>\n", bytes, lanes, form.laneBits, masked, form.byteWidth)
		result = "%" + bytes
	}
	return true, false, c.storePackedMoveOperand(ins.Args[form.destination], form.byteWidth, result)
}

// Normalization removes irrelevant inputs and aliases before LLVM sees undef.
func (c *amd64Ctx) emitTernaryLogicBytes(width int, immediate uint8, a, b, third string) string {
	return c.emitTernaryLogicTerms(width, x86TernaryLogicTerms(immediate, [3]int{0, 1, 2}), [3]string{a, b, third})
}

func (c *amd64Ctx) emitTernaryLogicTerms(width int, terms uint8, inputs [3]string) string {
	result := ""
	for subset := 0; subset < 8; subset++ {
		if terms>>uint(subset)&1 == 0 {
			continue
		}
		term := ""
		for role, input := range inputs {
			if subset>>uint(role)&1 == 0 {
				continue
			}
			if term == "" {
				term = input
				continue
			}
			name := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = and <%d x i8> %s, %s\n", name, width, term, input)
			term = "%" + name
		}
		if term == "" {
			term = llvmAllOnesI8Vec(width)
		}
		if result == "" {
			result = term
			continue
		}
		name := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor <%d x i8> %s, %s\n", name, width, result, term)
		result = "%" + name
	}
	if result == "" {
		return "zeroinitializer"
	}
	return result
}

func amd64TernaryLogicBit(immediate uint8, a, b, third bool) bool {
	index := 0
	for _, value := range []bool{a, b, third} {
		index <<= 1
		if value {
			index++
		}
	}
	return immediate>>uint(index)&1 != 0
}
