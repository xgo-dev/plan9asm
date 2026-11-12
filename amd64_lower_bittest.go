package plan9asm

import "fmt"

// lowerBitTestFamily implements the complete Go 1.27 ybtl table. BTW/L/Q,
// BTCW/L/Q, BTRW/L/Q, and BTSW/L/Q all accept exactly either a signed imm8 or
// a Yrl register bit index followed by a Yml register/memory destination.
func (c *amd64Ctx) lowerBitTestFamily(op Op, ins Instr) (ok bool, terminated bool, err error) {
	arch := c.goarch
	if arch == "" {
		arch = "amd64"
	}
	form, known, err := x86BitTestProperties(op, ins, arch)
	if !known || err != nil {
		return known, false, err
	}
	if form.destination.Kind != OpReg && (ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride) {
		return true, false, fmt.Errorf("%w: bit string needs its original native address size", ErrProbeNeedsContext)
	}
	stem, bits := form.stem, form.bits
	typ := amd64IntegerTypeForBits(bits)
	bitIndex, memoryWordOffset, registerIndex, err := c.bitTestIndex(form.index, bits, typ)
	if err != nil {
		return true, false, err
	}
	value, store, err := c.loadBitTestDestination(form.destination, typ, memoryWordOffset, registerIndex)
	if err != nil {
		return true, false, err
	}

	shifted := c.newTmp()
	bit := c.newTmp()
	carry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", shifted, typ, value, bitIndex)
	fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 1\n", bit, typ, shifted)
	fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, 0\n", carry, typ, bit)
	fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", carry, c.flagsCFSlot)
	if stem == "BT" {
		return true, false, nil
	}

	bitMask := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shl %s 1, %s\n", bitMask, typ, bitIndex)
	result := c.newTmp()
	switch stem {
	case "BTC":
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %%%s\n", result, typ, value, bitMask)
	case "BTR":
		inverseMask := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %%%s, -1\n", inverseMask, typ, bitMask)
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %%%s\n", result, typ, value, inverseMask)
	case "BTS":
		fmt.Fprintf(c.b, "  %%%s = or %s %s, %%%s\n", result, typ, value, bitMask)
	}
	return true, false, store("%" + result)
}

func amd64BitTestProperties(op string) (stem string, bits int, ok bool) {
	switch op {
	case "BTW":
		return "BT", 16, true
	case "BTL":
		return "BT", 32, true
	case "BTQ":
		return "BT", 64, true
	case "BTCW":
		return "BTC", 16, true
	case "BTCL":
		return "BTC", 32, true
	case "BTCQ":
		return "BTC", 64, true
	case "BTRW":
		return "BTR", 16, true
	case "BTRL":
		return "BTR", 32, true
	case "BTRQ":
		return "BTR", 64, true
	case "BTSW":
		return "BTS", 16, true
	case "BTSL":
		return "BTS", 32, true
	case "BTSQ":
		return "BTS", 64, true
	}
	return "", 0, false
}

// bitTestIndex returns the within-word index and, for a register index, the
// signed byte offset used when a memory destination is treated as an unbounded
// bit string. The index register has the same width as the instruction.
// Intel SDM Vol.2A, Bit(BitBase, BitOffset) and BT/BTC/BTR/BTS:
// https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf
// Immediate high bits are ignored by the CPU; unlike some assemblers, actual
// Go does not fold them into a new displacement (tested for every imm8).
func (c *amd64Ctx) bitTestIndex(index Operand, bits int, typ LLVMType) (bitIndex, memoryWordOffset string, registerIndex bool, err error) {
	if index.Kind == OpImm {
		return fmt.Sprintf("%d", index.Imm&int64(bits-1)), "", false, nil
	}
	value, err := c.evalIntSized(index, typ)
	if err != nil {
		return "", "", false, err
	}
	withinWord := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = and %s %s, %d\n", withinWord, typ, value, bits-1)
	bitIndex = "%" + withinWord

	signedIndex := value
	if bits != 64 {
		extended := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sext %s %s to i64\n", extended, typ, value)
		signedIndex = "%" + extended
	}
	wordIndex := c.newTmp()
	byteOffset := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = ashr i64 %s, %d\n", wordIndex, signedIndex, bitTestLog2(bits))
	fmt.Fprintf(c.b, "  %%%s = mul i64 %%%s, %d\n", byteOffset, wordIndex, bits/8)
	return bitIndex, "%" + byteOffset, true, nil
}

func bitTestLog2(bits int) int {
	switch bits {
	case 16:
		return 4
	case 32:
		return 5
	default:
		return 6
	}
}

func (c *amd64Ctx) loadBitTestDestination(destination Operand, typ LLVMType, memoryWordOffset string, registerIndex bool) (string, func(string) error, error) {
	if destination.Kind == OpReg {
		return c.loadIntDestination(destination, typ)
	}
	if destination.Kind == OpFP {
		if registerIndex {
			return "", nil, fmt.Errorf("%w: a register-indexed FP bit string has no fixed logical byte span", ErrProbeNeedsContext)
		}
		return c.loadBitTestFPDestination(destination, typ)
	}
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(destination)
	if err != nil {
		return "", nil, err
	}
	if registerIndex {
		adjusted := c.newTmp()
		// Signed floor division selects the complete containing word. Keep
		// the original pointer address space and its target-width wrapping.
		fmt.Fprintf(c.b, "  %%%s = getelementptr i8, %s %s, i64 %s\n", adjusted, pointerType, pointer, memoryWordOffset)
		pointer = "%" + adjusted
	}
	loaded := c.newTmp()
	// Intel SDM Vol.2A BT/BTC/BTR/BTS: even a dead CF retains the complete
	// native read/fault; modifying forms also retain their write, including
	// when the selected bit already has the requested value. This is not LOCK.
	fmt.Fprintf(c.b, "  %%%s = load volatile %s, %s %s, align 1\n", loaded, typ, pointerType, pointer)
	return "%" + loaded, func(value string) error {
		fmt.Fprintf(c.b, "  store volatile %s %s, %s %s, align 1\n", typ, value, pointerType, pointer)
		return nil
	}, nil
}

func (c *amd64Ctx) loadBitTestFPDestination(destination Operand, typ LLVMType) (string, func(string) error, error) {
	bits, _ := amd64IntegerTypeBits(typ)
	width := bits / 8
	result, err := c.bitTestFPSpan(destination.FPOffset, width)
	if err != nil {
		return "", nil, err
	}
	if result {
		if err := c.scalarFPResultInitialized(); err != nil {
			return "", nil, err
		}
	}
	bytes, err := c.loadX86PackedShiftBytes(destination, width, true)
	if err != nil {
		return "", nil, err
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to %s\n", value, width, bytes, typ)
	return "%" + value, func(value string) error {
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <%d x i8>\n", bytes, typ, value, width)
		return c.storeFPVectorBytes(destination.FPOffset, width, "%"+bytes, "")
	}, nil
}

func (c *amd64Ctx) bitTestFPSpan(off int64, width int) (bool, error) {
	if err := c.validateX86PackedShiftFPSpan(off, width); err != nil {
		return false, err
	}
	result := false
	for offset := off; offset < off+int64(width); offset++ {
		slot, output, _ := c.fpVectorSlot(offset)
		if slot.Type == Ptr || slot.Type == I1 {
			return false, fmt.Errorf("%w: FP bit string needs declared numerical bytes", ErrProbeNeedsContext)
		}
		result = result || output
	}
	return result, nil
}
