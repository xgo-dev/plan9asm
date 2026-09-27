package plan9asm

import (
	"fmt"
	"strings"
)

// lowerBitTestFamily implements the complete Go 1.27 ybtl table. BTW/L/Q,
// BTCW/L/Q, BTRW/L/Q, and BTSW/L/Q all accept exactly either a signed imm8 or
// a Yrl register bit index followed by a Yml register/memory destination.
func (c *amd64Ctx) lowerBitTestFamily(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	stem, bits, recognized := amd64BitTestProperties(baseOp)
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && bits == 64 {
		return true, false, fmt.Errorf("386 %s is illegal in 32-bit mode: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("%s %s expects bit index and destination: %q", c.goarch, baseOp, ins.Raw)
	}

	indexOperand := ins.Args[0]
	if indexOperand.Kind == OpImm {
		if indexOperand.Imm < -128 || indexOperand.Imm > 127 {
			return true, false, fmt.Errorf("%s %s index is outside Go 1.27's signed-imm8 class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if indexOperand.Kind != OpReg || !isX86YrlRegisterForArch(indexOperand.Reg, c.goarch) {
		return true, false, fmt.Errorf("%s %s index is outside Go 1.27's Yi8/Yrl classes: %q", c.goarch, baseOp, ins.Raw)
	}
	destination := ins.Args[1]
	if destination.Kind == OpReg {
		if !isX86YrlRegisterForArch(destination.Reg, c.goarch) {
			return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's Yml class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(destination) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's Yml class: %q", c.goarch, baseOp, ins.Raw)
	}

	typ := amd64IntegerTypeForBits(bits)
	bitIndex, memoryWordOffset, registerIndex, err := c.bitTestIndex(indexOperand, bits, typ)
	if err != nil {
		return true, false, err
	}
	value, store, err := c.loadBitTestDestination(destination, typ, memoryWordOffset, registerIndex)
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
	if !registerIndex || destination.Kind == OpReg || destination.Kind == OpFP {
		return c.loadIntDestination(destination, typ)
	}

	var address string
	var addressSpace int
	switch destination.Kind {
	case OpMem:
		var err error
		address, err = c.addrFromPlainMem(destination.Mem)
		if err != nil {
			return "", nil, err
		}
		switch destination.Mem.Segment {
		case "":
		case GS:
			addressSpace = 256
		case FS:
			addressSpace = 257
		default:
			return "", nil, fmt.Errorf("unsupported x86 segment register %s", destination.Mem.Segment)
		}
	case OpSym:
		pointer, err := c.ptrFromSB(destination.Sym)
		if err != nil {
			return "", nil, err
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = ptrtoint ptr %s to i64\n", converted, pointer)
		address = "%" + converted
	default:
		return "", nil, fmt.Errorf("expected register or memory destination, got %s", destination.String())
	}
	adjusted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", adjusted, address, memoryWordOffset)
	pointer := c.newTmp()
	pointerType := "ptr"
	if addressSpace != 0 {
		pointerType = fmt.Sprintf("ptr addrspace(%d)", addressSpace)
	}
	fmt.Fprintf(c.b, "  %%%s = inttoptr i64 %%%s to %s\n", pointer, adjusted, pointerType)
	loaded := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load %s, %s %%%s, align 1\n", loaded, typ, pointerType, pointer)
	return "%" + loaded, func(value string) error {
		fmt.Fprintf(c.b, "  store %s %s, %s %%%s, align 1\n", typ, value, pointerType, pointer)
		return nil
	}, nil
}
