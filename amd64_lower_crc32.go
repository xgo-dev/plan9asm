package plan9asm

import "fmt"

func (c *amd64Ctx) lowerCrc32(op Op, ins Instr) (ok bool, terminated bool, err error) {
	sourceType := LLVMType("")
	intrinsic := ""
	resultType := I32
	switch op {
	case "CRC32B":
		sourceType = I8
		intrinsic = "llvm.x86.sse42.crc32.32.8"
	case "CRC32W":
		sourceType = I16
		intrinsic = "llvm.x86.sse42.crc32.32.16"
	case "CRC32L":
		sourceType = I32
		intrinsic = "llvm.x86.sse42.crc32.32.32"
	case "CRC32Q":
		if c.goarch == "386" {
			return true, false, fmt.Errorf("386 CRC32Q is illegal in 32-bit mode: %q", ins.Raw)
		}
		sourceType = I64
		resultType = I64
		intrinsic = "llvm.x86.sse42.crc32.64.64"
	default:
		return false, false, nil
	}
	if len(ins.Args) != 2 {
		return true, false, fmt.Errorf("%s %s expects register/memory source and register destination: %q", c.goarch, op, ins.Raw)
	}
	source, destination := ins.Args[0], ins.Args[1]
	if source.Kind == OpReg {
		valid := isX86YrlRegisterForArch(source.Reg, c.goarch)
		if op == "CRC32B" {
			valid = isGoYmbRegisterForArch(source.Reg, c.goarch)
		}
		if !valid {
			return true, false, fmt.Errorf("%s %s source is outside Go 1.27's %s class: %q", c.goarch, op, map[bool]string{true: "Ymb", false: "Yml"}[op == "CRC32B"], ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s source is outside Go 1.27's register/memory class: %q", c.goarch, op, ins.Raw)
	}
	if destination.Kind != OpReg || !isX86YrlRegisterForArch(destination.Reg, c.goarch) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's Yrl class: %q", c.goarch, op, ins.Raw)
	}

	sourceValue, err := c.evalIntSized(source, sourceType)
	if err != nil {
		return true, false, err
	}
	crcValue, err := c.evalIntSized(destination, resultType)
	if err != nil {
		return true, false, err
	}
	call := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @%s(%s %s, %s %s)\n", call, resultType, intrinsic, resultType, crcValue, sourceType, sourceValue)
	return true, false, c.storeRegSized(destination.Reg, resultType, "%"+call)
}
