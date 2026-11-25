package x86

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
)

func (c *amd64Ctx) lowerCrc32(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	var srcTy asm.LLVMType
	switch op {
	case "CRC32B":
		srcTy = asm.I8
	case "CRC32W":
		srcTy = asm.I16
	case "CRC32L":
		srcTy = asm.I32
	case "CRC32Q":
		srcTy = asm.I64
	default:
		return false, false, nil
	}
	if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg ||
		(ins.Args[0].Kind != asm.OpMem && ins.Args[0].Kind != asm.OpReg && ins.Args[0].Kind != asm.OpSym) {
		return true, false, fmt.Errorf("amd64 %s expects mem/reg, reg: %q", op, ins.Raw)
	}
	dst := ins.Args[1].Reg

	sv, err := c.evalIntSized(ins.Args[0], srcTy)
	if err != nil {
		return true, false, err
	}
	dv, err := c.loadReg(dst)
	if err != nil {
		return true, false, err
	}

	switch op {
	case "CRC32Q":
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i64 @llvm.x86.sse42.crc32.64.64(i64 %s, i64 %s)\n", call, dv, sv)
		return true, false, c.storeReg(dst, "%"+call)

	case "CRC32L":
		crc32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", crc32, dv)
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.x86.sse42.crc32.32.32(i32 %%%s, i32 %s)\n", call, crc32, sv)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, call)
		return true, false, c.storeReg(dst, "%"+z)

	case "CRC32W":
		crc32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", crc32, dv)
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.x86.sse42.crc32.32.16(i32 %%%s, i16 %s)\n", call, crc32, sv)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, call)
		return true, false, c.storeReg(dst, "%"+z)

	case "CRC32B":
		crc32 := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i32\n", crc32, dv)
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.x86.sse42.crc32.32.8(i32 %%%s, i8 %s)\n", call, crc32, sv)
		z := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %%%s to i64\n", z, call)
		return true, false, c.storeReg(dst, "%"+z)
	}
	return true, false, fmt.Errorf("amd64: unknown CRC32 op %s", op)
}
