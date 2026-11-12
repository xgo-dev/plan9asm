package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) compareExchangeNativePrefix(memory Operand) (lock, segment string) {
	if c.namedAtomicLock {
		lock = "lock; "
	}
	if memory.Kind == OpMem && memory.Mem.Segment != "" {
		segment = "%" + strings.ToLower(string(memory.Mem.Segment)) + ":"
	}
	return lock, segment
}

func (c *amd64Ctx) emitScalarCompareExchangeNative(bits int, memory Operand, pointer, pointerType, expected, desired string) (old, success string) {
	lock, segment := c.compareExchangeNativePrefix(memory)
	typ := amd64IntegerTypeForBits(bits)
	width := map[int]string{8: "b", 16: "w", 32: "l", 64: "q"}[bits]
	register := "r"
	if bits == 8 {
		register = "q"
	}
	result, oldName, successByte, successName := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	// The complete native opcode supplies the read/write cycle on both paths,
	// including failure. A plain original opcode does not acquire LOCK. No LLVM
	// alignment precondition is asserted, and explicit FS/GS remains attached.
	fmt.Fprintf(c.b, "  %%%s = call { %s, i8 } asm sideeffect \"%scmpxchg%s $3, %s$2; sete $1\", \"={ax},=q,=*m,%s,0,*m,~{memory},~{dirflag},~{fpsr},~{flags}\"(%s elementtype(%s) %s, %s %s, %s %s, %s elementtype(%s) %s)\n",
		result, typ, lock, width, segment, register, pointerType, typ, pointer, typ, desired, typ, expected, pointerType, typ, pointer)
	fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, i8 } %%%s, 0\n", oldName, typ, result)
	fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, i8 } %%%s, 1\n", successByte, typ, result)
	fmt.Fprintf(c.b, "  %%%s = icmp ne i8 %%%s, 0\n", successName, successByte)
	return "%" + oldName, "%" + successName
}

func (c *amd64Ctx) emitPairCompareExchangeNative(bits int, memory Operand, pointer, pointerType, ax, dx, bx, cx string) (old, success string) {
	lock, segment := c.compareExchangeNativePrefix(memory)
	part, pair, mnemonic := I32, LLVMType("i64"), "cmpxchg8b"
	if bits == 128 {
		part, pair, mnemonic = I64, LLVMType("i128"), "cmpxchg16b"
	} else {
		ax, dx = c.truncI64(ax, I32), c.truncI64(dx, I32)
		bx, cx = c.truncI64(bx, I32), c.truncI64(cx, I32)
	}
	result := c.newTmp()
	// 8B supports unaligned memory without an invented natural alignment.
	// 16B retains the actual opcode's native #GP when its address is unaligned;
	// LLVM align=16 would instead give undefined behavior, not that exception.
	fmt.Fprintf(c.b, "  %%%s = call { %s, %s, i8 } asm sideeffect \"%s%s %s$3; sete $2\", \"={ax},={dx},=q,=*m,{bx},{cx},0,1,*m,~{memory},~{dirflag},~{fpsr},~{flags}\"(%s elementtype(%s) %s, %s %s, %s %s, %s %s, %s %s, %s elementtype(%s) %s)\n",
		result, part, part, lock, mnemonic, segment, pointerType, pair, pointer, part, bx, part, cx, part, ax, part, dx, pointerType, pair, pointer)
	low, high, byteName, successName := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, %s, i8 } %%%s, 0\n", low, part, part, result)
	fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, %s, i8 } %%%s, 1\n", high, part, part, result)
	fmt.Fprintf(c.b, "  %%%s = extractvalue { %s, %s, i8 } %%%s, 2\n", byteName, part, part, result)
	fmt.Fprintf(c.b, "  %%%s = icmp ne i8 %%%s, 0\n", successName, byteName)
	low64, high64 := "%"+low, "%"+high
	if part == I32 {
		lowWide, highWide := c.newTmp(), c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", lowWide, low64)
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", highWide, high64)
		low64, high64 = "%"+lowWide, "%"+highWide
	}
	return c.compareExchangeJoinPair(low64, high64, bits), "%" + successName
}
