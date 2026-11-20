package plan9asm

import (
	"fmt"
	"strings"
)

// Classify binary x86 special values using integer operations only. This is
// also used after a real strict operation without changing its MXCSR effects.
func emitX86FloatAddSubSpecialBits(e *amd64FMA3IntegerEmitter, bits int) (special, result, rightSigned string) {
	fraction, exponent := 23, uint64(0x7f800000)
	if bits == 64 {
		fraction, exponent = 52, 0x7ff0000000000000
	}
	typ := amd64FMA3LLVMType(1, bits)
	left := e.value("bitcast %s %%left to i%d", typ, bits)
	right := e.value("bitcast %s %%right to i%d", typ, bits)
	sign := uint64(1) << (bits - 1)
	leftAbs := e.value("and i%d %s, %d", bits, left, sign-1)
	rightAbs := e.value("and i%d %s, %d", bits, right, sign-1)
	leftNaN := e.value("icmp ugt i%d %s, %d", bits, leftAbs, exponent)
	rightNaN := e.value("icmp ugt i%d %s, %d", bits, rightAbs, exponent)
	leftInf := e.value("icmp eq i%d %s, %d", bits, leftAbs, exponent)
	rightInf := e.value("icmp eq i%d %s, %d", bits, rightAbs, exponent)
	special = e.value("or i1 %s, %s", leftNaN, rightNaN)
	special = e.value("or i1 %s, %s", special, leftInf)
	special = e.value("or i1 %s, %s", special, rightInf)
	negated := e.value("xor i%d %s, %d", bits, right, sign)
	rightSigned = e.value("select i1 %%subtract, i%d %s, i%d %s", bits, negated, bits, right)
	quiet := uint64(1) << (fraction - 1)
	leftQuiet := e.value("or i%d %s, %d", bits, left, quiet)
	rightQuiet := e.value("or i%d %s, %d", bits, right, quiet)
	// SUB never toggles a NaN's sign/payload, only its finite/inf operand sign.
	nan := e.value("select i1 %s, i%d %s, i%d %s", leftNaN, bits, leftQuiet, bits, rightQuiet)
	anyNaN := e.value("or i1 %s, %s", leftNaN, rightNaN)
	signs := e.value("xor i%d %s, %s", bits, left, rightSigned)
	opposite := e.value("icmp slt i%d %s, 0", bits, signs)
	bothInf := e.value("and i1 %s, %s", leftInf, rightInf)
	invalid := e.value("and i1 %s, %s", bothInf, opposite)
	infinity := e.value("select i1 %s, i%d %s, i%d %s", leftInf, bits, left, bits, rightSigned)
	infinity = e.value("select i1 %s, i%d %d, i%d %s", invalid, bits, sign|exponent|quiet, bits, infinity)
	result = e.value("select i1 %s, i%d %s, i%d %s", anyNaN, bits, nan, bits, infinity)
	return
}

func emitX86FloatAddSubSpecialHelper(b *strings.Builder, bits int) {
	typ := amd64FMA3LLVMType(1, bits)
	fmt.Fprintf(b, "define internal %s @__plan9asm_add_sub_special_f%d(%s %%left, %s %%right, i1 %%subtract, %s %%hardware) {\nentry:\n", typ, bits, typ, typ, typ)
	e := amd64FMA3IntegerEmitter{b: b}
	special, result, _ := emitX86FloatAddSubSpecialBits(&e, bits)
	floatResult := e.value("bitcast i%d %s to %s", bits, result, typ)
	selected := e.value("select i1 %s, %s %s, %s %%hardware", special, typ, floatResult, typ)
	fmt.Fprintf(b, "  ret %s %s\n}\n\n", typ, selected)
}

// Embedded rounding suppresses exceptions. Only finite binary arithmetic
// uses the reviewed exact accumulator (a*1+b); special results remain ADD/SUB
// semantics rather than FMA's operand priority.
func emitX86FloatAddSubRoundingHelper(b *strings.Builder, bits int) {
	typ := amd64FMA3LLVMType(1, bits)
	fmt.Fprintf(b, "define internal %s @__plan9asm_add_sub_round_f%d(%s %%left, %s %%right, i1 %%subtract, i32 %%mode, i32 %%mxcsr) {\nentry:\n", typ, bits, typ, typ)
	e := amd64FMA3IntegerEmitter{b: b}
	special, result, rightSigned := emitX86FloatAddSubSpecialBits(&e, bits)
	fmt.Fprintf(b, "  br i1 %s, label %%special, label %%finite\nspecial:\n", special)
	floatResult := e.value("bitcast i%d %s to %s", bits, result, typ)
	fmt.Fprintf(b, "  ret %s %s\nfinite:\n", typ, floatResult)
	rightFloat := e.value("bitcast i%d %s to %s", bits, rightSigned, typ)
	finite := e.value("call %s @__plan9asm_fma3_round_f%d(%s %%left, %s 1.0, %s %s, i32 %%mode, i32 %%mxcsr)", typ, bits, typ, typ, typ, rightFloat)
	fmt.Fprintf(b, "  ret %s %s\n}\n\n", typ, finite)
}

func (c *amd64Ctx) emitRoundedFloatAddSub(lanes, bits int, left, right string, subtract bool, rounding string) string {
	typ, vectorType := amd64FMA3LLVMType(1, bits), amd64FMA3LLVMType(lanes, bits)
	mode, mxcsr := c.packedNumericRoundingMode(rounding), c.loadMXCSR()
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		values := []string{left, right}
		if lanes > 1 {
			for index, value := range values {
				extracted := c.newTmp()
				fmt.Fprintf(c.b, "  %%%s = extractelement %s %s, i32 %d\n", extracted, vectorType, value, lane)
				values[index] = "%" + extracted
			}
		}
		computed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @__plan9asm_add_sub_round_f%d(%s %s, %s %s, i1 %t, i32 %s, i32 %s)\n", computed, typ, bits, typ, values[0], typ, values[1], subtract, mode, mxcsr)
		if lanes == 1 {
			return "%" + computed
		}
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement %s %s, %s %%%s, i32 %d\n", inserted, vectorType, result, typ, computed, lane)
		result = "%" + inserted
	}
	return result
}
