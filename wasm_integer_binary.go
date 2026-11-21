package plan9asm

import (
	"fmt"
	"strings"
)

func parseWASMIntegerBinary(ins Instr, name string) (wasmIntegerOp, bool, error) {
	spec, found := wasmIntegerBinaryOps[name]
	if found && (strings.ToUpper(string(ins.Op)) != name || len(ins.Args) != 0) {
		return spec, true, fmt.Errorf("%s is a zero-operand WebAssembly stack instruction without suffixes", ins.Op)
	}
	return spec, found, nil
}

func (spec wasmIntegerOp) rotateIntrinsic() string {
	if spec.op == "fshl" || spec.op == "fshr" {
		return spec.op + "." + string(spec.typ)
	}
	return ""
}

func (spec wasmIntegerOp) traps() bool {
	switch spec.op {
	case "sdiv", "udiv", "srem", "urem":
		return true
	default:
		return false
	}
}

func (spec wasmIntegerOp) bitWidth() int {
	if spec.typ == I64 {
		return 64
	}
	return 32
}

func (spec wasmIntegerOp) emitBinary(b *strings.Builder, left, right wasmValue, newTmp func() string, newLabel func(string) string) wasmValue {
	typ := spec.typ
	result := wasmValue{typ: typ, val: "%" + newTmp()}
	if intrinsic := spec.rotateIntrinsic(); intrinsic != "" {
		// Funnel shifts rotate when their two inputs are identical. LLVM
		// reduces the unsigned count modulo the carrier width.
		fmt.Fprintf(b, "  %s = call %s @llvm.%s(%s %s, %s %s, %s %s)\n",
			result.val, typ, intrinsic, typ, left.val, typ, left.val, typ, right.val)
		return result
	}
	switch spec.op {
	case "shl", "lshr", "ashr":
		count := newTmp()
		fmt.Fprintf(b, "  %%%s = and %s %s, %d\n", count, typ, right.val, spec.bitWidth()-1)
		right.val = "%" + count
	default:
		if spec.traps() {
			right.val = spec.checkDivision(b, left.val, right.val, newTmp, newLabel)
		}
	}
	fmt.Fprintf(b, "  %s = %s %s %s, %s\n", result.val, spec.op, typ, left.val, right.val)
	return result
}

func (spec wasmIntegerOp) checkDivision(b *strings.Builder, left, right string, newTmp func() string, newLabel func(string) string) string {
	typ := spec.typ
	nonzero := newTmp()
	fmt.Fprintf(b, "  %%%s = icmp ne %s %s, 0\n", nonzero, typ, right)
	valid := nonzero
	if spec.op == "sdiv" {
		outsideMinimum, notNegativeOne, fits := newTmp(), newTmp(), newTmp()
		valid = newTmp()
		minimum := int64(-1) << (spec.bitWidth() - 1)
		fmt.Fprintf(b, "  %%%s = icmp ne %s %s, %d\n", outsideMinimum, typ, left, minimum)
		fmt.Fprintf(b, "  %%%s = icmp ne %s %s, -1\n", notNegativeOne, typ, right)
		fmt.Fprintf(b, "  %%%s = or i1 %%%s, %%%s\n", fits, outsideMinimum, notNegativeOne)
		fmt.Fprintf(b, "  %%%s = and i1 %%%s, %%%s\n", valid, nonzero, fits)
	}
	// LLVM can discard the arithmetic when its result is unused. Wasm
	// requires the invalid operation to trap even if the result is dropped.
	emitWASMTrapUnless(b, valid, newLabel)
	if spec.op == "srem" {
		// MIN % -1 is zero in Wasm and undefined for LLVM srem. Replacing
		// -1 with +1 preserves every remainder and avoids LLVM overflow.
		negativeOne, divisor := newTmp(), newTmp()
		fmt.Fprintf(b, "  %%%s = icmp eq %s %s, -1\n", negativeOne, typ, right)
		fmt.Fprintf(b, "  %%%s = select i1 %%%s, %s 1, %s %s\n", divisor, negativeOne, typ, typ, right)
		return "%" + divisor
	}
	return right
}
