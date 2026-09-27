package plan9asm

import (
	"fmt"
	"strings"
)

type amd64ParallelBitSpec struct {
	bits, prefix int
	deposit      bool
}

var amd64ParallelBitSpecs = map[string]amd64ParallelBitSpec{
	"PDEPL": {bits: 32, prefix: 3, deposit: true},
	"PDEPQ": {bits: 64, prefix: 3, deposit: true},
	"PEXTL": {bits: 32, prefix: 2},
	"PEXTQ": {bits: 64, prefix: 2},
}

// lowerParallelBitDepositExtract implements the complete Go 1.27 PDEP/PEXT
// family. All four instructions share _yandnl's single Yml, Yrl, Yrl row.
func (c *amd64Ctx) lowerParallelBitDepositExtract(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, supported := amd64ParallelBitSpecs[baseOp]
	if !supported {
		return false, false, nil
	}
	bits := spec.bits
	// Go accepts Q names on 386, but VEX.W is ignored in not64 mode.
	// In particular, a memory mask must not accidentally read eight bytes.
	if c.goarch == "386" {
		bits = 32
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("amd64 %s has no instruction suffixes in Go 1.27's optab: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 3 {
		return true, false, fmt.Errorf("amd64 %s expects mask, source, destination: %q", baseOp, ins.Raw)
	}
	maskOperand := ins.Args[0]
	if maskOperand.Kind == OpReg {
		if !isX86YrlRegisterForArch(maskOperand.Reg, c.goarch) {
			return true, false, fmt.Errorf("amd64 %s first operand is outside Go 1.27's Yml class: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(maskOperand) {
		return true, false, fmt.Errorf("amd64 %s first operand is outside Go 1.27's Yml class: %q", baseOp, ins.Raw)
	}
	if ins.Args[1].Kind != OpReg || !isX86YrlRegisterForArch(ins.Args[1].Reg, c.goarch) {
		return true, false, fmt.Errorf("amd64 %s second operand is outside Go 1.27's Yrl class: %q", baseOp, ins.Raw)
	}
	if ins.Args[2].Kind != OpReg || !isX86YrlRegisterForArch(ins.Args[2].Reg, c.goarch) {
		return true, false, fmt.Errorf("amd64 %s destination is outside Go 1.27's Yrl class: %q", baseOp, ins.Raw)
	}

	typ := amd64IntegerTypeForBits(bits)
	mask, err := c.evalIntSized(maskOperand, typ)
	if err != nil {
		return true, false, err
	}
	source, err := c.evalIntSized(ins.Args[1], typ)
	if err != nil {
		return true, false, err
	}
	result := c.emitParallelBitOperation(spec.deposit, bits, mask, source)
	return true, false, c.storeRegSized(ins.Args[2].Reg, typ, result)
}

// emitParallelBitOperation emits target-independent LLVM so translated code
// retains PDEP/PEXT semantics even when the LLVM execution host lacks BMI2.
// cursor is at most bit before each iteration, so every variable shift stays
// strictly below the integer width and cannot produce LLVM poison.
func (c *amd64Ctx) emitParallelBitOperation(deposit bool, bits int, mask, source string) string {
	typ := fmt.Sprintf("i%d", bits)
	result := "0"
	cursor := "0"
	for bit := 0; bit < bits; bit++ {
		shiftedMask := c.newTmp()
		maskBit := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %d\n", shiftedMask, typ, mask, bit)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 1\n", maskBit, typ, shiftedMask)

		sourceShift := cursor
		destinationShift := fmt.Sprintf("%d", bit)
		if !deposit {
			sourceShift = fmt.Sprintf("%d", bit)
			destinationShift = cursor
		}
		shiftedSource := c.newTmp()
		sourceBit := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = lshr %s %s, %s\n", shiftedSource, typ, source, sourceShift)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, 1\n", sourceBit, typ, shiftedSource)
		placed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shl %s %%%s, %s\n", placed, typ, sourceBit, destinationShift)
		enabledMask := c.newTmp()
		enabled := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = sub %s 0, %%%s\n", enabledMask, typ, maskBit)
		fmt.Fprintf(c.b, "  %%%s = and %s %%%s, %%%s\n", enabled, typ, placed, enabledMask)
		nextResult := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or %s %s, %%%s\n", nextResult, typ, result, enabled)
		result = "%" + nextResult
		nextCursor := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %%%s\n", nextCursor, typ, cursor, maskBit)
		cursor = "%" + nextCursor
	}
	return result
}
