package plan9asm

import (
	"reflect"
	"strings"
)

// A zero-add to the zero-frame return word leaves that private word unchanged.
// With no route around the zero producer and no use of the register or FLAGS
// after the exchange, the remaining effect in a logical void entry is a fence.
func (c *amd64Ctx) bindMode32StackFence() error {
	fn, sig := c.fpScalarSource, c.fpSourceSig
	if c.goarch != "386" || !x86ScalarFloatIntegerNativeTarget("386", c.targetTriple) ||
		fn.FrameSize != 0 || sig.Ret != Void || len(sig.Frame.Results) != 0 || len(sig.ArgRegs) != 0 ||
		fn.x86DirectTailRoot != nil || fn.x86ContinuationFlow != nil || fn.x86SourceStack != nil ||
		fn.x86FixedLocal != nil || fn.x86RawReplay != nil || len(fn.X86RawText) != 0 ||
		len(fn.Instrs) < 5 || len(c.blocks) == 0 || strings.Contains(fn.Sym, "<") {
		return nil
	}
	start := len(fn.Instrs) - 4
	epilogue := fn.Instrs[start:]
	zero, lock, add, ret := epilogue[0], epilogue[1], epilogue[2], epilogue[3]
	if add.Op != "XADDL" || len(add.Args) != 2 || add.Args[0].Kind != OpReg ||
		add.Args[1].Kind != OpMem || add.Args[1].Mem != (MemRef{Base: SP}) ||
		zero.Op != "XORL" || len(zero.Args) != 2 ||
		lock.Op != "LOCK" || len(lock.Args) != 0 || ret.Op != OpRET || len(ret.Args) != 0 {
		return nil
	}
	scratch := add.Args[0].Reg
	root, fullRegister := x86CallerGP(scratch)
	_, _, mode32 := x86ResultGP(scratch, 4, "386")
	if !fullRegister || root != scratch || !mode32 ||
		zero.Args[0].Kind != OpReg || zero.Args[0].Reg != scratch ||
		zero.Args[1].Kind != OpReg || zero.Args[1].Reg != scratch {
		return nil
	}
	_, operands := splitOpcode(add.Raw)
	literals := splitTopLevelCSV(operands)
	if len(literals) != 2 || literals[1] != "(SP)" && literals[1] != "0(SP)" {
		return nil // Named AUTO has a different meaning even at displacement zero.
	}
	last := c.blocks[len(c.blocks)-1].instrs
	if len(last) < len(epilogue) || !reflect.DeepEqual(last[len(last)-len(epilogue):], epilogue) {
		return nil // An alternate entry could bypass the scratch zero.
	}
	for ordinal, ins := range fn.Instrs {
		_, stack, _ := x86StackWidthProperties(ins, c.goarch)
		if !x86ResultNamedPredicateInstruction(ins) || stack || ins.Op == "ADJSP" ||
			ins.Op == "ENTER" || ins.Op == "LEAVE" || ins.Op == OpCALL && fn.x86PanicTarget(ins) == "" {
			return nil
		}
		if ordinal == start+2 {
			continue
		}
		for _, operand := range ins.Args {
			if operand.Reg == SP || operand.Mem.Base == SP || operand.Mem.Index == SP {
				return nil
			}
		}
	}
	if err := x86ResultLocalSourceReplay(fn, "386", "zero-frame fence"); err != nil {
		return err
	}
	c.fpScalarSource.x86StackFence = &add
	return nil
}

func (fn Func) x86StackFenceAt(ins Instr) bool {
	return fn.x86StackFence != nil && ins.Op == "XADDL" && reflect.DeepEqual(*fn.x86StackFence, ins)
}
