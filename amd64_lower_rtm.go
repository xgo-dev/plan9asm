package plan9asm

import (
	"fmt"
	"strings"
)

type amd64RTMKind uint8

const (
	amd64RTMBegin amd64RTMKind = iota
	amd64RTMAbort
	amd64RTMEnd
	amd64RTMTest
)

type amd64RTMOperand uint8

const (
	amd64RTMNoOperand amd64RTMOperand = iota
	amd64RTMBranch
	amd64RTMUnsignedByte
)

type amd64RTMSpec struct {
	kind     amd64RTMKind
	operand  amd64RTMOperand
	outputAX bool
}

// amd64RTMSpecs is the complete Go 1.27 Restricted Transactional Memory
// grammar. XBEGIN is included even though Go's positive encoder corpus keeps
// its cases as TODOs: the optab accepts one Ybr target and writes abort status
// to EAX. XABORT accepts the complete Yu8 immediate domain.
var amd64RTMSpecs = map[Op]amd64RTMSpec{
	"XBEGIN": {kind: amd64RTMBegin, operand: amd64RTMBranch, outputAX: true},
	"XABORT": {kind: amd64RTMAbort, operand: amd64RTMUnsignedByte},
	"XEND":   {kind: amd64RTMEnd},
	"XTEST":  {kind: amd64RTMTest},
}

type amd64RTMForm struct {
	branch    Operand
	immediate uint8
}

func (c *amd64Ctx) lowerRTM(bi int, ii int, op Op, ins Instr, emitCondBr amd64EmitCondBr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64RTMSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	form, err := c.parseRTMForm(baseOp, spec, ins)
	if err != nil {
		return true, false, err
	}
	return c.emitRTM(bi, ii, baseOp, spec, form, emitCondBr)
}

func (c *amd64Ctx) parseRTMForm(op string, spec amd64RTMSpec, ins Instr) (amd64RTMForm, error) {
	var form amd64RTMForm
	switch spec.operand {
	case amd64RTMNoOperand:
		if len(ins.Args) != 0 {
			return form, fmt.Errorf("%s %s takes no operands: %q", c.goarch, op, ins.Raw)
		}
	case amd64RTMBranch:
		if len(ins.Args) != 1 {
			return form, fmt.Errorf("%s %s expects one Go 1.27 Ybr target: %q", c.goarch, op, ins.Raw)
		}
		form.branch = ins.Args[0]
	case amd64RTMUnsignedByte:
		if len(ins.Args) != 1 || ins.Args[0].Kind != OpImm || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
			return form, fmt.Errorf("%s %s expects one Go 1.27 Yu8 immediate: %q", c.goarch, op, ins.Raw)
		}
		form.immediate = uint8(ins.Args[0].Imm)
	default:
		panic("unknown amd64 RTM operand kind")
	}
	return form, nil
}

func (c *amd64Ctx) rtmBranchTarget(bi int, ii int, operand Operand) (string, error) {
	knownBlock := func(name string) bool {
		for _, block := range c.blocks {
			if block.name == name {
				return true
			}
		}
		return false
	}
	var target string
	switch operand.Kind {
	case OpIdent:
		target = operand.Ident
	case OpReg:
		target = string(operand.Reg)
		if !knownBlock(target) {
			return "", fmt.Errorf("%s XBEGIN register is not a local branch target: %q", c.goarch, target)
		}
	case OpSym:
		target = strings.TrimSpace(operand.Sym)
		if strings.HasSuffix(target, "(SB)") {
			return "", fmt.Errorf("%s XBEGIN target must be local: %q", c.goarch, target)
		}
		target = strings.TrimSuffix(target, "<>")
	case OpMem:
		if !strings.EqualFold(string(operand.Mem.Base), "PC") {
			return "", fmt.Errorf("%s XBEGIN expects a label or PC-relative target", c.goarch)
		}
		current := c.blockBase[bi] + ii
		index := current + int(operand.Mem.Off)
		targetBlock, ok := c.blockByIdx[index]
		if !ok || targetBlock < 0 || targetBlock >= len(c.blocks) {
			return "", fmt.Errorf("%s XBEGIN invalid PC-relative target %d(PC)", c.goarch, operand.Mem.Off)
		}
		target = c.blocks[targetBlock].name
	default:
		return "", fmt.Errorf("%s XBEGIN expects one Go 1.27 Ybr target", c.goarch)
	}
	if target == "" || !knownBlock(target) {
		return "", fmt.Errorf("%s XBEGIN unknown local target %q", c.goarch, target)
	}
	return target, nil
}

func (c *amd64Ctx) emitRTM(bi int, ii int, op string, spec amd64RTMSpec, form amd64RTMForm, emitCondBr amd64EmitCondBr) (bool, bool, error) {
	switch spec.kind {
	case amd64RTMBegin:
		if bi+1 >= len(c.blocks) {
			return true, false, fmt.Errorf("%s XBEGIN has no success fallthrough", c.goarch)
		}
		target, err := c.rtmBranchTarget(bi, ii, form.branch)
		if err != nil {
			return true, false, err
		}
		status := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.x86.xbegin()\n", status)
		if err := c.storeRegSized(AX, I32, "%"+status); err != nil {
			return true, false, err
		}
		success := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %%%s, -1\n", success, status)
		if err := emitCondBr("%"+success, c.blocks[bi+1].name, target); err != nil {
			return true, false, err
		}
		return true, true, nil
	case amd64RTMAbort:
		fmt.Fprintf(c.b, "  call void @llvm.x86.xabort(i8 %d)\n", form.immediate)
	case amd64RTMEnd:
		c.b.WriteString("  call void @llvm.x86.xend()\n")
	case amd64RTMTest:
		active := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.x86.xtest()\n", active)
		zero := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = icmp eq i32 %%%s, 0\n", zero, active)
		fmt.Fprintf(c.b, "  store i1 %%%s, ptr %s\n", zero, c.flagsZSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsCFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsSltSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsPFSlot)
		fmt.Fprintf(c.b, "  store i1 false, ptr %s\n", c.flagsOFSlot)
	default:
		panic("unknown amd64 RTM kind")
	}
	return true, false, nil
}
