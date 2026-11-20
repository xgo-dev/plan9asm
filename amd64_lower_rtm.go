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
	spec, form, known, err := x86RTMProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	return c.emitRTM(bi, ii, strings.ToUpper(string(op)), spec, form, emitCondBr)
}

func x86RTMProperties(op Op, ins Instr, arch string) (amd64RTMSpec, amd64RTMForm, bool, error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64RTMSpecs[Op(baseOp)]
	if !recognized {
		return spec, amd64RTMForm{}, false, nil
	}
	if rawOp != baseOp || arch != "386" && arch != "amd64" ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), rawOp) {
		return spec, amd64RTMForm{}, true, fmt.Errorf("%s %s has an invalid suffix, mode or dispatch identity: %q", arch, op, ins.Raw)
	}
	form, err := parseX86RTMForm(baseOp, spec, ins, arch)
	return spec, form, true, err
}

func parseX86RTMForm(op string, spec amd64RTMSpec, ins Instr, arch string) (amd64RTMForm, error) {
	var form amd64RTMForm
	switch spec.operand {
	case amd64RTMNoOperand:
		if len(ins.Args) != 0 {
			return form, fmt.Errorf("%s %s takes no operands: %q", arch, op, ins.Raw)
		}
	case amd64RTMBranch:
		if len(ins.Args) != 1 {
			return form, fmt.Errorf("%s %s expects one Go 1.27 Ybr target: %q", arch, op, ins.Raw)
		}
		form.branch = ins.Args[0]
	case amd64RTMUnsignedByte:
		if len(ins.Args) != 1 || ins.Args[0].Kind != OpImm || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 ||
			ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
			return form, fmt.Errorf("%s %s expects one Go 1.27 Yu8 integer immediate: %q", arch, op, ins.Raw)
		}
		form.immediate = uint8(ins.Args[0].Imm)
	default:
		panic("unknown amd64 RTM operand kind")
	}
	return form, nil
}

// Only the query kind is an ordinary numerical effect. Transaction begin,
// abort and end cannot inherit this straight-line storage/FLAGS continuation.
func x86TypedRTMStatusByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	spec, _, known, err := x86RTMProperties(op, ins, arch)
	if !known || spec.kind != amd64RTMTest {
		return x86TypedByteEffect{}, false, nil
	}
	if err != nil {
		return x86TypedByteEffect{}, true, err
	}
	if !x86RegisterQueryPreservesSourceState(ins) {
		return x86TypedByteEffect{}, true, fmt.Errorf("%w: RTM status query original/normalized identity differs", ErrProbeNeedsContext)
	}
	// XTEST reads no GP, numerical or incoming FLAGS input. Its hardware
	// transaction observation defines ZF and clears the other five flags.
	return x86TypedByteEffect{flagsDefined: x86ByteFlagsAll, flagsKilled: x86ByteFlagsAll}, true, nil
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
		c.clearX86StatusFlags(x86StatusAll &^ x86StatusZF)
	default:
		panic("unknown amd64 RTM kind")
	}
	return true, false, nil
}
