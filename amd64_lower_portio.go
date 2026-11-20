package plan9asm

import (
	"fmt"
	"strings"
)

func x86PortScalarProperties(op Op) (input bool, typ LLVMType, ok bool) {
	switch strings.ToUpper(string(op)) {
	case "INB":
		return true, I8, true
	case "INW":
		return true, I16, true
	case "INL":
		return true, I32, true
	case "OUTB":
		return false, I8, true
	case "OUTW":
		return false, I16, true
	case "OUTL":
		return false, I32, true
	default:
		return false, "", false
	}
}

func x86PortStringProperties(op Op) (input bool, width int, ok bool) {
	switch strings.ToUpper(string(op)) {
	case "INSB":
		return true, 1, true
	case "INSW":
		return true, 2, true
	case "INSL":
		return true, 4, true
	case "OUTSB":
		return false, 1, true
	case "OUTSW":
		return false, 2, true
	case "OUTSL":
		return false, 4, true
	default:
		return false, 0, false
	}
}

// lowerPortIO implements the complete x86 port-I/O rows in Go's yin and
// ynone operand tables. These instructions are inherently target-specific, so
// preserving them as constrained LLVM inline assembly is both more accurate
// and safer than pretending that they are ordinary memory accesses.
func (c *amd64Ctx) lowerPortIO(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if input, typ, scalar := x86PortScalarProperties(op); scalar {
		if c.repeatPrefix != "" {
			prefix := c.repeatPrefix
			c.repeatPrefix = ""
			return true, false, fmt.Errorf("%s %s prefix is unsupported for %s", c.goarch, prefix, op)
		}
		if len(ins.Args) > 1 || (len(ins.Args) == 1 && ins.Args[0].Kind != OpImm) {
			return true, false, fmt.Errorf("%s %s expects no operand or one immediate: %q", c.goarch, op, ins.Raw)
		}
		if len(ins.Args) == 1 && (ins.Args[0].Imm < -1<<31 || ins.Args[0].Imm > 1<<32-1) {
			return true, false, fmt.Errorf("%s %s immediate is outside the Go assembler's 32-bit form: %q", c.goarch, op, ins.Raw)
		}
		return true, false, c.lowerScalarPortIO(strings.ToLower(string(op)), input, typ, ins.Args)
	}

	input, _, stringOp := x86PortStringProperties(op)
	if !stringOp {
		return false, false, nil
	}
	prefix := c.repeatPrefix
	c.repeatPrefix = ""
	if len(ins.Args) != 0 {
		return true, false, fmt.Errorf("%s %s takes no operands: %q", c.goarch, op, ins.Raw)
	}
	return true, false, c.lowerStringPortIO(strings.ToLower(string(op)), input, prefix)
}

func (c *amd64Ctx) lowerScalarPortIO(asm string, input bool, typ LLVMType, args []Operand) error {
	constraints := "~{dirflag},~{fpsr},~{flags}"
	if input {
		call := c.newTmp()
		if len(args) == 0 {
			port, err := c.evalIntSized(Operand{Kind: OpReg, Reg: DX}, I16)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(i16 %s)\n", call, typ, asm+" $1, $0", "={ax},{dx},"+constraints, port)
		} else {
			fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q()\n", call, typ, fmt.Sprintf("%s $$%d, $0", asm, int64(args[0].Imm)), "={ax},"+constraints)
		}
		return c.storeRegSized(AX, typ, "%"+call)
	}

	value, err := c.evalIntSized(Operand{Kind: OpReg, Reg: AX}, typ)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		port, err := c.evalIntSized(Operand{Kind: OpReg, Reg: DX}, I16)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s %s, i16 %s)\n", asm+" $0, $1", "{ax},{dx},"+constraints, typ, value, port)
		return nil
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s %s)\n", fmt.Sprintf("%s $0, $$%d", asm, int64(args[0].Imm)), "{ax},"+constraints, typ, value)
	return nil
}

func (c *amd64Ctx) lowerStringPortIO(asm string, input bool, prefix string) error {
	indexReg := SI
	indexConstraint := "{si}"
	if input {
		indexReg = DI
		indexConstraint = "{di}"
	}
	index, err := c.loadReg(indexReg)
	if err != nil {
		return err
	}
	port, err := c.evalIntSized(Operand{Kind: OpReg, Reg: DX}, I16)
	if err != nil {
		return err
	}
	wordType := I64
	if c.goarch == "386" {
		wordType = I32
		index = c.truncI64(index, I32)
	}
	clobbers := "~{memory},~{dirflag},~{fpsr},~{flags}"
	if prefix == "" {
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(i16 %s, %s %s)\n", call, wordType, asm, "="+indexConstraint+",{dx},0,"+clobbers, port, wordType, index)
		return c.storeRegSized(indexReg, wordType, "%"+call)
	}

	count, err := c.loadReg(CX)
	if err != nil {
		return err
	}
	if c.goarch == "386" {
		count = c.truncI64(count, I32)
	}
	call := c.newTmp()
	resultType := fmt.Sprintf("{ %s, %s }", wordType, wordType)
	asmPrefix := "rep"
	if prefix == "REPN" {
		asmPrefix = "repne"
	}
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(i16 %s, %s %s, %s %s)\n", call, resultType, asmPrefix+"; "+asm, "="+indexConstraint+",={cx},{dx},0,1,"+clobbers, port, wordType, index, wordType, count)
	nextIndex := c.newTmp()
	nextCount := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 0\n", nextIndex, resultType, call)
	fmt.Fprintf(c.b, "  %%%s = extractvalue %s %%%s, 1\n", nextCount, resultType, call)
	if err := c.storeRegSized(indexReg, wordType, "%"+nextIndex); err != nil {
		return err
	}
	return c.storeRegSized(CX, wordType, "%"+nextCount)
}
