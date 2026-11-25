package x86

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
)

func (c *amd64Ctx) lowerString(op asm.Op, ins asm.Instr) (ok bool, terminated bool, err error) {
	if c.goarch != "386" {
		return false, false, nil
	}
	switch op {
	case "MOVSB", "MOVSL", "STOSL", "SCASB":
	default:
		return false, false, nil
	}

	prefix := c.repeatPrefix
	c.repeatPrefix = ""
	if len(ins.Args) != 0 {
		return true, false, fmt.Errorf("386 %s takes no operands: %q", op, ins.Raw)
	}
	repeated := prefix != ""
	if prefix == "REPN" && op != "SCASB" {
		return true, false, fmt.Errorf("386 REPN is unsupported for %s", op)
	}
	if prefix == "REP" && op == "SCASB" {
		return true, false, fmt.Errorf("386 REP SCASB is not yet supported")
	}

	count := "1"
	if repeated {
		cx32, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: asm.CX}, asm.I32)
		if err != nil {
			return true, false, err
		}
		wide := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i32 %s to i64\n", wide, cx32)
		count = "%" + wide
	}
	direction := c.loadDirectionFlag()

	switch op {
	case "MOVSB", "MOVSL":
		width := 1
		helper := "__plan9asm_movsb"
		if op == "MOVSL" {
			width = 4
			helper = "__plan9asm_movsl"
		}
		si, err := c.loadReg(asm.SI)
		if err != nil {
			return true, false, err
		}
		di, err := c.loadReg(asm.DI)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  call void @%s(i64 %s, i64 %s, i64 %s, i1 %s)\n", helper, di, si, count, direction)
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i64 %s, %d\n", bytes, count, width)
		if err := c.storeStringIndex(asm.SI, si, "%"+bytes, direction); err != nil {
			return true, false, err
		}
		if err := c.storeStringIndex(asm.DI, di, "%"+bytes, direction); err != nil {
			return true, false, err
		}

	case "STOSL":
		di, err := c.loadReg(asm.DI)
		if err != nil {
			return true, false, err
		}
		ax, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: asm.AX}, asm.I32)
		if err != nil {
			return true, false, err
		}
		fmt.Fprintf(c.b, "  call void @__plan9asm_rep_stosl(i64 %s, i32 %s, i64 %s, i1 %s)\n", di, ax, count, direction)
		bytes := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = mul i64 %s, 4\n", bytes, count)
		if err := c.storeStringIndex(asm.DI, di, "%"+bytes, direction); err != nil {
			return true, false, err
		}

	case "SCASB":
		di, err := c.loadReg(asm.DI)
		if err != nil {
			return true, false, err
		}
		needle, err := c.evalIntSized(asm.Operand{Kind: asm.OpReg, Reg: asm.AL}, asm.I8)
		if err != nil {
			return true, false, err
		}
		call := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call { i64, i64, i1 } @__plan9asm_repne_scasb(i64 %s, i8 %s, i64 %s, i1 %s)\n", call, di, needle, count, direction)
		next := c.newTmp()
		remaining := c.newTmp()
		equal := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractvalue { i64, i64, i1 } %%%s, 0\n", next, call)
		fmt.Fprintf(c.b, "  %%%s = extractvalue { i64, i64, i1 } %%%s, 1\n", remaining, call)
		fmt.Fprintf(c.b, "  %%%s = extractvalue { i64, i64, i1 } %%%s, 2\n", equal, call)
		if err := c.storeReg(asm.DI, "%"+next); err != nil {
			return true, false, err
		}
		zf := "%" + equal
		if repeated {
			oldZF := c.loadFlag(c.flagsZSlot)
			executed := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp ne i64 %s, 0\n", executed, count)
			preserved := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i1 %%%s, i1 %s\n", preserved, executed, equal, oldZF)
			zf = "%" + preserved
		}
		fmt.Fprintf(c.b, "  store i1 %s, ptr %s\n", zf, c.flagsZSlot)
		if repeated {
			if err := c.storeRegSized(asm.CX, asm.I32, c.truncI64("%"+remaining, asm.I32)); err != nil {
				return true, false, err
			}
		}
	}

	if repeated && op != "SCASB" {
		if err := c.storeRegSized(asm.CX, asm.I32, "0"); err != nil {
			return true, false, err
		}
	}
	return true, false, nil
}

func (c *amd64Ctx) loadDirectionFlag() string {
	t := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i1, ptr %s\n", t, c.directionSlot)
	return "%" + t
}

func (c *amd64Ctx) storeStringIndex(reg asm.Reg, old, delta, backward string) error {
	forward := c.newTmp()
	reverse := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = add i64 %s, %s\n", forward, old, delta)
	fmt.Fprintf(c.b, "  %%%s = sub i64 %s, %s\n", reverse, old, delta)
	next := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select i1 %s, i64 %%%s, i64 %%%s\n", next, backward, reverse, forward)
	return c.storeReg(reg, "%"+next)
}
