package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

type nativeAMD64 struct {
	*nativeEmitter
	frame nativeFramePlan
}

func nativeAMD64Reg(o Operand, bits int) (string, error) {
	if o.Kind != OpReg {
		return "", fmt.Errorf("expected amd64 register")
	}
	if bits == 8 {
		switch o.Reg {
		case AH, CH, DH, BH:
			return "%" + strings.ToLower(string(o.Reg)), nil
		}
	}
	if base, _, ok := amd64ByteAlias(o.Reg); ok {
		o.Reg = base
	}
	names := map[Reg][4]string{
		AX: {"al", "ax", "eax", "rax"}, BX: {"bl", "bx", "ebx", "rbx"},
		CX: {"cl", "cx", "ecx", "rcx"}, DX: {"dl", "dx", "edx", "rdx"},
		SI: {"sil", "si", "esi", "rsi"}, DI: {"dil", "di", "edi", "rdi"},
		SP: {"spl", "sp", "esp", "rsp"}, BP: {"bpl", "bp", "ebp", "rbp"},
	}
	width := map[int]int{8: 0, 16: 1, 32: 2, 64: 3}[bits]
	if n, ok := names[o.Reg]; ok {
		return "%" + n[width], nil
	}
	name := string(o.Reg)
	if strings.HasPrefix(name, "R") {
		n, err := strconv.Atoi(name[1:])
		if err == nil && n >= 8 && n <= 15 {
			suffix := []string{"b", "w", "d", ""}[width]
			return fmt.Sprintf("%%r%d%s", n, suffix), nil
		}
	}
	return "", fmt.Errorf("unsupported amd64 register %s", name)
}

func (e *nativeAMD64) operand(o Operand, bits int) (string, error) {
	switch o.Kind {
	case OpReg:
		if xmm, ok := nativeAMD64XMM(o); ok {
			return xmm, nil
		}
		return nativeAMD64Reg(o, bits)
	case OpImm:
		if o.ImmRaw == "" && !o.ImmIsFloat {
			return fmt.Sprintf("$%d", o.Imm), nil
		}
	}
	if !x86ScalarCompareMemoryValid(o, "amd64") {
		return "", fmt.Errorf("unsupported native address %s", o.String())
	}
	if base, m, ok := x86ScalarCompareSBAddress(o, "amd64"); ok {
		_, off, _ := parseSBRef(m.Sym)
		target, err := e.symbol(base+"(SB)", true)
		if err != nil {
			return "", err
		}
		if off += m.Off; off != 0 {
			target += fmt.Sprintf("%+d", off)
		}
		return target + "(%rip)", nil
	}
	if o.Kind == OpSym {
		if address, err := parseInt(o.Sym); err == nil {
			return fmt.Sprintf("%d", address), nil
		}
	}
	if o.Kind != OpMem || o.Mem.Segment != "" {
		return "", fmt.Errorf("native memory needs physical backing: %s", o.String())
	}
	base := ""
	if o.Mem.Base != "" {
		var err error
		base, err = nativeAMD64Reg(Operand{Kind: OpReg, Reg: o.Mem.Base}, 64)
		if err != nil {
			return "", err
		}
	}
	if o.Mem.Index == "" {
		if base == "" {
			return fmt.Sprintf("%d", o.Mem.Off), nil
		}
		return fmt.Sprintf("%d(%s)", o.Mem.Off, base), nil
	}
	index, err := nativeAMD64Reg(Operand{Kind: OpReg, Reg: o.Mem.Index}, 64)
	return fmt.Sprintf("%d(%s,%s,%d)", o.Mem.Off, base, index, o.Mem.Scale), err
}

func nativeAMD64XMM(o Operand) (string, bool) {
	if o.Kind != OpReg || !strings.HasPrefix(string(o.Reg), "X") {
		return "", false
	}
	n, err := strconv.Atoi(string(o.Reg)[1:])
	if err != nil || n < 0 || n > 15 {
		return "", false
	}
	return fmt.Sprintf("%%xmm%d", n), true
}

func (e *nativeAMD64) instruction(out *strings.Builder, ins Instr) error {
	a := ins.Args
	op := string(ins.Op)
	bad := func() error { return fmt.Errorf("unsupported native amd64 operand form for %s", op) }
	emit := func(op string, args ...string) { fmt.Fprintf(out, "\t%s %s\n", op, strings.Join(args, ", ")) }
	if ins.Op != OpTEXT && ins.Op != OpLABEL {
		_, rest := splitOpcode(ins.Raw)
		parts := splitTopLevelCSV(rest)
		if len(parts) != len(a) {
			return bad()
		}
		for i, o := range a {
			if o.Kind == OpImm {
				if _, ok := nativeInteger(strings.TrimSpace(parts[i])); !ok {
					return bad()
				}
			}
		}
	}
	switch op {
	case "TEXT":
		e.frame.prologue(out)
		return nil
	case "LABEL":
		fmt.Fprintf(out, "%s:\n", e.labels[a[0].Sym])
		return nil
	case "RET":
		if len(a) != 0 {
			return bad()
		}
		e.frame.epilogue(out)
		emit("ret")
		return nil
	case "CALL", "JMP":
		if len(a) != 1 {
			return bad()
		}
		if a[0].Kind == OpReg || a[0].Kind == OpMem {
			if a[0].Kind == OpReg && !isX86YrlRegisterForArch(a[0].Reg, "amd64") {
				return bad()
			}
			dst, err := e.operand(a[0], 64)
			if err != nil {
				return err
			}
			emit(strings.ToLower(op), "*"+dst)
			return nil
		}
		dst, err := e.branch(a[0], true)
		if err != nil {
			return err
		}
		// ELF interposable function references use PLT relocations; local TEXT does not.
		if e.target.GOOS == "linux" && a[0].Kind == OpSym {
			name := strings.TrimSuffix(a[0].Sym, "(SB)")
			if _, ok := e.imports[name]; ok {
				dst += "@PLT"
			}
		}
		emit(strings.ToLower(op), dst)
		return nil
	case "JEQ", "JNE", "JLT", "JLE", "JGT", "JGE", "JCS", "JCC", "JHI", "JLS", "JMI", "JPL", "JOS", "JOC":
		if len(a) != 1 {
			return bad()
		}
		dst, err := e.branch(a[0], false)
		if err != nil {
			return err
		}
		inst := map[string]string{"JEQ": "je", "JNE": "jne", "JLT": "jl", "JLE": "jle", "JGT": "jg", "JGE": "jge", "JCS": "jb", "JCC": "jae", "JHI": "ja", "JLS": "jbe", "JMI": "js", "JPL": "jns", "JOS": "jo", "JOC": "jno"}[op]
		emit(inst, dst)
		return nil
	}
	return e.typedInstruction(out, ins)
}
