package native

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

type nativeAMD64 struct {
	*nativeEmitter
	frame nativeFramePlan
}

func nativeAMD64Reg(o asm.Operand, bits int) (string, error) {
	if o.Kind != asm.OpReg {
		return "", fmt.Errorf("expected amd64 register")
	}
	if bits == 8 {
		switch o.Reg {
		case asm.AH, asm.CH, asm.DH, asm.BH:
			return "%" + strings.ToLower(string(o.Reg)), nil
		}
	}
	reg := o.Reg
	switch reg {
	case asm.AL, asm.AH:
		reg = asm.AX
	case asm.BL, asm.BH:
		reg = asm.BX
	case asm.CL, asm.CH:
		reg = asm.CX
	case asm.DL, asm.DH:
		reg = asm.DX
	}
	names := map[asm.Reg][4]string{
		asm.AX: {"al", "ax", "eax", "rax"},
		asm.BX: {"bl", "bx", "ebx", "rbx"},
		asm.CX: {"cl", "cx", "ecx", "rcx"},
		asm.DX: {"dl", "dx", "edx", "rdx"},
		asm.SI: {"sil", "si", "esi", "rsi"},
		asm.DI: {"dil", "di", "edi", "rdi"},
		asm.SP: {"spl", "sp", "esp", "rsp"},
		asm.BP: {"bpl", "bp", "ebp", "rbp"},
	}
	width := map[int]int{8: 0, 16: 1, 32: 2, 64: 3}[bits]
	if n, ok := names[reg]; ok {
		return "%" + n[width], nil
	}
	name := string(reg)
	if strings.HasPrefix(name, "R") {
		n, err := strconv.Atoi(name[1:])
		if err == nil && n >= 8 && n <= 15 {
			suffix := []string{"b", "w", "d", ""}[width]
			return fmt.Sprintf("%%r%d%s", n, suffix), nil
		}
	}
	return "", fmt.Errorf("unsupported amd64 register %s", name)
}

func nativeAMD64XMM(o asm.Operand) (string, bool) {
	if o.Kind != asm.OpReg || !strings.HasPrefix(string(o.Reg), "X") {
		return "", false
	}
	n, err := strconv.Atoi(string(o.Reg)[1:])
	if err != nil || n < 0 || n > 15 {
		return "", false
	}
	return fmt.Sprintf("%%xmm%d", n), true
}

func (e *nativeAMD64) operand(o asm.Operand, bits int) (string, error) {
	switch o.Kind {
	case asm.OpReg:
		if xmm, ok := nativeAMD64XMM(o); ok {
			return xmm, nil
		}
		return nativeAMD64Reg(o, bits)
	case asm.OpImm:
		if o.ImmRaw != "" {
			return "", fmt.Errorf("unresolved native immediate")
		}
		return fmt.Sprintf("$%d", o.Imm), nil
	case asm.OpSym:
		s := o.Sym
		if strings.HasPrefix(s, "$") {
			s = strings.TrimPrefix(s, "$")
		}
		if strings.HasSuffix(s, "(SB)") {
			base, off, ok := asm.ParseSBRef(s)
			if !ok {
				return "", fmt.Errorf("unsupported native symbol %s", o.Sym)
			}
			target, err := e.symbol(base+"(SB)", true)
			if err != nil {
				return "", err
			}
			if off != 0 {
				target += fmt.Sprintf("%+d", off)
			}
			return target + "(%rip)", nil
		}
	case asm.OpMem:
		m := o.Mem
		if m.OffRaw != "" || m.Segment != "" || m.Off < -1<<31 || m.Off > 1<<31-1 {
			break
		}
		if m.Sym != "" {
			if m.Base != "" || m.Index != "" {
				break
			}
			base, off, ok := asm.ParseSBRef(m.Sym)
			if !ok {
				break
			}
			target, err := e.symbol(base+"(SB)", true)
			if err != nil {
				return "", err
			}
			if off += m.Off; off != 0 {
				target += fmt.Sprintf("%+d", off)
			}
			return target + "(%rip)", nil
		}
		base := ""
		if m.Base != "" {
			var err error
			base, err = nativeAMD64Reg(asm.Operand{Kind: asm.OpReg, Reg: m.Base}, 64)
			if err != nil {
				return "", err
			}
		}
		if m.Index == "" {
			if base == "" {
				return fmt.Sprintf("%d", m.Off), nil
			}
			return fmt.Sprintf("%d(%s)", m.Off, base), nil
		}
		index, err := nativeAMD64Reg(asm.Operand{Kind: asm.OpReg, Reg: m.Index}, 64)
		if err != nil {
			return "", err
		}
		scale := m.Scale
		if scale == 0 {
			scale = 1
		}
		return fmt.Sprintf("%d(%s,%s,%d)", m.Off, base, index, scale), nil
	}
	return "", fmt.Errorf("unsupported amd64 operand %s", o.String())
}

func (e *nativeAMD64) instruction(out *strings.Builder, ins asm.Instr) error {
	a := ins.Args
	op := string(ins.Op)
	bad := func() error { return fmt.Errorf("unsupported native amd64 operand form for %s", op) }
	emit := func(op string, args ...string) { fmt.Fprintf(out, "\t%s %s\n", op, strings.Join(args, ", ")) }
	if ins.Op != asm.OpTEXT && ins.Op != asm.OpLABEL {
		_, rest := asm.SplitOpcode(ins.Raw)
		parts := asm.SplitTopLevelCSV(rest)
		if len(parts) != len(a) {
			return bad()
		}
		for i, o := range a {
			if o.Kind == asm.OpImm {
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
	case "ADJSP":
		if len(a) != 1 || a[0].Kind != asm.OpImm {
			return bad()
		}
		if a[0].Imm > 0 {
			fmt.Fprintf(out, "\tsubq $%d, %%rsp\n", a[0].Imm)
		} else if a[0].Imm < 0 {
			fmt.Fprintf(out, "\taddq $%d, %%rsp\n", -a[0].Imm)
		}
		return nil
	case "PUSHQ", "POPQ":
		if len(a) != 1 {
			return bad()
		}
		arg, err := e.operand(a[0], 64)
		if err != nil {
			return err
		}
		emit(strings.ToLower(op), arg)
		return nil
	case "CALL", "JMP":
		if len(a) != 1 {
			return bad()
		}
		if a[0].Kind == asm.OpReg || a[0].Kind == asm.OpMem {
			if a[0].Kind == asm.OpReg {
				if _, isX := nativeAMD64XMM(a[0]); isX {
					return bad()
				}
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
		if e.target.GOOS == "linux" && a[0].Kind == asm.OpSym {
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
		inst := map[string]string{
			"JEQ": "je", "JNE": "jne", "JLT": "jl", "JLE": "jle", "JGT": "jg", "JGE": "jge",
			"JCS": "jb", "JCC": "jae", "JHI": "ja", "JLS": "jbe", "JMI": "js", "JPL": "jns",
			"JOS": "jo", "JOC": "jno",
		}[op]
		emit(inst, dst)
		return nil
	case "DIVQ", "IDIVQ", "DIVL", "IDIVL", "INCQ", "DECQ", "INCL", "DECL", "NEGQ", "NEGL", "NOTQ", "NOTL":
		if len(a) != 1 {
			return bad()
		}
		bits := 64
		if strings.HasSuffix(op, "L") {
			bits = 32
		}
		arg, err := e.operand(a[0], bits)
		if err != nil {
			return err
		}
		emit(strings.ToLower(op), arg)
		return nil
	case "CQO", "CDQ", "NOP", "UD2":
		if len(a) != 0 {
			return bad()
		}
		fmt.Fprintf(out, "\t%s\n", strings.ToLower(op))
		return nil
	}
	if len(a) != 2 {
		return bad()
	}

	// Scalar FP / packed SIMD moves used by purego & native stubs.
	switch op {
	case "MOVSD", "MOVSS", "MOVUPS", "MOVAPS", "MOVUPD", "MOVAPD", "MOVDQU", "MOVDQA", "MOVOU", "MOVOA", "MOVO":
		att := strings.ToLower(op)
		if op == "MOVOU" || op == "MOVO" {
			att = "movdqu"
		} else if op == "MOVOA" {
			att = "movdqa"
		}
		src, err := e.operand(a[0], 64)
		if err != nil {
			return err
		}
		dst, err := e.operand(a[1], 64)
		if err != nil {
			return err
		}
		emit(att, src, dst)
		return nil
	case "MOVBLZX", "MOVWLZX", "MOVBQZX", "MOVWQZX", "MOVBLSX", "MOVWLSX", "MOVBQSX", "MOVWQSX", "MOVLQSX":
		attMap := map[string][3]string{
			"MOVBLZX": {"movzbl", "8", "32"}, "MOVWLZX": {"movzwl", "16", "32"},
			"MOVBQZX": {"movzbq", "8", "64"}, "MOVWQZX": {"movzwq", "16", "64"},
			"MOVBLSX": {"movsbl", "8", "32"}, "MOVWLSX": {"movswl", "16", "32"},
			"MOVBQSX": {"movsbq", "8", "64"}, "MOVWQSX": {"movswq", "16", "64"},
			"MOVLQSX": {"movslq", "32", "64"},
		}
		info := attMap[op]
		srcBits, _ := strconv.Atoi(info[1])
		dstBits, _ := strconv.Atoi(info[2])
		src, err := e.operand(a[0], srcBits)
		if err != nil {
			return err
		}
		dst, err := e.operand(a[1], dstBits)
		if err != nil {
			return err
		}
		emit(info[0], src, dst)
		return nil
	}

	bits := 64
	if strings.HasSuffix(op, "B") {
		bits = 8
	} else if strings.HasSuffix(op, "W") {
		bits = 16
	} else if strings.HasSuffix(op, "L") {
		bits = 32
	}
	allowed := map[string]bool{
		"MOVQ": true, "MOVL": true, "MOVW": true, "MOVB": true, "LEAQ": true, "LEAL": true,
		"ADDQ": true, "ADDL": true, "SUBQ": true, "SUBL": true,
		"XORQ": true, "XORL": true, "ANDQ": true, "ANDL": true, "ORQ": true, "ORL": true,
		"CMPQ": true, "CMPL": true, "CMPW": true, "CMPB": true,
		"TESTQ": true, "TESTL": true, "TESTW": true, "TESTB": true,
		"SHLQ": true, "SHLL": true, "SHRQ": true, "SHRL": true, "SARQ": true, "SARL": true,
	}
	if !allowed[op] {
		return bad()
	}
	// MOVQ $sym(SB), dst -> leaq sym(%rip), dst
	if (op == "MOVQ" || op == "MOVL") && a[0].Kind == asm.OpSym && strings.HasPrefix(a[0].Sym, "$") {
		src, err := e.operand(a[0], bits)
		if err != nil {
			return err
		}
		dst, err := e.operand(a[1], bits)
		if err != nil {
			return err
		}
		emit("lea"+strings.ToLower(op[len(op)-1:]), src, dst)
		return nil
	}
	// MOVQ/MOVL between XMM and integer registers/memory.
	if op == "MOVQ" || op == "MOVL" {
		x0, ok0 := nativeAMD64XMM(a[0])
		x1, ok1 := nativeAMD64XMM(a[1])
		if ok0 || ok1 {
			if ok0 && ok1 {
				return bad()
			}
			inst := "movq"
			if op == "MOVL" {
				inst = "movd"
			}
			if ok0 {
				r, err := e.operand(a[1], bits)
				if err != nil || a[1].Kind == asm.OpImm {
					return bad()
				}
				emit(inst, x0, r)
			} else {
				r, err := e.operand(a[0], bits)
				if err != nil || a[0].Kind == asm.OpImm {
					return bad()
				}
				emit(inst, r, x1)
			}
			return nil
		}
	}
	// Go CMP places the minuend first, unlike AT&T syntax.
	if strings.HasPrefix(op, "CMP") {
		a = []asm.Operand{a[1], a[0]}
	}
	if a[1].Kind == asm.OpImm || (a[0].Kind == asm.OpMem && a[1].Kind == asm.OpMem) {
		return bad()
	}
	if (op == "LEAQ" || op == "LEAL") && ((a[0].Kind != asm.OpMem && a[0].Kind != asm.OpSym) || a[1].Kind != asm.OpReg) {
		return bad()
	}
	shift := strings.HasPrefix(op, "SHL") || strings.HasPrefix(op, "SHR") || strings.HasPrefix(op, "SAR")
	if shift {
		if a[0].Kind == asm.OpReg && (a[0].Reg == asm.CX || a[0].Reg == asm.CL) {
			dst, err := e.operand(a[1], bits)
			if err != nil {
				return err
			}
			emit(strings.ToLower(op), "%cl", dst)
			return nil
		}
		if a[0].Kind != asm.OpImm || a[0].Imm < 0 || a[0].Imm >= int64(bits) {
			return bad()
		}
	}
	if a[0].Kind == asm.OpImm && !shift {
		v := a[0].Imm
		if bits == 32 {
			if v < -1<<31 || v > 1<<32-1 {
				return bad()
			}
		} else if bits == 64 && !(op == "MOVQ" && a[1].Kind == asm.OpReg) && (v < -1<<31 || v > 1<<31-1) {
			return bad()
		}
	}
	src, err := e.operand(a[0], bits)
	if err != nil {
		return err
	}
	dst, err := e.operand(a[1], bits)
	if err != nil {
		return err
	}
	emit(strings.ToLower(op), src, dst)
	return nil
}
