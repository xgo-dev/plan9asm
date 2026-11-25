package native

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strconv"
	"strings"
)

type nativeAMD64 struct{ *nativeEmitter }

func nativeAMD64Reg(o asm.Operand, bits int) (string, error) {
	if o.Kind != asm.OpReg {
		return "", fmt.Errorf("expected amd64 register")
	}
	names := map[asm.Reg][2]string{asm.AX: {"eax", "rax"}, asm.BX: {"ebx", "rbx"}, asm.CX: {"ecx", "rcx"}, asm.DX: {"edx", "rdx"}, asm.SI: {"esi", "rsi"}, asm.DI: {"edi", "rdi"}, asm.SP: {"esp", "rsp"}, asm.BP: {"ebp", "rbp"}}
	if n, ok := names[o.Reg]; ok {
		if bits == 32 {
			return "%" + n[0], nil
		}
		return "%" + n[1], nil
	}
	name := string(o.Reg)
	if strings.HasPrefix(name, "R") {
		n, err := strconv.Atoi(name[1:])
		if err == nil && n >= 8 && n <= 15 {
			suffix := ""
			if bits == 32 {
				suffix = "d"
			}
			return fmt.Sprintf("%%r%d%s", n, suffix), nil
		}
	}
	return "", fmt.Errorf("unsupported amd64 register %s", name)
}

func nativeAMD64Operand(o asm.Operand, bits int) (string, error) {
	switch o.Kind {
	case asm.OpReg:
		return nativeAMD64Reg(o, bits)
	case asm.OpImm:
		if o.ImmRaw != "" {
			return "", fmt.Errorf("unresolved native immediate")
		}
		return fmt.Sprintf("$%d", o.Imm), nil
	case asm.OpMem:
		m := o.Mem
		if m.Sym != "" || m.OffRaw != "" || m.Index != "" || m.Segment != "" || m.Off < -1<<31 || m.Off > 1<<31-1 {
			break
		}
		base, err := nativeAMD64Reg(asm.Operand{Kind: asm.OpReg, Reg: m.Base}, 64)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d(%s)", m.Off, base), nil
	}
	return "", fmt.Errorf("unsupported amd64 operand %s", o.String())
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
		return nil
	case "LABEL":
		fmt.Fprintf(out, "%s:\n", e.labels[a[0].Sym])
		return nil
	case "RET":
		if len(a) != 0 {
			return bad()
		}
		emit("ret")
		return nil
	case "CALL", "JMP":
		if len(a) != 1 {
			return bad()
		}
		dst, err := e.branch(a[0], true)
		if err != nil {
			return err
		}
		// ELF interposable function references use PLT relocations; local TEXT does not.
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
		inst := map[string]string{"JEQ": "je", "JNE": "jne", "JLT": "jl", "JLE": "jle", "JGT": "jg", "JGE": "jge", "JCS": "jb", "JCC": "jae", "JHI": "ja", "JLS": "jbe", "JMI": "js", "JPL": "jns", "JOS": "jo", "JOC": "jno"}[op]
		emit(inst, dst)
		return nil
	}
	if len(a) != 2 {
		return bad()
	}
	bits := 64
	if strings.HasSuffix(op, "L") {
		bits = 32
	}
	allowed := map[string]bool{"MOVQ": true, "MOVL": true, "LEAQ": true, "ADDQ": true, "ADDL": true, "SUBQ": true, "SUBL": true, "XORQ": true, "XORL": true, "ANDQ": true, "ANDL": true, "ORQ": true, "ORL": true, "CMPQ": true, "CMPL": true, "TESTQ": true, "TESTL": true, "SHLQ": true, "SHLL": true, "SHRQ": true, "SHRL": true, "SARQ": true, "SARL": true}
	if !allowed[op] {
		return bad()
	}
	// MOVQ between XMM and integer registers is a bit transfer, not conversion.
	if op == "MOVQ" {
		x0, ok0 := nativeAMD64XMM(a[0])
		x1, ok1 := nativeAMD64XMM(a[1])
		if ok0 || ok1 {
			if ok0 && ok1 {
				return bad()
			}
			if ok0 {
				r, err := nativeAMD64Operand(a[1], 64)
				if err != nil || a[1].Kind == asm.OpImm {
					return bad()
				}
				emit("movq", x0, r)
			} else {
				r, err := nativeAMD64Operand(a[0], 64)
				if err != nil || a[0].Kind == asm.OpImm {
					return bad()
				}
				emit("movq", r, x1)
			}
			return nil
		}
	}
	// Go CMP places the minuend first, unlike AT&T syntax.
	if op == "CMPQ" || op == "CMPL" {
		a = []asm.Operand{a[1], a[0]}
	}
	if a[1].Kind == asm.OpImm || (a[0].Kind == asm.OpMem && a[1].Kind == asm.OpMem) {
		return bad()
	}
	if op == "LEAQ" && (a[0].Kind != asm.OpMem || a[1].Kind != asm.OpReg) {
		return bad()
	}
	shift := strings.HasPrefix(op, "SHL") || strings.HasPrefix(op, "SHR") || strings.HasPrefix(op, "SAR")
	if shift && (a[0].Kind != asm.OpImm || a[0].Imm < 0 || a[0].Imm >= int64(bits)) {
		return bad()
	}
	if a[0].Kind == asm.OpImm && !shift {
		v := a[0].Imm
		if bits == 32 {
			if v < -1<<31 || v > 1<<32-1 {
				return bad()
			}
		} else if !(op == "MOVQ" && a[1].Kind == asm.OpReg) && (v < -1<<31 || v > 1<<31-1) {
			return bad()
		}
	}
	src, err := nativeAMD64Operand(a[0], bits)
	if err != nil {
		return err
	}
	dst, err := nativeAMD64Operand(a[1], bits)
	if err != nil {
		return err
	}
	emit(strings.ToLower(op), src, dst)
	return nil
}
