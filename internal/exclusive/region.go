// Package exclusive keeps an ARM load-exclusive/store-exclusive attempt in one
// machine instruction sequence. LLVM may spill virtual registers on either side
// of an inline asm, including when compiling an unoptimized module.
package exclusive

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

const Opcode asm.Op = "\x00exclusive"
const ExitOpcode asm.Op = "\x00exclusive.exit"

type Region struct {
	// Apple A32 reserves R7 as its frame pointer. Move the source R6:R7
	// pair together to R10:R11, including the implicit partner of LDREXD.
	reserveR7    bool
	wide         bool
	instructions []string
	regs         map[int]bool
	Flags        bool
	// ExitPreservesFlags is set when a register test can bypass the first NZCV write.
	ExitPreservesFlags bool
	symbol             string
	exit               asm.Instr
}

func isLoad(op string) bool {
	switch op {
	case "LDREX", "LDREXB", "LDREXD", "LDXR", "LDXRB", "LDXRW", "LDXRH", "LDAXR", "LDAXRB", "LDAXRH", "LDAXRW", "LDXP", "LDXPW", "LDAXP", "LDAXPW":
		return true
	}
	return false
}
func isStore(op string) bool {
	switch op {
	case "STREX", "STREXB", "STREXD", "STXR", "STXRB", "STXRW", "STXRH", "STLXR", "STLXRB", "STLXRH", "STLXRW", "STXP", "STXPW", "STLXP", "STLXPW":
		return true
	}
	return false
}

// Rewrite retains instruction positions, including the source branch to a CAS
// mismatch exit. A branch into the middle of a reservation cannot be moved.
func Rewrite(fn asm.Func, wide, reserveR7 bool) (asm.Func, []Region, error) {
	hasStore, hasLoad := false, false
	for _, ins := range fn.Instrs {
		if ins.Op == Opcode || ins.Op == ExitOpcode {
			return fn, nil, fmt.Errorf("invalid source opcode")
		}
		op, _, _ := strings.Cut(string(ins.Op), ".")
		hasStore = hasStore || isStore(op)
		hasLoad = hasLoad || isLoad(op)
	}
	if !hasStore || !hasLoad {
		return fn, nil, nil
	}
	src := fn.Instrs
	fn.Instrs = append([]asm.Instr(nil), src...)
	var regions []Region
	entries := map[int][]int{}
	pc := 0
	for _, ins := range src {
		if ins.Op == asm.OpLABEL {
			continue
		}
		for _, a := range ins.Args {
			if a.Kind == asm.OpMem && a.Mem.Base == asm.PC {
				dest := pc + int(a.Mem.Off)
				entries[dest] = append(entries[dest], pc)
			}
		}
		pc++
	}
	pc = 0
	for i, ins := range src {
		if ins.Op == asm.OpLABEL {
			continue
		}
		startPC := pc
		pc++
		op, _, _ := strings.Cut(string(ins.Op), ".")
		if !isLoad(op) {
			continue
		}
		r := Region{wide: wide, reserveR7: reserveR7, regs: map[int]bool{}}
		ok := r.add(ins)
		for j := i + 1; j < len(src); j++ {
			next := src[j]
			n := string(next.Op)
			base, _, _ := strings.Cut(n, ".")
			// A second load replaces the reservation. CLREX and an explicit
			// store-release handoff delimit source regions without progress guarantees.
			if isLoad(base) || n == "CLREX" || n == "STLR" || n == "RET" || n == "WORD" && len(next.Args) == 1 && next.Args[0].Imm == 0xf57ff01f {
				break
			}
			if next.Op == asm.OpLABEL {
				ok = false
			}
			if ok {
				if (n == "BEQ" || n == "BLT") && len(next.Args) == 1 && next.Args[0].Kind == asm.OpMem && next.Args[0].Mem == (asm.MemRef{Base: asm.PC, Off: 2}) && j+1 < len(src) && src[j+1].Op == "DMB" && r.Flags {
					r.instructions = append(r.instructions, strings.ToLower(n)+" 3f")
					ok = r.add(src[j+1])
					r.instructions = append(r.instructions, "3:")
					j++
					continue
				}
				ok = r.add(next)
			}
			if !isStore(base) {
				continue
			}
			for dest := startPC + 1; dest <= startPC+j-i; dest++ {
				for _, src := range entries[dest] {
					if src < startPC || src > startPC+j-i {
						ok = false
					}
				}
			}
			if !ok {
				break
			}
			arg := asm.Operand{Kind: asm.OpImm, Imm: int64(len(regions))}
			fn.Instrs[i] = asm.Instr{Op: Opcode, Args: []asm.Operand{arg}, Raw: ins.Raw}
			for k := i + 1; k <= j; k++ {
				fn.Instrs[k] = asm.Instr{Op: "NOP"}
			}
			if r.exit.Op != "" {
				fn.Instrs[j] = r.exit
				if wide {
					fn.Instrs[j].Op = ExitOpcode
				}
			}
			regions = append(regions, r)
			break
		}
	}
	return fn, regions, validateUnbundled(fn, regions)
}

func (r *Region) reg(v asm.Operand) (int, bool) {
	if v.Kind != asm.OpReg {
		return 0, false
	}
	s := string(v.Reg)
	if !strings.HasPrefix(s, "R") {
		return 0, false
	}
	n, e := strconv.Atoi(s[1:])
	// Keep fixed constraints away from frame/platform registers.
	if e != nil || n < 0 || (!r.wide && n > 8) || (r.wide && n > 15) {
		return 0, false
	}
	r.regs[n] = true
	return n, true
}

// The Go assembler may select R11 as the scratch register for a byte load
// from a symbol. Use a virtual tied operand on hosts that reserve R11 as FP.
func (r *Region) guardReg(a asm.Operand) (string, bool) {
	if a.Kind == asm.OpReg && a.Reg == "R11" {
		r.regs[11] = true
		return "REG11", true
	}
	n, ok := r.reg(a)
	return r.name(n, false), ok
}

func (r *Region) add(ins asm.Instr) bool {
	op := string(ins.Op)
	a := ins.Args
	if isLoad(op) || isStore(op) {
		return r.access(op, a)
	}
	line := ""
	if r.wide && (op == "ADD.S" || op == "ADC") || !r.wide && (op == "ADDW" || op == "CMPW") {
		return false
	}
	switch op {
	case "DMB":
		if r.wide || len(a) != 1 {
			return false
		}
		switch strings.ToUpper(a[0].String()) {
		case "MB_ISHST":
			line = ".inst 0xf57ff05a"
		case "MB_ISH":
			line = ".inst 0xf57ff05b"
		default:
			return false
		}
	case "MOVB":
		if r.wide || len(a) != 2 || a[0].Kind != asm.OpSym || !strings.HasSuffix(a[0].Sym, "(SB)") || strings.HasPrefix(a[0].Sym, "$") || r.symbol != "" {
			return false
		}
		r.symbol = a[0].Sym
		dst, ok := r.guardReg(a[1])
		if !ok {
			return false
		}
		line = "ldrsb " + dst + ", [SYMPTR]"
	case "CBNZ", "CBNZW":
		if !r.wide || len(a) != 2 || a[1].Kind != asm.OpIdent || r.exit.Op != "" {
			return false
		}
		n, ok := r.reg(a[0])
		if !ok {
			return false
		}
		r.ExitPreservesFlags = !r.Flags
		r.exit = asm.Instr{Op: "BNE", Args: a[1:]}
		line = "cbnz " + r.name(n, op == "CBNZW") + ", 2f"
	case "BNE", "B.NE":
		if !r.Flags || len(a) != 1 || a[0].Kind != asm.OpIdent {
			return false
		}
		if r.exit.Op != "" && r.exit.Args[0].String() != a[0].String() {
			return false
		}
		r.exit = ins
		line = "bne 2f"
	case "CMP", "CMPW":
		if len(a) != 2 {
			return false
		}
		if !r.wide && a[0].Kind == asm.OpImm && a[0].ImmRaw == "" && a[0].Imm >= 0 && a[0].Imm <= 255 {
			dst, ok := r.guardReg(a[1])
			if !ok {
				return false
			}
			line = fmt.Sprintf("cmp %s, #%d", dst, a[0].Imm)
			r.Flags = true
			break
		}
		src, ok := r.reg(a[0])
		dst, ok2 := r.reg(a[1])
		if !ok || !ok2 {
			return false
		}
		line = fmt.Sprintf("cmp %s, %s", r.name(dst, op == "CMPW"), r.name(src, op == "CMPW"))
		r.Flags = true
	case "ADD", "ADDW", "ADD.S", "ADC", "AND", "ORR", "EOR", "BIC":
		if len(a) != 2 && len(a) != 3 {
			return false
		}
		if op == "ADC" && !r.Flags {
			return false
		}
		s, ok := r.reg(a[0])
		n, ok2 := r.reg(a[1])
		dst, ok3 := r.reg(a[len(a)-1])
		if !ok || !ok2 || !ok3 {
			return false
		}
		w := op == "ADDW"
		m := strings.ToLower(strings.TrimSuffix(op, "W"))
		if op == "ADD.S" {
			m = "adds"
			r.Flags = true
		}
		line = fmt.Sprintf("%s %s, %s, %s", m, r.name(dst, w), r.name(n, w), r.name(s, w))
	default:
		return false
	}
	r.instructions = append(r.instructions, line)
	return true
}

func (r *Region) physicalReg(n int) int {
	if r.reserveR7 && (n == 6 || n == 7) {
		return n + 4
	}
	return n
}

func (r *Region) name(n int, word bool) string {
	n = r.physicalReg(n)
	prefix := "r"
	if r.wide {
		prefix = "x"
		if word {
			prefix = "w"
		}
	}
	return prefix + strconv.Itoa(n)
}

func (r *Region) access(op string, a []asm.Operand) bool {
	if strings.Contains(op, "REX") == r.wide {
		return false
	}
	load := isLoad(op)
	mi, di := 0, 1
	if !load {
		mi, di = 1, 0
	}
	if load && len(a) != 2 || !load && len(a) != 3 {
		return false
	}
	mem := a[mi]
	if mem.Kind != asm.OpMem || mem.Mem != (asm.MemRef{Base: mem.Mem.Base}) {
		return false
	}
	addr, ok := r.reg(asm.Operand{Kind: asm.OpReg, Reg: mem.Mem.Base})
	if !ok {
		return false
	}
	var regs []int
	pair := strings.HasSuffix(strings.TrimSuffix(op, "W"), "P")
	if r.wide && pair {
		if a[di].Kind != asm.OpRegList || len(a[di].RegList) != 2 {
			return false
		}
		for _, reg := range a[di].RegList {
			n, ok := r.reg(asm.Operand{Kind: asm.OpReg, Reg: reg})
			if !ok {
				return false
			}
			regs = append(regs, n)
		}
		if load && regs[0] == regs[1] {
			return false
		}
	} else {
		n, ok := r.reg(a[di])
		if !ok {
			return false
		}
		regs = []int{n}
	}
	var st int
	if !load {
		st, ok = r.reg(a[2])
		if !ok || st == addr {
			return false
		}
		for _, n := range regs {
			if st == n {
				return false
			}
		}
	}
	if r.wide {
		word := strings.HasSuffix(op, "W") || strings.HasSuffix(op, "H") || strings.HasSuffix(op, "B")
		var args []string
		if !load {
			args = append(args, r.name(st, true))
		}
		for _, n := range regs {
			args = append(args, r.name(n, word))
		}
		args = append(args, "["+r.name(addr, false)+"]")
		r.instructions = append(r.instructions, strings.ToLower(strings.TrimSuffix(op, "W"))+" "+strings.Join(args, ", "))
	} else {
		var code uint32
		switch op {
		case "LDREX":
			code = 0xe1900f9f
		case "LDREXB":
			code = 0xe1d00f9f
		case "LDREXD":
			code = 0xe1b00f9f
		case "STREX":
			code = 0xe1800f90
		case "STREXB":
			code = 0xe1c00f90
		case "STREXD":
			code = 0xe1a00f90
		default:
			return false
		}
		n := regs[0]
		if strings.HasSuffix(op, "D") {
			if n%2 != 0 || n >= 8 || !load && st == n+1 {
				return false
			}
			r.regs[n+1] = true
		}
		addr, n, st = r.physicalReg(addr), r.physicalReg(n), r.physicalReg(st)
		code |= uint32(addr) << 16
		if load {
			code |= uint32(n) << 12
		} else {
			code |= uint32(st<<12 | n)
		}
		r.instructions = append(r.instructions, fmt.Sprintf(".inst %#x", code))
	}
	return true
}

func (r Region) Emit(b *strings.Builder, tmp func() string, load func(asm.Reg) (string, error), store func(asm.Reg, string) error, flags func(string), entryNZCV string, exit *string, symPtr func(string) (string, error)) error {
	ty := "i32"
	if r.wide {
		ty = "i64"
	}
	var order []int
	for n := range r.regs {
		order = append(order, n)
	}
	sort.Ints(order)
	var cons, args, fields []string
	for _, n := range order {
		constraint := "=&{" + r.name(n, false) + "}"
		if n == 11 && !r.wide {
			constraint = "=&r"
		}
		cons = append(cons, constraint)
		fields = append(fields, ty)
	}
	code := strings.Join(r.instructions, "\\0A\\09")
	for i, n := range order {
		if n == 11 && !r.wide {
			code = strings.ReplaceAll(code, "REG11", fmt.Sprintf("$%d", i))
		}
	}
	exitIndex := -1
	if r.exit.Op != "" {
		exitIndex = len(fields)
		code += fmt.Sprintf("\\0A\\09mov $%d, #0\\0A\\09b 4f\\0A2:\\0A\\09mov $%d, #1\\0A4:", exitIndex, exitIndex)
		cons = append(cons, "=&r")
		fields = append(fields, ty)
	}
	if r.Flags {
		sys := "cpsr"
		if r.wide {
			sys = "nzcv"
		}
		code += fmt.Sprintf("\\0A\\09mrs $%d, %s", len(fields), sys)
		cons = append(cons, "=&r")
		fields = append(fields, ty)
	}
	for i, n := range order {
		reg := asm.Reg(fmt.Sprintf("R%d", n))
		v, e := load(reg)
		if e != nil {
			return e
		}
		cons = append(cons, strconv.Itoa(i))
		args = append(args, ty+" "+v)
	}
	if entryNZCV != "" {
		// A register-tested exit can bypass the first compare in the region.
		// Seed NZCV from the translated state before the hardware reservation.
		code = fmt.Sprintf("msr nzcv, $%d\\0A\\09", len(cons)) + code
		cons = append(cons, "r")
		args = append(args, "i64 "+entryNZCV)
	}
	if r.symbol != "" {
		p, e := symPtr(r.symbol)
		if e != nil {
			return e
		}
		code = strings.ReplaceAll(code, "SYMPTR", fmt.Sprintf("$%d", len(cons)))
		cons = append(cons, "r")
		args = append(args, "ptr "+p)
	}
	cons = append(cons, "~{memory}")
	if r.Flags {
		cons = append(cons, "~{cc}")
	}
	rt := "{" + strings.Join(fields, ",") + "}"
	v := tmp()
	fmt.Fprintf(b, "  %%%s = call %s asm sideeffect \"%s\", %q(%s)\n", v, rt, code, strings.Join(cons, ","), strings.Join(args, ", "))
	for i := range fields {
		t := tmp()
		fmt.Fprintf(b, "  %%%s = extractvalue %s %%%s, %d\n", t, rt, v, i)
		if i == exitIndex {
			pred := tmp()
			fmt.Fprintf(b, "  %%%s = icmp ne %s %%%s, 0\n", pred, ty, t)
			*exit = "%" + pred
		} else if i >= len(order) {
			flags("%" + t)
		} else if err := store(asm.Reg(fmt.Sprintf("R%d", order[i])), "%"+t); err != nil {
			return err
		}
	}
	return nil
}
