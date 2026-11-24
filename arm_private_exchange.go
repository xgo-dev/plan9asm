package plan9asm

import (
	"fmt"
	"strings"
)

type armPrivateExchangeSite struct {
	address int
	call    int
	target  string
	reg     Reg
}

// PrepareARMPrivateExchanges folds address-only private scalar leaves into
// their original ARM caller's register and flags state. Call it before
// inferring signatures or splitting a complete assembly file. keep protects
// declarations with an explicit ABI, using the original TEXT symbol.
func PrepareARMPrivateExchanges(file *File, keep func(string) bool) (*File, error) {
	if file == nil || file.Arch != ArchARM {
		return file, nil
	}
	leaves := make(map[string]Func)
	for _, fn := range file.Funcs {
		if !strings.HasSuffix(fn.Sym, "<>") || keep != nil && keep(fn.Sym) {
			continue
		}
		if _, duplicate := leaves[fn.Sym]; duplicate {
			return nil, fmt.Errorf("duplicate ARM private TEXT %q", fn.Sym)
		}
		leaves[fn.Sym] = fn
	}
	if len(leaves) == 0 {
		return file, nil
	}

	sites := make(map[int][]armPrivateExchangeSite)
	folded := make(map[string]bool)
	remaining := 1 << 16 // Bound the total size before copying any leaf bodies.
	for i, fn := range file.Funcs {
		nextExchange := make(map[Reg]int)
		for address := len(fn.Instrs) - 1; address >= 0; address-- {
			ins := fn.Instrs[address]
			op, _, _ := strings.Cut(string(ins.Op), ".")
			if op == "BX" && len(ins.Args) == 1 && ins.Args[0].Kind == OpMem {
				nextExchange[ins.Args[0].Mem.Base] = address
				continue
			}
			if op != "MOVW" || len(nextExchange) == 0 {
				continue
			}
			target, reg := armPrivateExchangeAddress(ins)
			leaf, private := leaves[target]
			call, reachesExchange := nextExchange[reg]
			if !private || !reachesExchange {
				continue
			}
			if !folded[target] && !armPrivateExchangeLeaf(leaf) {
				return nil, armPrivateExchangeError(target, "needs a zero-frame scalar leaf")
			}
			site := armPrivateExchangeSite{address: address, call: call, target: target, reg: reg}
			if err := site.prove(fn, leaf); err != nil {
				return nil, err
			}
			if len(leaf.Instrs) > remaining {
				return nil, armPrivateExchangeError(target, "exceeds the complete-file source expansion budget")
			}
			remaining -= len(leaf.Instrs)
			sites[i] = append(sites[i], site)
			folded[target] = true
		}
	}
	if len(folded) == 0 {
		return file, nil
	}

	for _, data := range file.Data {
		for _, ref := range []string{data.Sym, data.Addr} {
			if name := armPrivateExchangeSymbol(ref); folded[name] {
				return nil, armPrivateExchangeError(name, "escapes through DATA")
			}
		}
	}
	for _, global := range file.Globl {
		if name := armPrivateExchangeSymbol(global.Sym); folded[name] {
			return nil, armPrivateExchangeError(name, "has a separate GLOBL address")
		}
	}

	result := *file
	result.Funcs = make([]Func, 0, len(file.Funcs)-len(folded))
	for i, fn := range file.Funcs {
		addresses := make(map[int]string, len(sites[i]))
		for _, site := range sites[i] {
			addresses[site.address] = site.target
		}
		for ordinal, ins := range fn.Instrs {
			if ins.Op == OpTEXT {
				continue
			}
			for j, arg := range ins.Args {
				name := armPrivateExchangeSymbol(arg.Sym)
				if arg.Kind == OpMem {
					name = armPrivateExchangeSymbol(arg.Mem.Sym)
				}
				if folded[name] && (j != 0 || addresses[ordinal] != name) {
					return nil, armPrivateExchangeError(name, "has another code-address use at %s", ins.Raw)
				}
			}
		}
		if folded[fn.Sym] {
			continue
		}
		if len(sites[i]) != 0 {
			fn.Instrs = append([]Instr(nil), fn.Instrs...)
			names := newAssemblyBlockNames(fn)
			for _, site := range sites[i] {
				fn.Instrs[site.address] = Instr{Op: "NOP", Raw: fn.Instrs[site.address].Raw}
				exchange := fn.Instrs[site.call]
				label := names.fresh("arm_private_exchange")
				_, suffix, _ := strings.Cut(string(exchange.Op), "BX")
				fn.Instrs[site.call] = Instr{Op: Op("BL" + suffix), Raw: exchange.Raw,
					Args: []Operand{{Kind: OpIdent, Ident: label}}}
				leaf := leaves[site.target]
				fn.Instrs = append(fn.Instrs, Instr{Op: OpLABEL, Args: []Operand{{Kind: OpLabel, Sym: label}}})
				fn.Instrs = append(fn.Instrs, leaf.Instrs[1:len(leaf.Instrs)-1]...)
				fn.Instrs = append(fn.Instrs, Instr{Op: "B", Raw: "B (R14)",
					Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: armLinkRegister}}}})
			}
		}
		result.Funcs = append(result.Funcs, fn)
	}
	return &result, nil
}

func armPrivateExchangeError(symbol, format string, args ...any) error {
	return fmt.Errorf("%w: ARM private exchange %q %s", ErrProbeNeedsContext, symbol, fmt.Sprintf(format, args...))
}

func armPrivateExchangeAddress(ins Instr) (string, Reg) {
	op, condition, _, _ := armDecodeOp(string(ins.Op))
	if op != "MOVW" || condition != "" && condition != "AL" || len(ins.Args) != 2 ||
		ins.Args[0].Kind != OpSym || !strings.HasPrefix(ins.Args[0].Sym, "$") {
		return "", ""
	}
	form, err := parseARMIntegerSymbolForm(op, ins)
	if err != nil {
		return "", ""
	}
	symbol, offset, ok := parseSBRef(strings.TrimPrefix(form.symbol, "$"))
	if !ok || offset != 0 {
		return "", ""
	}
	return symbol, form.reg
}

func armPrivateExchangeSymbol(ref string) string {
	ref = strings.TrimPrefix(ref, "$")
	if name, _, ok := parseSBRef(ref); ok {
		return name
	}
	return ref
}

func (site armPrivateExchangeSite) prove(fn, leaf Func) error {
	if fn.Instrs[len(fn.Instrs)-1].Op != OpRET || len(fn.Instrs[len(fn.Instrs)-1].Args) != 0 {
		return armPrivateExchangeError(site.target, "requires an explicit final caller return")
	}
	reg, err := armBranchExchangeTarget(fn.Instrs[site.call])
	if err != nil {
		return err
	}
	if reg != site.reg || reg == "R10" || reg == "R14" || reg == "R11" && site.call != site.address+1 {
		return armPrivateExchangeError(site.target, "cannot prove a stable target in %s", site.reg)
	}
	for _, ins := range leaf.Instrs[1:] {
		for _, operand := range ins.Args {
			if armKernelOperandUsesReg(operand, site.reg) {
				return armPrivateExchangeError(site.target, "observes its incoming code address at %s", ins.Raw)
			}
		}
	}
	for ordinal, ins := range fn.Instrs {
		if ordinal == site.address || ordinal == site.call {
			continue
		}
		if ordinal > site.address && ordinal < site.call && !armPrivateScalarData(ins) {
			return armPrivateExchangeError(site.target, "target does not reach BX through straight-line scalar operations: %s", ins.Raw)
		}
		switch ins.Op {
		case OpWORD, OpBYTE, "LONG", "PCALIGN":
			return armPrivateExchangeError(site.target, "shares the caller with native layout at %s", ins.Raw)
		}
		for _, operand := range ins.Args {
			if operand.Kind == OpSym && strings.HasPrefix(operand.Sym, "$") {
				if mem, ok := parseMem(strings.TrimPrefix(operand.Sym, "$")); ok {
					operand = Operand{Kind: OpMem, Mem: mem}
				}
			}
			for _, physical := range [...]Reg{site.reg, "R11", PC, "R15"} {
				if armKernelOperandUsesReg(operand, physical) {
					return armPrivateExchangeError(site.target, "has an observable target, scratch or PC at %s", ins.Raw)
				}
			}
		}
	}
	return nil
}

func armPrivateExchangeLeaf(fn Func) bool {
	if fn.FrameSize != 0 && fn.FrameSize != -4 || fn.ArgSize != 0 || len(fn.Instrs) < 2 ||
		fn.Instrs[0].Op != OpTEXT || fn.Instrs[len(fn.Instrs)-1].Op != OpRET ||
		len(fn.Instrs[len(fn.Instrs)-1].Args) != 0 {
		return false
	}
	if _, err := armSourceNoFrame(fn); err != nil {
		return false
	}
	for _, ins := range fn.Instrs[1 : len(fn.Instrs)-1] {
		if !armPrivateScalarData(ins) {
			return false
		}
	}
	return true
}

func armPrivateScalarData(ins Instr) bool {
	op, _, _, _ := armDecodeOp(string(ins.Op))
	switch op {
	case "MOVW", "MOVB", "MOVBU", "MOVH", "MOVHU",
		"ADD", "SUB", "RSB", "ADC", "SBC", "RSC", "AND", "ORR", "EOR", "BIC", "MVN",
		"SLL", "SRL", "SRA", "MUL", "MULU", "MULA", "MULL", "MULLU", "MULAL", "MULALU",
		"CLZ", "REV", "REV16", "REVSH", "RBIT", "BFC", "BFI", "BFX", "BFXU",
		"CMP", "CMN", "TST", "TEQ", "NOP":
	default:
		return false
	}
	for _, arg := range ins.Args {
		switch arg.Kind {
		case OpImm:
			if arg.ImmRaw != "" || arg.ImmIsFloat {
				return false
			}
		case OpReg, OpRegShift:
			if !armPrivateDataRegister(arg.Reg) || arg.ShiftReg != "" && !armPrivateDataRegister(arg.ShiftReg) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func armPrivateDataRegister(reg Reg) bool {
	index, ok := armLocalLinkIndex(reg)
	return ok && index <= 12 && index != 10 && index != 11
}
