package plan9asm

import (
	"fmt"
	"strings"
)

// X86TailGroup names one ordinary entry and its private continuation TEXTs.
// Names use source spelling, before Options.ResolveSym. See X86TailGroups.
type X86TailGroup struct {
	Root    string
	Helpers []string
}

type x86Continuation struct {
	root  string
	label string
}

func (f *File) isX86Continuation(name string, resolve func(string) string) bool {
	for symbol := range f.x86Continuations {
		if resolve(symbol) == name {
			return true
		}
	}
	return false
}

func coalesceX86Continuations(file *File, opt Options) (*File, error) {
	if file == nil {
		return nil, fmt.Errorf("nil file")
	}
	if len(opt.X86TailGroups) == 0 || len(file.x86Continuations) != 0 {
		return file, nil
	}
	if file.Arch != ArchAMD64 || (opt.Goarch != "amd64" && opt.Goarch != "386") {
		return nil, fmt.Errorf("x86 continuation groups require an x86 target")
	}
	resolve := opt.ResolveSym
	if resolve == nil {
		resolve = func(s string) string { return s }
	}
	functions := make(map[string]Func, len(file.Funcs))
	for _, fn := range file.Funcs {
		if _, duplicate := functions[fn.Sym]; duplicate {
			return nil, fmt.Errorf("duplicate continuation TEXT %q", fn.Sym)
		}
		functions[fn.Sym] = fn
	}
	addresses := map[string]x86Continuation{}
	owners := map[string]string{}
	for gi, group := range opt.X86TailGroups {
		if len(group.Helpers) == 0 {
			return nil, fmt.Errorf("empty continuation group %q", group.Root)
		}
		members := append([]string{group.Root}, group.Helpers...)
		for mi, name := range members {
			fn, exists := functions[name]
			if !exists || owners[name] != "" {
				return nil, fmt.Errorf("missing or repeated continuation TEXT %q", name)
			}
			owners[name] = group.Root
			if fn.X86RawText != nil || fn.FrameSize != 0 {
				return nil, fmt.Errorf("continuation TEXT %q requires a zero frame and no native layout dependency", name)
			}
			if len(fn.Instrs) == 0 {
				return nil, fmt.Errorf("empty continuation TEXT %q", name)
			}
			last := fn.Instrs[len(fn.Instrs)-1]
			if (last.Op != "RET" || len(last.Args) != 0) && last.Op != "JMP" {
				return nil, fmt.Errorf("continuation TEXT %q has no explicit terminating transfer", name)
			}
			if mi == 0 {
				continue
			}
			sig, ok := opt.Sigs[resolve(name)]
			if !ok || sig.Ret != Void || len(sig.Args) != 0 || fn.ArgSize != 0 ||
				len(sig.Frame.Params)+len(sig.Frame.Results) != 0 {
				return nil, fmt.Errorf("continuation %q must be a zero-frame void helper", name)
			}
			addresses[name] = x86Continuation{
				root: group.Root, label: fmt.Sprintf("p9_cont_%d_%d", gi, mi),
			}
		}
	}

	// These addresses are local control-flow labels, not callable functions or
	// byte-addressable code. Refuse a group before emitting any changed ABI.
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			for ai, arg := range ins.Args {
				if arg.Kind != OpSym {
					continue
				}
				base, off, ok := parseSBRef(arg.Sym)
				target, continuation := addresses[strings.TrimPrefix(base, "$")]
				if !ok || !continuation {
					continue
				}
				if off != 0 || ins.Op == "CALL" || (ins.Op == "JMP" && owners[fn.Sym] != target.root) {
					return nil, fmt.Errorf("invalid continuation reference in %q: %s", fn.Sym, ins.Raw)
				}
				if ins.Op == "JMP" && len(ins.Args) == 1 {
					continue
				}
				address := ins.Op == "LEAQ" || ins.Op == "LEAL" ||
					((ins.Op == "MOVQ" || ins.Op == "MOVL") && strings.HasPrefix(arg.Sym, "$"))
				if !address || ai != 0 || len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
					return nil, fmt.Errorf("continuation %q is not readable or callable code: %s", base, ins.Raw)
				}
			}
		}
	}
	for _, d := range file.Data {
		if d.Addr != "" {
			base, _, _ := parseSBRef(d.Addr)
			if _, ok := addresses[strings.TrimPrefix(base, "$")]; ok {
				return nil, fmt.Errorf("continuation DATA relocations require an explicit initializer")
			}
		}
	}

	fused := map[string]Func{}
	for gi, group := range opt.X86TailGroups {
		root := functions[group.Root]
		root.Instrs = nil
		root.x86IndirectLabels = nil
		for mi, name := range append([]string{group.Root}, group.Helpers...) {
			fn := functions[name]
			prefix := fmt.Sprintf("p9_body_%d_%d_", gi, mi)
			if mi != 0 {
				label := addresses[name].label
				root.Instrs = append(root.Instrs, Instr{Op: OpLABEL, Args: []Operand{{Kind: OpLabel, Sym: label}}})
				root.x86IndirectLabels = append(root.x86IndirectLabels, label)
			}
			labels := map[string]string{}
			for i, ins := range fn.Instrs {
				if ins.Op == OpLABEL && len(ins.Args) == 1 {
					labels[ins.Args[0].Sym] = fmt.Sprintf("%s%d", prefix, i)
				}
			}
			for _, ins := range fn.Instrs {
				ins.Args = append([]Operand(nil), ins.Args...)
				for ai, arg := range ins.Args {
					switch arg.Kind {
					case OpLabel:
						ins.Args[ai].Sym = labels[arg.Sym]
					case OpIdent:
						if label, ok := labels[arg.Ident]; ok {
							ins.Args[ai].Ident = label
						}
					case OpReg:
						if label, ok := labels[string(arg.Reg)]; ok && (ins.Op == "JMP" || isAMD64ConditionalBranch(ins.Op)) {
							ins.Args[ai] = Operand{Kind: OpIdent, Ident: label}
						}
					case OpSym:
						base, off, ok := parseSBRef(arg.Sym)
						if target, exists := addresses[base]; ok && exists && off == 0 && ins.Op == "JMP" {
							ins.Args[ai] = Operand{Kind: OpIdent, Ident: target.label}
						}
					}
				}
				root.Instrs = append(root.Instrs, ins)
			}
		}
		fused[group.Root] = root
	}
	result := *file
	result.Funcs = nil
	result.x86Continuations = addresses
	for _, fn := range file.Funcs {
		if _, helper := addresses[fn.Sym]; helper {
			continue
		}
		if root, ok := fused[fn.Sym]; ok {
			fn = root
		}
		fn.x86ContinuationAddresses = addresses
		result.Funcs = append(result.Funcs, fn)
	}
	return &result, nil
}
