package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"golang.org/x/tools/go/packages"
)

// inferX86TailGroups recognizes private threaded dispatchers, not arbitrary
// tail calls. The direct-jump component must have one framed entry; every
// other TEXT must be an uncalled, zero-frame helper. Code pointers may only
// enter complete file-local tables, then be loaded immediately before JMP.
func inferX86TailGroups(pkg *packages.Package, file *plan9asm.File, asmPath, goarch string,
	resolve func(string) string, sigs map[string]plan9asm.FuncSig,
) ([]plan9asm.X86TailGroup, error) {
	if file.Arch != plan9asm.ArchAMD64 || goarch != "amd64" {
		return nil, nil
	}
	byName := map[string]int{}
	for i, fn := range file.Funcs {
		byName[fn.Sym] = i
	}
	neighbors := make([][]int, len(file.Funcs))
	for i, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			if ins.Op != "JMP" || len(ins.Args) != 1 {
				continue
			}
			name, off, ok := continuationSB(ins.Args[0])
			if j, exists := byName[name]; ok && off == 0 && exists {
				neighbors[i] = append(neighbors[i], j)
				neighbors[j] = append(neighbors[j], i)
			}
		}
	}
	var groups []plan9asm.X86TailGroup
	seen := map[int]bool{}
	for start := range file.Funcs {
		if seen[start] || len(neighbors[start]) == 0 {
			continue
		}
		component := map[int]bool{}
		queue := []int{start}
		for len(queue) != 0 {
			i := queue[0]
			queue = queue[1:]
			if seen[i] {
				continue
			}
			seen[i], component[i] = true, true
			queue = append(queue, neighbors[i]...)
		}
		group, ok := continuationComponent(file, component, resolve, sigs)
		if !ok || !closedContinuationTables(file, group, sigs, resolve) {
			continue
		}
		private, err := privateContinuationReferences(pkg, asmPath, group.Helpers)
		if err != nil {
			return nil, err
		}
		if private {
			groups = append(groups, group)
		}
	}
	return groups, nil
}

func continuationComponent(file *plan9asm.File, members map[int]bool,
	resolve func(string) string, sigs map[string]plan9asm.FuncSig,
) (plan9asm.X86TailGroup, bool) {
	var group plan9asm.X86TailGroup
	borrowedFrame := false
	for i, fn := range file.Funcs {
		if !members[i] {
			continue
		}
		sig, ok := sigs[resolve(fn.Sym)]
		if !ok || fn.FrameSize != 0 {
			return group, false
		}
		if len(sig.Frame.Params)+len(sig.Frame.Results) != 0 {
			if group.Root != "" {
				return group, false
			}
			group.Root = fn.Sym
			continue
		}
		if sig.Ret != plan9asm.Void || len(sig.Args) != 0 || fn.ArgSize != 0 {
			return group, false
		}
		group.Helpers = append(group.Helpers, fn.Sym)
		for _, ins := range fn.Instrs {
			for _, arg := range ins.Args {
				if arg.Kind == plan9asm.OpFP || arg.Kind == plan9asm.OpFPAddr {
					borrowedFrame = true
				}
			}
		}
	}
	return group, group.Root != "" && len(group.Helpers) != 0 && borrowedFrame
}

func continuationSB(arg plan9asm.Operand) (string, int64, bool) {
	if arg.Kind != plan9asm.OpSym || !strings.HasSuffix(arg.Sym, "(SB)") {
		return "", 0, false
	}
	name, off := splitSymPlusOff(strings.TrimSuffix(strings.TrimPrefix(arg.Sym, "$"), "(SB)"))
	return name, off, name != ""
}

type continuationTable struct {
	slots map[int64]bool
	init  string
}

func closedContinuationTables(file *plan9asm.File, group plan9asm.X86TailGroup,
	sigs map[string]plan9asm.FuncSig, resolve func(string) string,
) bool {
	members, helpers := map[string]bool{group.Root: true}, map[string]bool{}
	for _, name := range group.Helpers {
		members[name], helpers[name] = true, true
	}
	tables := map[string]*continuationTable{}
	initializers := map[string]bool{}
	for _, fn := range file.Funcs {
		for i, ins := range fn.Instrs {
			for _, arg := range ins.Args {
				name, off, ok := continuationSB(arg)
				if !ok || !helpers[name] {
					continue
				}
				if off != 0 {
					return false
				}
				if ins.Op == "JMP" && len(ins.Args) == 1 && members[fn.Sym] {
					continue
				}
				if members[fn.Sym] || ins.Op != "LEAQ" || len(ins.Args) != 2 ||
					ins.Args[1].Kind != plan9asm.OpReg || i+1 >= len(fn.Instrs) {
					return false
				}
				next := fn.Instrs[i+1]
				if next.Op != "MOVQ" || len(next.Args) != 2 || !sameContinuationReg(next.Args[0], ins.Args[1]) {
					return false
				}
				table, slot, ok := continuationSB(next.Args[1])
				if !ok || !strings.HasSuffix(table, "<>") || slot < 0 || slot%8 != 0 {
					return false
				}
				if tables[table] == nil {
					tables[table] = &continuationTable{slots: map[int64]bool{}, init: fn.Sym}
				}
				if tables[table].init != fn.Sym || tables[table].slots[slot] {
					return false
				}
				tables[table].slots[slot] = true
				initializers[fn.Sym] = true
			}
		}
	}
	for table, info := range tables {
		complete := false
		for _, global := range file.Globl {
			if global.Sym == table && global.Size == int64(len(info.slots))*8 {
				complete = true
				for off := int64(0); off < global.Size; off += 8 {
					complete = complete && info.slots[off]
				}
			}
		}
		if !complete {
			return false
		}
	}
	for _, data := range file.Data {
		if tables[data.Sym] != nil {
			return false
		}
		name, _, _ := continuationSB(plan9asm.Operand{Kind: plan9asm.OpSym, Sym: data.Addr})
		if helpers[name] {
			return false
		}
	}

	// Table-base registers cannot be overwritten, copied or exposed. This
	// permits indexed reads but proves that the addresses remain in the group.
	tableRegs := map[plan9asm.Reg]bool{}
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			for ai, arg := range ins.Args {
				table, off, ok := continuationSB(arg)
				if !ok || tables[table] == nil {
					continue
				}
				if initializers[fn.Sym] {
					continue // The complete initializer is checked below.
				}
				if fn.Sym != group.Root || ai != 0 || off != 0 || ins.Op != "LEAQ" ||
					len(ins.Args) != 2 || ins.Args[1].Kind != plan9asm.OpReg {
					return false
				}
				tableRegs[ins.Args[1].Reg] = true
				switch ins.Args[1].Reg {
				case "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15":
					// These registers have no implicit x86 instruction writes.
				default:
					return false
				}
			}
		}
	}
	for _, fn := range file.Funcs {
		if initializers[fn.Sym] {
			sig := sigs[resolve(fn.Sym)]
			if sig.Ret != plan9asm.Void || len(sig.Args) != 0 || !continuationInitializer(fn, helpers, tables) {
				return false
			}
		}
		if members[fn.Sym] && !continuationDispatchBody(fn, members, tables, tableRegs) {
			return false
		}
	}
	return continuationTableDefinitions(file, group, tables, tableRegs)
}

func continuationInitializer(fn plan9asm.Func, helpers map[string]bool, tables map[string]*continuationTable) bool {
	for i := 0; i < len(fn.Instrs); {
		ins := fn.Instrs[i]
		if ins.Op == plan9asm.OpTEXT && i == 0 {
			i++
			continue
		}
		if ins.Op == "RET" && len(ins.Args) == 0 && i == len(fn.Instrs)-1 {
			return true
		}
		if ins.Op != "LEAQ" || len(ins.Args) != 2 || i+1 >= len(fn.Instrs) {
			return false
		}
		name, off, _ := continuationSB(ins.Args[0])
		next := fn.Instrs[i+1]
		if !helpers[name] || off != 0 || next.Op != "MOVQ" || len(next.Args) != 2 || !sameContinuationReg(next.Args[0], ins.Args[1]) {
			return false
		}
		table, _, _ := continuationSB(next.Args[1])
		if tables[table] == nil {
			return false
		}
		i += 2
	}
	return false
}

func continuationDispatchBody(fn plan9asm.Func, members map[string]bool,
	tables map[string]*continuationTable, tableRegs map[plan9asm.Reg]bool,
) bool {
	for i, ins := range fn.Instrs {
		switch ins.Op {
		case "SYSCALL", "SYSENTER", "SYSEXIT", "SYSRET", "IRET", "IRETL", "IRETQ", "IRETW",
			"INT", "INTO", "LCALL", "LJMP", "RETF", "RETFQ", "XBEGIN", "XEND", "XABORT":
			return false // Exceptional control flow or implicit machine-state changes.
		}
		if ins.Op == "RET" && len(ins.Args) != 0 {
			return false
		}
		if ins.Op == "CALL" || ins.Op == "BYTE" || ins.Op == "WORD" || ins.Op == "LONG" || ins.Op == "QUAD" {
			return false
		}
		for ai, arg := range ins.Args {
			if arg.Kind == plan9asm.OpMem && arg.Mem.Base == plan9asm.PC {
				return false // No alternate entrance into a load/JMP pair.
			}
			if arg.Kind == plan9asm.OpReg && tableRegs[arg.Reg] {
				if ins.Op != "LEAQ" || ai != 1 || len(ins.Args) != 2 {
					return false
				}
				base, _, _ := continuationSB(ins.Args[0])
				if tables[base] == nil {
					return false
				}
			}
			if arg.Kind == plan9asm.OpMem && (tableRegs[arg.Mem.Base] || tableRegs[arg.Mem.Index]) {
				if !tableRegs[arg.Mem.Base] || tableRegs[arg.Mem.Index] || ai != 0 || ins.Op != "MOVQ" || len(ins.Args) != 2 ||
					ins.Args[1].Kind != plan9asm.OpReg || i+1 >= len(fn.Instrs) {
					return false
				}
				next := fn.Instrs[i+1]
				if next.Op != "JMP" || len(next.Args) != 1 || !sameContinuationReg(next.Args[0], ins.Args[1]) {
					return false
				}
			}
		}
		if ins.Op != "JMP" || len(ins.Args) != 1 {
			continue
		}
		arg := ins.Args[0]
		if name, off, ok := continuationSB(arg); ok {
			if !members[name] || off != 0 {
				return false
			}
			continue
		}
		if arg.Kind == plan9asm.OpIdent {
			continue
		}
		if arg.Kind != plan9asm.OpReg || i == 0 {
			return false
		}
		prev := fn.Instrs[i-1]
		if prev.Op != "MOVQ" || len(prev.Args) != 2 || !sameContinuationReg(prev.Args[1], arg) ||
			prev.Args[0].Kind != plan9asm.OpMem || !tableRegs[prev.Args[0].Mem.Base] {
			return false
		}
	}
	return true
}

func sameContinuationReg(a, b plan9asm.Operand) bool {
	return a.Kind == plan9asm.OpReg && b.Kind == plan9asm.OpReg && a.Reg == b.Reg
}

// Inspect all sibling Go sources, including tests and other build variants.
// A false positive only prevents this optimization. Silently dropping a
// callable Go symbol would change the program's ABI.
func privateContinuationReferences(pkg *packages.Package, asmPath string, helpers []string) (bool, error) {
	if pkg == nil || pkg.Types == nil {
		return false, nil
	}
	names := map[string]bool{}
	for _, symbol := range helpers {
		if !strings.HasPrefix(symbol, "·") {
			return false, nil
		}
		name := strings.TrimPrefix(symbol, "·")
		if ast.IsExported(name) || pkg.Types.Scope().Lookup(name) == nil {
			return false, nil
		}
		names[name] = true
	}
	entries, err := os.ReadDir(filepath.Dir(asmPath))
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(filepath.Dir(asmPath), entry.Name())
		if filepath.Clean(path) == filepath.Clean(asmPath) {
			continue
		}
		ext := filepath.Ext(path)
		if ext != ".go" && ext != ".s" && ext != ".S" && ext != ".h" {
			continue
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return false, err
		}
		if ext != ".go" {
			for name := range names {
				if strings.Contains(string(source), name) {
					return false, nil
				}
			}
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ParseComments)
		if err != nil {
			return false, err
		}
		declarations := map[*ast.Ident]bool{}
		for _, declaration := range parsed.Decls {
			if fn, ok := declaration.(*ast.FuncDecl); ok && names[fn.Name.Name] && fn.Body == nil {
				declarations[fn.Name] = true
			}
		}
		private := true
		ast.Inspect(parsed, func(node ast.Node) bool {
			if id, ok := node.(*ast.Ident); ok && names[id.Name] && !declarations[id] {
				private = false
			}
			return private
		})
		for _, comments := range parsed.Comments {
			for _, comment := range comments.List {
				if strings.Contains(comment.Text, "go:linkname") {
					for name := range names {
						if strings.Contains(comment.Text, name) {
							private = false
						}
					}
				}
			}
		}
		if !private {
			return false, nil
		}
	}
	return true, nil
}
