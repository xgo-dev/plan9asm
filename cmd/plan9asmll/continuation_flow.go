package main

import (
	"strings"

	"github.com/xgo-dev/plan9asm"
)

// Every possible path to a table load must initialize its base. Direct jumps
// to an exit before initialization are legal; an indirect dispatch is not.
// Worklist joins intersect definite definitions, including helper backedges.
func continuationTableDefinitions(file *plan9asm.File, group plan9asm.X86TailGroup,
	tables map[string]*continuationTable, regs map[plan9asm.Reg]bool,
) bool {
	type point struct {
		function    string
		instruction int
	}
	functions := map[string]plan9asm.Func{}
	labels := map[string]map[string]int{}
	members := map[string]bool{group.Root: true}
	for _, name := range group.Helpers {
		members[name] = true
	}
	for _, fn := range file.Funcs {
		if !members[fn.Sym] {
			continue
		}
		functions[fn.Sym] = fn
		labels[fn.Sym] = map[string]int{}
		for i, ins := range fn.Instrs {
			if ins.Op == plan9asm.OpLABEL && len(ins.Args) == 1 {
				labels[fn.Sym][ins.Args[0].Sym] = i
			}
		}
	}
	bits := map[plan9asm.Reg]uint64{}
	for r := range regs {
		bits[r] = uint64(1) << len(bits)
	}
	entry := point{function: group.Root}
	known := map[point]uint64{entry: 0}
	queue := []point{entry}
	merge := func(next point, state uint64) bool {
		if next.instruction < 0 || next.instruction >= len(functions[next.function].Instrs) {
			return false
		}
		old, visited := known[next]
		if visited {
			state &= old
		}
		if !visited || old != state {
			known[next] = state
			queue = append(queue, next)
		}
		return true
	}
	for len(queue) != 0 {
		at := queue[0]
		queue = queue[1:]
		state := known[at]
		ins := functions[at.function].Instrs[at.instruction]
		for _, arg := range ins.Args {
			if arg.Kind == plan9asm.OpMem && regs[arg.Mem.Base] && state&bits[arg.Mem.Base] == 0 {
				return false
			}
		}
		if ins.Op == "LEAQ" && len(ins.Args) == 2 {
			name, _, _ := continuationSB(ins.Args[0])
			if tables[name] != nil {
				state |= bits[ins.Args[1].Reg]
			}
		}
		if ins.Op == "RET" {
			continue
		}
		branch := strings.HasPrefix(string(ins.Op), "J") || ins.Op == "LOOP"
		if branch {
			if len(ins.Args) == 0 {
				return false
			}
			arg := ins.Args[len(ins.Args)-1]
			if name, _, ok := continuationSB(arg); ok {
				if name == group.Root || !merge(point{function: name}, state) {
					return false
				}
			} else if arg.Kind == plan9asm.OpIdent {
				target, ok := labels[at.function][arg.Ident]
				if !ok || !merge(point{function: at.function, instruction: target}, state) {
					return false
				}
			} else if ins.Op == "JMP" && arg.Kind == plan9asm.OpReg {
				for _, helper := range group.Helpers {
					if !merge(point{function: helper}, state) {
						return false
					}
				}
			} else {
				return false
			}
			if ins.Op == "JMP" {
				continue
			}
		}
		if !merge(point{function: at.function, instruction: at.instruction + 1}, state) {
			return false
		}
	}
	return true
}
