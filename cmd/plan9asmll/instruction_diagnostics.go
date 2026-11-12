package main

import (
	"sort"

	"github.com/xgo-dev/plan9asm"
)

// Supplementary hints from this compilation's complete parsed input. They
// neither grant support nor change a failed translation into a successful one.
// In particular, a read/CPP/parse failure has no parsed instruction inventory.
type instructionDiagnostics struct {
	supported map[string]struct{}
	ops       []string
	hits      []unsupportedHit
}

func (d *instructionDiagnostics) collect(file *plan9asm.File) {
	d.ops, d.hits = nil, nil
	if file == nil || len(d.supported) == 0 {
		return
	}
	seen := make(map[string]struct{})
	for _, function := range file.Funcs {
		for ordinal, instruction := range function.Instrs {
			op := normalizeOp(string(instruction.Op))
			if op == "" || op == "LABEL" || isDirective(op) {
				continue
			}
			if _, supported := d.supported[op]; supported {
				continue
			}
			seen[op] = struct{}{}
			d.hits = append(d.hits, unsupportedHit{
				Op: op, Source: instruction.Raw,
				Function: function.Sym, Instruction: ordinal + 1,
			})
		}
	}
	for op := range seen {
		d.ops = append(d.ops, op)
	}
	sort.Strings(d.ops)
}
