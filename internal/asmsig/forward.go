// Package asmsig contains signature inference shared by the command drivers.
package asmsig

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm"
)

// RefineTailForwarders gives declaration-free, pure tail stubs the ABI of
// their destination. known protects signatures established by declarations or
// other reliable ABI evidence. Explicit FP slots also provide usable evidence
// when build tags hide the Go declarations but keep the assembly selected.
// Existing signatures with no such evidence are not invented or discarded.
func RefineTailForwarders(file *plan9asm.File, sigs map[string]plan9asm.FuncSig, resolve func(string) string, known map[string]bool) {
	evidence := make(map[string]bool, len(known))
	for name, value := range known {
		evidence[name] = value
	}
	// Iteration resolves chains independent of source order. Cycles without
	// any frame/declaration evidence remain unresolved.
	for pass := 0; pass < len(file.Funcs); pass++ {
		changed := false
		for _, fn := range file.Funcs {
			caller := resolve(fn.Sym)
			if known[caller] {
				continue
			}
			symbol, pure := pureTailTarget(fn)
			if !pure {
				continue
			}
			targetName := resolve(symbol)
			target, ok := sigs[targetName]
			if !ok || (!evidence[targetName] && len(target.Frame.Params) == 0 && len(target.Frame.Results) == 0) {
				continue
			}
			target.Name = caller
			if !reflect.DeepEqual(sigs[caller], target) || !evidence[caller] {
				sigs[caller] = target
				evidence[caller] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}
}

func pureTailTarget(fn plan9asm.Func) (string, bool) {
	target := ""
	for _, ins := range fn.Instrs {
		op := strings.ToUpper(string(ins.Op))
		switch op {
		case "TEXT", "PCDATA", "FUNCDATA":
			continue
		case "RET":
			if target != "" && len(ins.Args) == 0 {
				continue // Unreachable after the unconditional tail transfer.
			}
		case "JMP", "B":
		default:
			return "", false
		}
		if target != "" || len(ins.Args) != 1 || ins.Args[0].Kind != plan9asm.OpSym {
			return "", false
		}
		sym := strings.TrimSpace(ins.Args[0].Sym)
		if !strings.HasSuffix(sym, "(SB)") {
			return "", false
		}
		target = strings.TrimSuffix(sym, "(SB)")
		if i := strings.LastIndexAny(target, "+-"); i > 0 {
			if offset, err := strconv.ParseInt(strings.TrimSpace(target[i:]), 0, 64); err == nil {
				if offset != 0 {
					return "", false
				}
				target = strings.TrimSpace(target[:i])
			}
		}
	}
	return target, target != ""
}
