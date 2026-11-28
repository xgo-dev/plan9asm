package exclusive

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

// Follow every still-open load, including backwards edges. A source store to
// a different address already breaks the architecture's constrained-loop
// guarantee. It still runs through the real monitor in the scalar lowering.
func validateUnbundled(fn asm.Func, regions []Region) error {
	var code []asm.Instr
	labels := map[string]int{}
	var pending []int
	for _, ins := range fn.Instrs {
		if ins.Op == asm.OpLABEL {
			if len(ins.Args) == 1 {
				labels[ins.Args[0].Sym] = len(code)
			}
			continue
		}
		base, _, _ := strings.Cut(string(ins.Op), ".")
		if isLoad(base) {
			pending = append(pending, len(code)+1)
		}
		code = append(code, ins)
	}
	for _, r := range regions {
		if r.exit.Op != "" {
			if i, ok := labels[r.exit.Args[0].String()]; ok {
				pending = append(pending, i)
			}
		}
	}
	seen := make([]bool, len(code))
	for len(pending) > 0 {
		i := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if i < 0 || i >= len(code) || seen[i] {
			continue
		}
		seen[i] = true
		ins := code[i]
		op, cond, _ := strings.Cut(string(ins.Op), ".")
		if isStore(op) {
			return fmt.Errorf("%w: unbundled exclusive store reachable with a live reservation: %s", asm.ErrProbeNeedsContext, ins.Raw)
		}
		if ins.Op == Opcode || isLoad(op) && cond == "" || op == "RET" && (cond == "" || cond == "AL") || op == "CLREX" || op == "STLR" || op == "WORD" && cond == "" && len(ins.Args) == 1 && ins.Args[0].Imm == 0xf57ff01f {
			continue
		}
		switch op {
		case string(ExitOpcode), "B", "BR", "BX", "JMP", "BNE", "BEQ", "BLT", "BLE", "BGT", "BGE", "BMI", "BPL", "BHS", "BLO", "BCC", "BCS", "BHI", "BLS", "BVS", "BVC", "CBZ", "CBNZ", "CBZW", "CBNZW", "TBZ", "TBNZ":
			if len(ins.Args) == 0 {
				return fmt.Errorf("invalid branch %s", ins.Raw)
			}
			a := ins.Args[len(ins.Args)-1]
			if a.Kind == asm.OpMem && a.Mem.Base == asm.PC {
				pending = append(pending, i+int(a.Mem.Off))
			} else if idx, ok := labels[a.String()]; ok {
				pending = append(pending, idx)
			} else if a.Kind != asm.OpSym || !strings.HasSuffix(a.Sym, "(SB)") {
				return fmt.Errorf("%w: unresolved control transfer while exclusive reservation is live: %s", asm.ErrProbeNeedsContext, ins.Raw)
			}
			if (op == "B" || op == "BR" || op == "BX" || op == "JMP") && (cond == "" || cond == "AL") {
				continue
			}
		}
		pending = append(pending, i+1)
	}
	return nil
}
