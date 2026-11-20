package plan9asm

import "strings"

// This is the existing complete named LEA grammar restricted to an SB address.
// It describes a GP write, not DATA contents, numerical address bits or backing.
func x86SBLEAWriteShape(ins Instr, arch string) (int, uint8, int64, MemRef, bool) {
	if !x86ResultNamedPredicateInstruction(ins) || arch != "386" && arch != "amd64" {
		return 0, 0, 0, MemRef{}, false
	}
	width, err := x86LEAOperandWidth(ins, arch)
	if err != nil {
		return 0, 0, 0, MemRef{}, false
	}
	memory, valid := x86SBMemoryAddressRole(ins.Args[0], arch)
	if !valid || memory.OffRaw != "" || memory.Segment != "" || memory.IndexExt != "" ||
		memory.Index == "" && memory.Scale != 0 {
		return 0, 0, 0, MemRef{}, false
	}
	symbol, _, valid := parseSBRef(memory.Sym)
	if !valid || symbol == "" || strings.IndexAny(symbol, "$+(),[] \t") >= 0 {
		return 0, 0, 0, MemRef{}, false
	}
	index, mask, valid := x86ResultGP(ins.Args[1].Reg, width, arch)
	return index, mask, width, memory, valid && (arch != "amd64" || index != 14)
}

// The paired ordinary lowerer may discard an address value without claiming
// any of its bits are NUM. W preserves prior upper bytes; L only defines the
// architectural zero upper32; Q leaves all written bytes unknown. No read,
// store, caller, raw-entry or logical-frame permission is established here.
func x86ResultUnknownSBAddressStep(ins Instr, state *x86ResultState, arch string) (bool, bool) {
	if address, immediate, _, known := x86StaticAddressValueMove(ins, arch); known && immediate {
		// Go progedit turns native-word MOV $symbol into LEA. Project only
		// that already validated address role; the original source is not
		// rewritten and no external address bit becomes numerical knowledge.
		ins.Args = append([]Operand(nil), ins.Args...)
		ins.Args[0] = Operand{Kind: OpMem, Mem: MemRef{Sym: address.symbol + "(SB)", Off: address.offset}}
		ins.Op = "LEAQ"
		if arch == "386" {
			ins.Op = "LEAL"
		}
	}
	index, mask, width, memory, known := x86SBLEAWriteShape(ins, arch)
	if !known {
		return false, false
	}
	if state == nil {
		return false, true
	}
	if memory.Index != "" {
		source, _, valid := x86ResultGP(memory.Index, x86ResultPointerWord(arch), arch)
		if !valid || state.pointerGP[source] || state.callerAddressGP[source] || state.resultAddressGP[source].valid ||
			!x86ResultRead(Operand{Kind: OpReg, Reg: memory.Index}, x86ResultPointerWord(arch), state, nil, arch) {
			return false, true
		}
	}
	state.gp[index] &^= mask
	state.canonicalGP[index] &^= mask
	if width == 4 {
		state.gp[index] |= 0xf0
		state.canonicalGP[index] |= 0xf0
	}
	state.pointerGP[index], state.callerAddressGP[index] = false, false
	state.callerAddressOrigin[index] = 0
	state.resultAddressGP[index] = x86ResultSlotAddress{}
	state.predicate = x86ResultPredicate{}
	return true, true
}
