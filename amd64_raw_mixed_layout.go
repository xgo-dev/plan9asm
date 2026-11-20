package plan9asm

// These legacy SSE/SSE2 symbol loads occur between generated raw instruction
// spans. Their exact Go-assembler lengths are needed only to locate raw
// PC-relative targets; the named instructions still lower semantically.
var x86RawMixedSSESymbolReadOps = map[Op]bool{
	"ADDPD": true, "ADDPS": true, "MULPD": true, "MULPS": true,
	"ANDPD": true, "ANDPS": true, "ANDNPD": true, "ANDNPS": true,
	"XORPD": true, "XORPS": true, "CMPPD": true, "CMPPS": true,
	"PAND": true, "PANDN": true, "POR": true, "PXOR": true,
	"PADDB": true, "PADDW": true, "PADDL": true, "PADDQ": true,
	"PSUBL": true, "PCMPGTL": true, "PCMPEQL": true,
	"PMULHUW": true, "PMADDWL": true, "PMINUB": true, "PMAXUB": true,
	"MOVQ": true,
}

func x86RawMixedSSESymbolReadSize(ins Instr) (int, bool) {
	if !x86RawMixedSSESymbolReadOps[ins.Op] || len(ins.Args) < 2 ||
		ins.Args[0].Kind != OpSym || ins.Args[1].Kind != OpReg {
		return 0, false
	}
	if _, _, ok := parseSBRef(ins.Args[0].Sym); !ok {
		return 0, false
	}
	register, ok := amd64ParseXReg(ins.Args[1].Reg)
	if !ok || register >= 16 {
		return 0, false
	}
	compare := ins.Op == "CMPPD" || ins.Op == "CMPPS"
	if compare {
		if len(ins.Args) != 3 || ins.Args[2].Kind != OpImm || ins.Args[2].Imm < 0 || ins.Args[2].Imm > 255 {
			return 0, false
		}
	} else if len(ins.Args) != 2 {
		return 0, false
	}
	// 0F opcode, ModRM and disp32 = 7 bytes. Packed-double/integer and
	// MOVQ forms have one mandatory prefix; X8..X15 add one REX byte.
	length := 7
	if ins.Op == "MOVQ" || len(ins.Op) > 0 && ins.Op[0] == 'P' ||
		len(ins.Op) >= 2 && ins.Op[len(ins.Op)-2:] == "PD" {
		length++
	}
	if register >= 8 {
		length++
	}
	if compare {
		length++
	}
	return length, true
}
