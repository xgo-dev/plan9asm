package arm64

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
	"golang.org/x/arch/arm64/arm64asm"
)

// IsRawSVELengthAdd identifies the signed imm6 ADDVL/ADDPL encoding.
func IsRawSVELengthAdd(word uint32) bool {
	return word&^uint32(0x00400000|31<<16|63<<5|31) == 0x04205000
}

// DecodeRawWord decodes a 32-bit little-endian AArch64 instruction word into a
// canonical Plan 9 asm.Instr using golang.org/x/arch/arm64/arm64asm.
// This scales to the full AArch64 ISA (NEON, Crypto, LSE, SVE, system) without
// hand-maintaining bit-slicing decoders for each WORD directive.
func DecodeRawWord(word uint32) (asm.Instr, bool) {
	// x/arch versions compatible with Go 1.20 omit these scalable-length
	// encodings. The signed imm6 scales by VL (or PL) in the named lowerer.
	if IsRawSVELengthAdd(word) {
		op := asm.Op("ADDVL")
		if word&(1<<22) != 0 {
			op = "ADDPL"
		}
		reg := func(n uint32) asm.Operand {
			name := asm.Reg(fmt.Sprintf("R%d", n))
			if n == 31 {
				name = asm.SP
			}
			return asm.Operand{Kind: asm.OpReg, Reg: name}
		}
		imm := int64(int32(word<<21) >> 26)
		return asm.Instr{Op: op, DecodedFromRaw: true, Raw: fmt.Sprintf("WORD $%#x", word), Args: []asm.Operand{
			{Kind: asm.OpImm, Imm: imm}, reg(word >> 16 & 31), reg(word & 31),
		}}, true
	}
	if decoded, ok := decodeSVEWord(word); ok {
		return decoded, true
	}
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], word)
	inst, err := arm64asm.Decode(buf[:])
	if err != nil {
		return asm.Instr{}, false
	}
	text := strings.TrimSpace(arm64asm.GoSyntax(inst, 0, nil, nil))
	if text == "" || strings.HasPrefix(text, "?") {
		return asm.Instr{}, false
	}
	// arm64asm spells NOP as "NOOP"; normalize to Plan 9 "NOP".
	if text == "NOOP" {
		return asm.Instr{Op: "NOP", Raw: fmt.Sprintf("WORD $0x%08x", word), DecodedFromRaw: true}, true
	}
	src := "TEXT _decode(SB),$0-0\n\t" + text + "\n\tRET\n"
	file, err := asm.Parse(asm.ArchARM64, src)
	if err != nil || len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) < 2 {
		return asm.Instr{}, false
	}
	decoded := file.Funcs[0].Instrs[1]
	// x/arch GoSyntax omits writeback on some NEON structure loads.
	// The decoded addressing mode retains this part of the instruction.
	if !strings.Contains(string(decoded.Op), ".") {
		for _, arg := range inst.Args {
			mem, ok := arg.(arm64asm.MemImmediate)
			if !ok {
				continue
			}
			switch mem.Mode {
			case arm64asm.AddrPreIndex:
				decoded.Op += ".W"
			case arm64asm.AddrPostIndex, arm64asm.AddrPostReg:
				decoded.Op += ".P"
			}
		}
	}
	// GoSyntax renders a Systemreg as an integer. Keep the architectural
	// register name so the named lowering also handles raw NZCV accesses.
	for _, operand := range inst.Args {
		if sys, ok := operand.(arm64asm.Systemreg); ok {
			idx := 0
			if decoded.Op == "MSR" {
				idx = 1
			}
			if (decoded.Op == "MRS" || decoded.Op == "MSR") && len(decoded.Args) == 2 {
				name := sys.String()
				if name == "S3_3_C4_C2_0" {
					name = "NZCV"
				}
				decoded.Args[idx] = asm.Operand{Kind: asm.OpIdent, Ident: name}
			}
		}
	}
	decoded.DecodedFromRaw = true
	return decoded, true
}
