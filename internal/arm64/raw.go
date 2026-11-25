package arm64

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
	"golang.org/x/arch/arm64/arm64asm"
)

// DecodeRawWord decodes a 32-bit little-endian AArch64 instruction word into a
// canonical Plan 9 asm.Instr using golang.org/x/arch/arm64/arm64asm.
// This scales to the full AArch64 ISA (NEON, Crypto, LSE, SVE, system) without
// hand-maintaining bit-slicing decoders for each WORD directive.
func DecodeRawWord(word uint32) (asm.Instr, bool) {
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
	decoded.DecodedFromRaw = true
	return decoded, true
}
