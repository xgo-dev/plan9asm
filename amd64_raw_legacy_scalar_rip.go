package plan9asm

import (
	"fmt"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

// These Go legacy SSE scalar families read a fixed-width RIP-relative source
// and update only a vector register or flags. A source-local constant can be
// materialized without losing an in-place memory write or relocation.
var x86RawLegacyScalarReadOps = map[Op]bool{
	"MOVL": true, "MOVQ": true,
	"UCOMISD": true, "UCOMISS": true, "COMISD": true, "COMISS": true,
	"CMPSS": true, "CMPSD": true,
	"ADDSS": true, "ADDSD": true, "SUBSS": true, "SUBSD": true,
	"MULSS": true, "MULSD": true, "DIVSS": true, "DIVSD": true,
	"MINSS": true, "MINSD": true, "MAXSS": true, "MAXSD": true,
	"SQRTSS": true, "SQRTSD": true,
}

func decodeX86RawLegacyScalarRIPData(
	code []byte, offset int, inst x86asm.Inst, syntax string,
) (Instr, x86RawLiteralRange, bool, error) {
	if inst.Mode != 64 || inst.AddrSize != 64 || inst.PCRel != 4 ||
		inst.MemBytes != 4 && inst.MemBytes != 8 {
		return Instr{}, x86RawLiteralRange{}, false, nil
	}
	op := Op(strings.Fields(syntax)[0])
	if !x86RawLegacyScalarReadOps[op] {
		return Instr{}, x86RawLiteralRange{}, false, nil
	}
	if _, ok := inst.Args[0].(x86asm.Reg); !ok {
		return Instr{}, x86RawLiteralRange{}, false, nil
	}
	mem, ok := inst.Args[1].(x86asm.Mem)
	if !ok || mem.Base != x86asm.RIP {
		return Instr{}, x86RawLiteralRange{}, false, nil
	}
	if len(code) <= offset || code[offset] == 0x64 || code[offset] == 0x65 || code[offset] == 0x67 {
		return Instr{}, x86RawLiteralRange{}, false, nil
	}
	modRMIndex := offset + inst.PCRelOff - 1
	if modRMIndex < offset || modRMIndex >= len(code) || code[modRMIndex]&0xc7 != 0x05 {
		return Instr{}, x86RawLiteralRange{}, false, nil
	}
	trailing := inst.Len - inst.PCRelOff - inst.PCRel
	if trailing != 0 && (op != "CMPSS" && op != "CMPSD" || trailing != 1) {
		return Instr{}, x86RawLiteralRange{}, false, nil
	}
	patched, data, literal, err := x86RawRIPBytesWithSuffix(code, offset, modRMIndex, inst.MemBytes, trailing)
	if err != nil {
		return Instr{}, x86RawLiteralRange{}, true, err
	}
	physical, err := x86asm.Decode(patched, 64)
	if err != nil || physical.Len != len(patched) {
		return Instr{}, x86RawLiteralRange{}, true, fmt.Errorf("patched legacy scalar encoding is invalid: %v", err)
	}
	patchedSyntax, err := decodedX86GoSyntax(physical, patched)
	if err != nil {
		return Instr{}, x86RawLiteralRange{}, true, err
	}
	instrs, err := parseDecodedX86Instruction(patchedSyntax)
	if err != nil || len(instrs) != 1 || len(instrs[0].Args) < 2 || instrs[0].Args[0].Kind != OpMem {
		return Instr{}, x86RawLiteralRange{}, true, fmt.Errorf("patched legacy scalar instruction %q has no memory source: %v", patchedSyntax, err)
	}
	setX86RawRIPDataOperand(&instrs[0], 0, data)
	return instrs[0], literal, true, nil
}
