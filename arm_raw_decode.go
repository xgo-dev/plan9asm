package plan9asm

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/arch/arm/armasm"
)

// decodeARMRawWordInstruction recovers the Go assembler spelling for an ARM
// WORD using Go's architecture decoder. The returned instruction is not
// considered supported until the ordinary ARM semantic lowerer accepts it.
func decodeARMRawWordInstruction(ins Instr) (Instr, error) {
	if len(ins.Args) != 1 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
		return Instr{}, fmt.Errorf("arm WORD expects exactly one resolved integer constant: %q", ins.Raw)
	}
	word := uint32(ins.Args[0].Imm)
	if decoded, ok, err := decodeARMRawCoprocessorTransfer(word, ins.Raw); ok {
		if err != nil {
			return Instr{}, err
		}
		return decoded, nil
	}
	// A32 UDF has 16 immediate bits split around its fixed low nibble. Go's
	// runtime uses UDF #16 as a GDB-recognized breakpoint; external assembly
	// also uses UDF #0 as a terminating tail guard. x/arch does not decode
	// these forms, but all immediates share Go's operand-free UNDEF semantics.
	if word&0xfff000f0 == 0xe7f000f0 {
		return Instr{Op: "UNDEF", Raw: fmt.Sprintf("UNDEF /* decoded from %s */", ins.Raw)}, nil
	}
	var code [4]byte
	binary.LittleEndian.PutUint32(code[:], word)
	decoded, err := armasm.Decode(code[:], armasm.ModeARM)
	if err != nil {
		return Instr{}, fmt.Errorf("decode ARM WORD %#08x: %w", word, err)
	}
	for _, arg := range decoded.Args {
		if arg == nil {
			break
		}
		if _, ok := arg.(armasm.PCRel); ok {
			return Instr{}, fmt.Errorf("ARM WORD %#08x is PC-relative and cannot be mapped safely to source labels: %q", word, ins.Raw)
		}
	}
	syntax := armasm.GoSyntax(decoded, 0, nil, nil)
	if op, rest, ok := strings.Cut(syntax, " "); ok && strings.HasPrefix(op, "BLX") {
		condition := strings.TrimPrefix(op, "BLX")
		if condition != "" && !strings.HasPrefix(condition, ".") {
			condition = "." + condition
		}
		syntax = "BL" + condition + " (" + rest + ")"
	}
	// x/arch uses ARM architectural brackets for memory operands, while the
	// Go assembler source grammar spells the same operand with parentheses.
	// Convert them before parsing; otherwise [SP] is mistaken for a register
	// list and raw LDREXD/STREXD forms lose their memory operand class.
	syntax = strings.NewReplacer("[", "(", "]", ")").Replace(syntax)
	file, err := Parse(ArchARM, "TEXT decoded(SB), $0-0\n"+syntax+"\n")
	if err != nil {
		return Instr{}, fmt.Errorf("parse decoded ARM WORD %#08x as %q: %w", word, syntax, err)
	}
	if len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) != 2 {
		return Instr{}, fmt.Errorf("decoded ARM WORD %#08x produced an invalid instruction sequence %q", word, syntax)
	}
	result := file.Funcs[0].Instrs[1]
	result.Raw = fmt.Sprintf("%s /* decoded from %s */", result.Raw, ins.Raw)
	return result, nil
}

// decodeARMRawCoprocessorTransfer covers the A32 MRC/MCR register-transfer
// encodings that Go assembly commonly emits as WORD (for example CP15 ID
// reads). x/arch/arm intentionally does not decode coprocessor transfers, so
// recover their complete operand fields here before falling back to it.
func decodeARMRawCoprocessorTransfer(word uint32, raw string) (Instr, bool, error) {
	if word&0x0f000010 != 0x0e000010 {
		return Instr{}, false, nil
	}
	conditionNames := [...]string{
		"EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC",
		"HI", "LS", "GE", "LT", "GT", "LE", "", "",
	}
	condition := conditionNames[word>>28&15]
	if word>>28&15 == 15 {
		return Instr{}, false, nil
	}
	op := "MCR"
	if word>>20&1 != 0 {
		op = "MRC"
	}
	if condition != "" {
		op += "." + condition
	}
	part := func(value uint32) string { return fmt.Sprintf("$%d", value) }
	syntax := fmt.Sprintf("%s %s, %s, R%d, %s, %s, %s",
		op,
		part(word>>8&15),
		part(word>>21&7),
		word>>12&15,
		part(word>>16&15),
		part(word>>0&15),
		part(word>>5&7),
	)
	file, err := Parse(ArchARM, "TEXT decoded(SB), $0-0\n"+syntax+"\n")
	if err != nil {
		return Instr{}, true, fmt.Errorf("parse decoded ARM coprocessor WORD %#08x as %q: %w", word, syntax, err)
	}
	if len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) != 2 {
		return Instr{}, true, fmt.Errorf("decoded ARM coprocessor WORD %#08x produced an invalid instruction sequence %q", word, syntax)
	}
	result := file.Funcs[0].Instrs[1]
	result.Raw = fmt.Sprintf("%s /* decoded from %s */", result.Raw, raw)
	return result, true, nil
}
