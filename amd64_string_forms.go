package plan9asm

import (
	"fmt"
	"strings"
)

type x86StringSpec struct {
	kind  string
	typ   LLVMType
	width int
}

var x86StringSpecs = map[Op]x86StringSpec{
	"MOVSB": {kind: "movs", typ: I8, width: 1},
	"MOVSW": {kind: "movs", typ: I16, width: 2},
	"MOVSL": {kind: "movs", typ: I32, width: 4},
	"MOVSQ": {kind: "movs", typ: I64, width: 8},
	"STOSB": {kind: "stos", typ: I8, width: 1},
	"STOSW": {kind: "stos", typ: I16, width: 2},
	"STOSL": {kind: "stos", typ: I32, width: 4},
	"STOSQ": {kind: "stos", typ: I64, width: 8},
	"SCASB": {kind: "scas", typ: I8, width: 1},
	"SCASW": {kind: "scas", typ: I16, width: 2},
	"SCASL": {kind: "scas", typ: I32, width: 4},
	"SCASQ": {kind: "scas", typ: I64, width: 8},
	"CMPSB": {kind: "cmps", typ: I8, width: 1},
	"CMPSW": {kind: "cmps", typ: I16, width: 2},
	"CMPSL": {kind: "cmps", typ: I32, width: 4},
	"CMPSQ": {kind: "cmps", typ: I64, width: 8},
	"LODSB": {kind: "lods", typ: I8, width: 1},
	"LODSW": {kind: "lods", typ: I16, width: 2},
	"LODSL": {kind: "lods", typ: I32, width: 4},
	"LODSQ": {kind: "lods", typ: I64, width: 8},
}

// This name-only query is used by dispatch and helper discovery. A recognized
// spelling alone does not validate its operands or establish an effect.
func x86StringProperties(op Op) (kind string, typ LLVMType, width int, ok bool) {
	spec, ok := x86StringSpecs[Op(normalizeInstructionOpcode(op))]
	if !ok {
		return "", "", 0, false
	}
	return spec.kind, spec.typ, spec.width, true
}

// x86StringInstructionProperties validates Go's complete twenty ynone string
// rows. REP/REPN remain independently dispatched prefixes, not string bodies
// or inert effects. This grammar grants no memory, entry or FLAGS knowledge.
func x86StringInstructionProperties(ins Instr, arch string) (x86StringSpec, bool, error) {
	// Match lowerInstr's existing case normalization, deriving the only head
	// from the actual instruction. Raw remains diagnostic source text only.
	op := Op(strings.ToUpper(string(ins.Op)))
	kind, typ, width, known := x86StringProperties(op)
	if !known {
		return x86StringSpec{}, false, nil
	}
	if op != Op(normalizeInstructionOpcode(op)) {
		return x86StringSpec{}, true, fmt.Errorf("%s %s does not accept instruction suffixes: %q", arch, op, ins.Raw)
	}

	spec := x86StringSpec{kind: kind, typ: typ, width: width}
	if arch != "386" && arch != "amd64" {
		return spec, true, fmt.Errorf("%s %s requires an x86 source mode: %q", arch, op, ins.Raw)
	}
	if arch == "386" && typ == I64 {
		return spec, true, fmt.Errorf("386 %s is not in the Go assembler's 32-bit instruction table", op)
	}
	if len(ins.Args) != 0 {
		return spec, true, fmt.Errorf("%s %s takes no operands: %q", arch, op, ins.Raw)
	}
	return spec, true, nil
}
