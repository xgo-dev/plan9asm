package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedIntegerMinMaxSpec struct {
	laneBits  int
	signed    bool
	minimum   bool
	broadcast bool
	mapNumber int
	opcode    int
}

// The twelve legacy and sixteen VEX/EVEX members share typed operand and
// numerical rules. Legacy retains its RMW/upper aliases and original m128
// opcode; only VEX/EVEX D/Q has scalar-memory broadcast.
func (c *amd64Ctx) lowerPackedIntegerMinMax(op Op, ins Instr) (ok bool, terminated bool, err error) {
	form, known, err := x86IntegerMinMaxProperties(op, ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if err := c.validateConflictFunnelMemory(ins, form.x86PackedBinaryForm); err != nil {
		return true, false, err
	}
	first := ins.Args[form.first]
	if form.legacy && form.memory >= 0 &&
		(first.Kind == OpFP || first.Kind == OpMem && !x86OrdinaryNativeMemoryOperand(first, c.goarch) ||
			!x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple)) {
		return true, false, fmt.Errorf("%w: legacy integer min/max m128 needs its original native storage/target", ErrProbeNeedsContext)
	}
	spec := form.spec
	predicate := "ult"
	if spec.signed {
		predicate = "slt"
	}
	if !spec.minimum {
		predicate = strings.Replace(predicate, "lt", "gt", 1)
	}
	legacyMnemonic := ""
	if form.legacy && form.memory >= 0 {
		legacyMnemonic = strings.ToLower(string(op))
	}
	err = c.emitPackedBinaryE4(ins, form.x86PackedBinaryForm, spec.laneBits, legacyMnemonic,
		func(lanes, bits int, first, second string) string {
			compared, computed := c.newTmp(), c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = icmp %s <%d x i%d> %s, %s\n", compared, predicate, lanes, bits, second, first)
			fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, <%d x i%d> %s, <%d x i%d> %s\n", computed, lanes, compared, lanes, bits, second, lanes, bits, first)
			return "%" + computed
		})
	return true, false, err
}

var amd64PackedIntegerMinMaxSpecs = map[string]amd64PackedIntegerMinMaxSpec{
	"VPMINSB": {laneBits: 8, signed: true, minimum: true, mapNumber: 2, opcode: 0x38},
	"VPMINUB": {laneBits: 8, minimum: true, mapNumber: 1, opcode: 0xda},
	"VPMAXSB": {laneBits: 8, signed: true, mapNumber: 2, opcode: 0x3c},
	"VPMAXUB": {laneBits: 8, mapNumber: 1, opcode: 0xde},
	"VPMINSW": {laneBits: 16, signed: true, minimum: true, mapNumber: 1, opcode: 0xea},
	"VPMINUW": {laneBits: 16, minimum: true, mapNumber: 2, opcode: 0x3a},
	"VPMAXSW": {laneBits: 16, signed: true, mapNumber: 1, opcode: 0xee},
	"VPMAXUW": {laneBits: 16, mapNumber: 2, opcode: 0x3e},

	"VPMINSD": {laneBits: 32, signed: true, minimum: true, broadcast: true, mapNumber: 2, opcode: 0x39},
	"VPMINUD": {laneBits: 32, minimum: true, broadcast: true, mapNumber: 2, opcode: 0x3b},
	"VPMAXSD": {laneBits: 32, signed: true, broadcast: true, mapNumber: 2, opcode: 0x3d},
	"VPMAXUD": {laneBits: 32, broadcast: true, mapNumber: 2, opcode: 0x3f},
	"VPMINSQ": {laneBits: 64, signed: true, minimum: true, broadcast: true, mapNumber: 2, opcode: 0x39},
	"VPMINUQ": {laneBits: 64, minimum: true, broadcast: true, mapNumber: 2, opcode: 0x3b},
	"VPMAXSQ": {laneBits: 64, signed: true, broadcast: true, mapNumber: 2, opcode: 0x3d},
	"VPMAXUQ": {laneBits: 64, broadcast: true, mapNumber: 2, opcode: 0x3f},
}
