package plan9asm

import "fmt"

// cmd/asm accepts extended GP address spellings in mode32, but their source
// names do not supply physical 386 registers. Keep that missing role distinct
// from an invalid operand format; never create numerical/address facts or
// silently allocate an AMD64 register while translating a 386 function.
func x86VectorValueMemoryInput(ins Instr, arch string) (Instr, bool) {
	if arch != "386" {
		return ins, false
	}
	local, contextual := ins, false
	for index, operand := range ins.Args {
		// Go's mode32 SIB encoder rejects extended base/index registers;
		// only the ordinary non-SIB base path accepts these spellings.
		if operand.Kind != OpMem || operand.Mem.Index != "" || operand.Mem.Scale != 0 ||
			operand.Mem.Base == "R12" || x86PackedShiftMemoryValid(operand, arch) {
			continue
		}
		shape := operand
		if shape.Mem.Off == int64(uint32(shape.Mem.Off)) {
			shape.Mem.Off = int64(int32(shape.Mem.Off))
		}
		if x86PackedShiftMemoryValid(shape, "amd64") {
			if !contextual {
				local.Args = append([]Operand(nil), ins.Args...)
			}
			operand.Mem.Base = AX
			local.Args[index], contextual = operand, true
		}
	}
	return local, contextual
}

func x86VectorValueMemoryContext(ins Instr) error {
	return fmt.Errorf("%w: 386 %s address has no bound physical extended-GP role: %q", ErrProbeNeedsContext, ins.Op, ins.Raw)
}
