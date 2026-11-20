package plan9asm

import (
	"fmt"
	"strings"
)

// A VSIB form describes physical operands, not initialized values, backing
// storage or caller authority. Prefetch has no data operand or result width.
type x86VSIBForm struct {
	opcode                  Op
	spec                    amd64GatherSpec
	memory, data, mask      Operand
	indexBytes, dataBytes   int
	evex, scatter, prefetch bool
}

func x86VSIBProperties(ins Instr, arch string) (x86VSIBForm, bool, error) {
	name, _, suffix := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	f := x86VSIBForm{opcode: Op(name)}
	if spec, ok := amd64GatherSpecs[f.opcode]; ok {
		f.spec = spec
	} else if spec, ok := amd64ScatterSpecs[name]; ok {
		f.spec, f.evex, f.scatter = spec, true, true
	} else if spec, ok := amd64VSIBPrefetchSpecs[f.opcode]; ok {
		f.spec = amd64GatherSpec{elemBits: spec.elemBits, indexBits: spec.indexBits}
		f.evex, f.prefetch = true, true
		f.scatter, f.indexBytes = spec.direction == amd64VSIBPrefetchScatter, spec.indexBytes
	} else {
		return f, false, nil
	}
	op := f.opcode
	if suffix {
		if f.scatter && !f.prefetch {
			return f, true, fmt.Errorf("amd64 %s has no suffixes in its Go 1.27 table: %q", op, ins.Raw)
		}
		return f, true, fmt.Errorf("amd64 %s does not accept instruction suffixes: %q", op, ins.Raw)
	}
	if f.prefetch {
		if len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpMem {
			return f, true, fmt.Errorf("amd64 %s expects K1..K7 and VSIB memory: %q", op, ins.Raw)
		}
		f.mask, f.memory = ins.Args[0], ins.Args[1]
		maskIndex, ok := amd64ParseKReg(f.mask.Reg)
		if !ok || maskIndex == 0 {
			return f, true, fmt.Errorf("amd64 %s requires K1..K7: %q", op, ins.Raw)
		}
		if amd64VectorByteWidth(f.memory.Mem.Index) != f.indexBytes {
			return f, true, fmt.Errorf("amd64 %s has the wrong VSIB index width: %q", op, ins.Raw)
		}
	} else if f.scatter {
		if len(ins.Args) != 3 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpMem {
			return f, true, fmt.Errorf("amd64 %s expects data vector, K1-K7, VSIB memory: %q", op, ins.Raw)
		}
		f.data, f.mask, f.memory = ins.Args[0], ins.Args[1], ins.Args[2]
		maskIndex, ok := amd64ParseKReg(f.mask.Reg)
		if !ok || maskIndex == 0 {
			return f, true, fmt.Errorf("amd64 %s requires K1-K7: %q", op, ins.Raw)
		}
	} else {
		if len(ins.Args) != 3 {
			return f, true, fmt.Errorf("amd64 %s expects exactly three operands from its Go 1.27 gather table: %q", op, ins.Raw)
		}
		f.evex = ins.Args[0].Kind == OpMem
		f.mask, f.memory, f.data = ins.Args[0], ins.Args[1], ins.Args[2]
		if f.evex {
			f.memory, f.mask = ins.Args[0], ins.Args[1]
		}
		if f.memory.Kind != OpMem || f.data.Kind != OpReg {
			return f, true, fmt.Errorf("amd64 %s expects vector-mask,memory,vector or memory,K-mask,vector: %q", op, ins.Raw)
		}
	}
	if !f.prefetch {
		f.dataBytes, f.indexBytes = amd64VectorByteWidth(f.data.Reg), amd64VectorByteWidth(f.memory.Mem.Index)
		if f.dataBytes == 0 || f.indexBytes == 0 || !amd64GatherTableAllows(f.spec.table, f.evex, f.dataBytes, f.indexBytes) {
			if f.scatter {
				return f, true, fmt.Errorf("amd64 %s data/index widths are outside its Go 1.27 table: %q", op, ins.Raw)
			}
			return f, true, fmt.Errorf("amd64 %s vector widths are outside its Go 1.27 gather table: %q", op, ins.Raw)
		}
	}
	if err := validateX86VSIBMemory(f.memory.Mem, f.indexBytes, arch); err != nil {
		return f, true, fmt.Errorf("amd64 %s invalid VSIB memory: %q: %w", op, ins.Raw, err)
	}
	dataIndex := 0
	if !f.prefetch {
		var ok bool
		dataIndex, ok = amd64GatherRegisterIndex(f.data.Reg, f.dataBytes, f.evex, arch, false)
		if !ok {
			if f.scatter {
				return f, true, fmt.Errorf("amd64 %s data register is outside its Go 1.27 class: %q", op, ins.Raw)
			}
			return f, true, fmt.Errorf("amd64 %s destination is outside its Go 1.27 register class: %q", op, ins.Raw)
		}
	}
	indexIndex, ok := amd64GatherRegisterIndex(f.memory.Mem.Index, f.indexBytes, f.evex, arch, true)
	if !ok {
		if f.scatter && !f.prefetch {
			return f, true, fmt.Errorf("amd64 %s VSIB index is outside its Go 1.27 class: %q", op, ins.Raw)
		}
		return f, true, fmt.Errorf("amd64 %s VSIB index is outside its Go 1.27 register class: %q", op, ins.Raw)
	}
	if !f.scatter && !f.prefetch {
		if dataIndex == indexIndex {
			return f, true, fmt.Errorf("amd64 %s index and destination registers must be distinct: %q", op, ins.Raw)
		}
		if f.evex {
			maskIndex, ok := amd64ParseKReg(f.mask.Reg)
			if f.mask.Kind != OpReg || !ok || maskIndex == 0 {
				return f, true, fmt.Errorf("amd64 %s EVEX form requires K1..K7: %q", op, ins.Raw)
			}
		} else {
			maskIndex, ok := amd64GatherRegisterIndex(f.mask.Reg, f.dataBytes, false, arch, false)
			if f.mask.Kind != OpReg || !ok || amd64VectorByteWidth(f.mask.Reg) != f.dataBytes {
				return f, true, fmt.Errorf("amd64 %s VEX form requires a destination-width vector mask: %q", op, ins.Raw)
			}
			if maskIndex == indexIndex || maskIndex == dataIndex {
				return f, true, fmt.Errorf("amd64 %s mask, index, and destination registers must be distinct: %q", op, ins.Raw)
			}
		}
	}
	return f, true, nil
}

func validateX86VSIBMemory(memory MemRef, indexBytes int, arch string) error {
	if memory.Index == "" || amd64VectorByteWidth(memory.Index) != indexBytes {
		return fmt.Errorf("expected a VSIB vector index")
	}
	if memory.Scale != 0 && memory.Scale != 1 && memory.Scale != 2 && memory.Scale != 4 && memory.Scale != 8 {
		return fmt.Errorf("VSIB scale must be 1, 2, 4, or 8")
	}
	if memory.Sym != "" {
		return fmt.Errorf("Go's x86 assembler does not accept an SB base with VSIB")
	}
	if memory.Base != "" && !isX86YrlRegisterForArch(memory.Base, arch) {
		return fmt.Errorf("VSIB base is not a GP register for %s", arch)
	}
	if memory.Segment != "" && memory.Segment != FS && memory.Segment != GS {
		return fmt.Errorf("unsupported VSIB segment %s", memory.Segment)
	}
	return nil
}
