package plan9asm

import (
	"fmt"
	"strings"
)

type x86InsertExtractSpec struct {
	insert, scalar, vex, legacy bool
	chunk, laneBits             int
	allowY, allowZ              bool
}

var x86InsertExtractSpecs = map[Op]x86InsertExtractSpec{
	"EXTRACTPS":     {scalar: true, legacy: true, chunk: 4, laneBits: 32},
	"INSERTPS":      {insert: true, scalar: true, legacy: true, chunk: 4, laneBits: 32},
	"VEXTRACTF128":  {vex: true, chunk: 16, laneBits: 8, allowY: true},
	"VEXTRACTI128":  {vex: true, chunk: 16, laneBits: 8, allowY: true},
	"VEXTRACTF32X4": {chunk: 16, laneBits: 32, allowY: true, allowZ: true},
	"VEXTRACTI32X4": {chunk: 16, laneBits: 32, allowY: true, allowZ: true},
	"VEXTRACTF64X2": {chunk: 16, laneBits: 64, allowY: true, allowZ: true},
	"VEXTRACTI64X2": {chunk: 16, laneBits: 64, allowY: true, allowZ: true},
	"VEXTRACTF32X8": {chunk: 32, laneBits: 32, allowZ: true},
	"VEXTRACTI32X8": {chunk: 32, laneBits: 32, allowZ: true},
	"VEXTRACTF64X4": {chunk: 32, laneBits: 64, allowZ: true},
	"VEXTRACTI64X4": {chunk: 32, laneBits: 64, allowZ: true},
	"VINSERTF128":   {insert: true, vex: true, chunk: 16, laneBits: 8, allowY: true},
	"VINSERTI128":   {insert: true, vex: true, chunk: 16, laneBits: 8, allowY: true},
	"VINSERTF32X4":  {insert: true, chunk: 16, laneBits: 32, allowY: true, allowZ: true},
	"VINSERTI32X4":  {insert: true, chunk: 16, laneBits: 32, allowY: true, allowZ: true},
	"VINSERTF64X2":  {insert: true, chunk: 16, laneBits: 64, allowY: true, allowZ: true},
	"VINSERTI64X2":  {insert: true, chunk: 16, laneBits: 64, allowY: true, allowZ: true},
	"VINSERTF32X8":  {insert: true, chunk: 32, laneBits: 32, allowZ: true},
	"VINSERTI32X8":  {insert: true, chunk: 32, laneBits: 32, allowZ: true},
	"VINSERTF64X4":  {insert: true, chunk: 32, laneBits: 64, allowZ: true},
	"VINSERTI64X4":  {insert: true, chunk: 32, laneBits: 64, allowZ: true},
	"VEXTRACTPS":    {scalar: true, chunk: 4, laneBits: 32},
	"VINSERTPS":     {insert: true, scalar: true, chunk: 4, laneBits: 32},
}

type x86InsertExtractForm struct {
	spec                                    x86InsertExtractSpec
	source, base, destination, mask, memory int
	width, output, offset                   int
	immediate                               byte
	zeroing, memoryWrite                    bool
}

func (form x86InsertExtractForm) undefinedOpcode() bool {
	// Go emits EVEX.z for a memory destination, but the ISA makes that
	// encoding terminal #UD rather than a zeroing store.
	return form.zeroing && form.memoryWrite
}

// Block transfers read the inserted/selected chunk and, for insertion, only
// the retained base bytes. This describes numerical inputs, not memory extent.
func (form x86InsertExtractForm) blockInputBytes() (source, base uint64) {
	chunk := x86CallerVectorByteMask(int64(form.spec.chunk))
	selected := chunk << uint(form.offset)
	if form.spec.insert {
		return chunk, x86CallerVectorByteMask(int64(form.width)) &^ selected
	}
	return selected, 0
}

func x86InsertExtractProperties(ins Instr, goarch string) (x86InsertExtractForm, bool, error) {
	op, suffix, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, recognized := x86InsertExtractSpecs[Op(op)]
	if !recognized {
		return x86InsertExtractForm{}, false, nil
	}
	f := x86InsertExtractForm{spec: spec, source: 1, base: -1, destination: len(ins.Args) - 1, mask: -1, memory: -1}
	fail := func() (x86InsertExtractForm, bool, error) {
		return f, true, fmt.Errorf("%s %s operands/suffix outside Go insert/extract grammar: %q", goarch, ins.Op, ins.Raw)
	}
	count := 3
	if spec.insert {
		count, f.base = 4, 2
		if spec.legacy {
			count = 3
		}
	}
	// Go's 386 frontend cannot represent a four-operand named insertion.
	// A validated physical VINSERTPS has its independent mode32 register and
	// encoding checks; a textual Raw annotation cannot create that identity.
	physicalScalarInsert := spec.insert && spec.scalar && ins.x86Encoded
	if goarch != "amd64" && goarch != "386" || spec.insert && !spec.legacy && goarch == "386" && !physicalScalarInsert || len(ins.Args) != count && len(ins.Args) != count+1 ||
		len(ins.Args) == count+1 && (spec.vex || spec.scalar) || dotted && (suffix != "Z" || spec.vex || spec.scalar) ||
		ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
		return fail()
	}
	if len(ins.Args) == count+1 {
		f.mask = count - 1
		if !amd64NonzeroKOperand(ins.Args[f.mask]) {
			return fail()
		}
	}
	if goarch == "386" && f.mask >= 0 {
		return fail()
	}
	f.zeroing = dotted
	if f.zeroing && f.mask < 0 {
		return fail()
	}
	minimum := int64(0)
	if !spec.insert && spec.vex {
		minimum = -128
	}
	if spec.scalar && !spec.insert && !spec.legacy {
		index, valid := amd64VectorRegisterIndex(ins.Args[1].Reg, 16)
		if valid && index < 16 {
			minimum = -128
		}
	}
	maximum := int64(255)
	if spec.legacy && !spec.insert {
		maximum = 3
	}
	if ins.Args[0].Imm < minimum || ins.Args[0].Imm > maximum {
		return fail()
	}
	f.immediate = byte(ins.Args[0].Imm)
	f.width, f.output = 16, spec.chunk
	large := ins.Args[f.source]
	if spec.insert {
		large = ins.Args[f.base]
	}
	if !spec.scalar {
		f.width = amd64VectorByteWidth(large.Reg)
		if large.Kind != OpReg || !(f.width == 32 && spec.allowY || f.width == 64 && spec.allowZ) {
			return fail()
		}
		f.offset = (int(f.immediate) & (f.width/spec.chunk - 1)) * spec.chunk
	} else {
		f.offset = int(f.immediate&3) * 4
	}
	if spec.insert {
		f.output = f.width
	}
	highMode32 := Reg("")
	register := func(arg Operand, width int) bool {
		index, valid := amd64VectorRegisterIndex(arg.Reg, width)
		limit := 32
		if spec.vex || spec.legacy {
			limit = 16
		}
		if goarch == "386" && spec.legacy {
			limit = 8
		}
		if arg.Kind != OpReg || !valid || index >= limit {
			return false
		}
		if goarch == "386" && index >= 8 {
			highMode32 = arg.Reg
		}
		return true
	}
	if !register(large, f.width) {
		return fail()
	}
	if spec.insert && !register(ins.Args[f.destination], f.output) {
		return fail()
	}
	transfer := ins.Args[f.destination]
	if spec.insert {
		transfer = ins.Args[f.source]
	}
	if isAMD64MemoryOperand(transfer) {
		f.memory, f.memoryWrite = f.destination, !spec.insert
		if spec.insert {
			f.memory = f.source
		}
		if transfer.Kind == OpSym {
			_, absolute := parseInt(strings.TrimSpace(transfer.Sym))
			if strings.HasPrefix(strings.TrimSpace(transfer.Sym), "$") || !strings.HasSuffix(transfer.Sym, "(SB)") && absolute != nil {
				return fail()
			}
		}
		if transfer.Kind == OpMem && (!x86MemoryRegistersValidForArch(transfer.Mem, goarch) ||
			transfer.Mem.Index != "" && (transfer.Mem.Index == SP || transfer.Mem.Scale != 1 && transfer.Mem.Scale != 2 && transfer.Mem.Scale != 4 && transfer.Mem.Scale != 8) ||
			transfer.Mem.Off != int64(int32(transfer.Mem.Off)) && (goarch != "386" || transfer.Mem.Off != int64(uint32(transfer.Mem.Off)))) {
			return fail()
		}
	} else if !spec.insert && spec.scalar {
		if transfer.Kind != OpReg || !isX86YrlRegisterForArch(transfer.Reg, goarch) {
			return fail()
		}
	} else {
		width := spec.chunk
		if spec.scalar {
			width = 16
		}
		if !register(transfer, width) {
			return fail()
		}
	}
	if highMode32 != "" {
		// Go can encode named VEX/EVEX high SIMD registers in mode32.
		// Its syntax/object acceptance does not supply physical register
		// identities which the independent mode32 raw decoder rejects.
		return f, true, fmt.Errorf("%w: 386 insert/extract register %s has no proved physical mode32 binding", ErrProbeNeedsContext, highMode32)
	}
	return f, true, nil
}

func (c *amd64Ctx) bindInsertExtractForm(op Op, ins Instr) (Instr, x86InsertExtractForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := x86InsertExtractSpecs[Op(base)]; !known {
		return ins, x86InsertExtractForm{}, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(op), string(ins.Op)) {
		return ins, x86InsertExtractForm{}, true, fmt.Errorf("insert/extract dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op
	f, known, err := x86InsertExtractProperties(ins, c.goarch)
	if err == nil && !f.undefinedOpcode() && f.memory >= 0 && ins.Args[f.memory].Kind == OpFP {
		err = c.validateFPVectorSpan(ins.Args[f.memory].FPOffset, f.spec.chunk)
	}
	return ins, f, known, err
}
