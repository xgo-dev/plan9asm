package plan9asm

import (
	"fmt"
	"strings"
)

// Scalar lane transfers select bytes, not an entire initialized vector. The
// encoding grammar grants no caller region, native backing, or pointee facts.
type x86ScalarLaneForm struct {
	insert, legacy                  bool
	bits, source, base, destination int
	memory, offset, gpBits          int
	transferReg                     Reg
}

func x86ScalarLaneProperties(ins Instr, arch string) (x86ScalarLaneForm, bool, error) {
	op, _, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	f := x86ScalarLaneForm{source: 1, base: -1, destination: 2, memory: -1}
	allowM := false
	if spec, known := amd64PackedIntegerInsertSpecs[op]; known {
		f.insert, f.legacy, f.bits, f.base = true, spec.legacy, spec.laneBits, 2
		allowM = spec.legacy && spec.laneBits != 16
		if !spec.legacy {
			f.destination = 3
		}
	} else if spec, known := amd64PackedScalarExtractSpecs[Op(op)]; known && op != "EXTRACTPS" && op != "VEXTRACTPS" {
		f.legacy, f.bits, allowM = !spec.vector, spec.bits, spec.allowMMX
	} else {
		return f, false, nil
	}
	fail := func() (x86ScalarLaneForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside complete Go scalar-lane grammar: %q", arch, ins.Op, ins.Raw)
	}
	if arch == "" {
		arch = "amd64"
	}
	if arch != "amd64" && arch != "386" || dotted || len(ins.Args) != f.destination+1 ||
		ins.Args[0].Kind != OpImm || ins.Args[0].ImmIsFloat || ins.Args[0].ImmRaw != "" ||
		arch == "386" && (f.legacy && f.bits == 64 || f.insert && !f.legacy) {
		return fail()
	}
	if arch == "386" && !f.insert && !f.legacy && f.bits == 64 {
		// Preserve the original Go Q/W1 source identity, but use the actual
		// non-64-bit WIG operation: imm[1:0], r32/m32, not a qword followed
		// by GP truncation. Memory writes and all byte consumers agree.
		f.bits = 32
	}
	vectorIndex, high := 0, Reg("")
	xreg := func(arg Operand) bool {
		index, valid := amd64ParseXReg(arg.Reg)
		limit := 32
		if f.legacy {
			limit = 16
			if arch == "386" {
				limit = 8
			}
		}
		if arg.Kind != OpReg || !valid || index >= limit {
			return false
		}
		vectorIndex = index
		if arch == "386" && index >= 8 {
			high = arg.Reg
		}
		return true
	}
	transfer := ins.Args[f.destination]
	if f.insert {
		if !xreg(ins.Args[f.base]) || !xreg(ins.Args[f.destination]) {
			return fail()
		}
		transfer = ins.Args[f.source]
	} else if !xreg(ins.Args[f.source]) {
		return fail()
	}
	minimum := int64(0)
	if !f.insert && !f.legacy && vectorIndex < 16 {
		minimum = -128 // VEX Yi8 and Yu8 rows; EVEX only Yu8.
	}
	immediate := ins.Args[0].Imm
	if arch == "386" && !ins.x86Encoded {
		immediate = int64(int32(immediate)) // Stock Go oclass TYPE_CONST.
	}
	if immediate < minimum || immediate > 255 {
		return fail()
	}
	f.offset = (int(byte(immediate)) & (128/f.bits - 1)) * (f.bits / 8)
	f.gpBits = f.bits
	if !f.insert && f.gpBits < 32 {
		f.gpBits = 32
	}
	if isAMD64MemoryOperand(transfer) && x86PackedShiftMemoryValid(transfer, arch) {
		f.memory = f.destination
		if f.insert {
			f.memory = f.source
		}
	} else if transfer.Kind == OpReg && isX86YrlRegisterForArch(transfer.Reg, arch) {
		f.transferReg = transfer.Reg
	} else if index, valid := amd64ParseMReg(transfer.Reg); transfer.Kind == OpReg && valid && allowM && !ins.x86Encoded {
		// Go's legacy Ymm here is a ModRM GP-number spelling, not an MMX
		// bank read/write. Physical decoded instructions already name GP.
		f.transferReg = amd64MMXEncodingGP(index)
	} else {
		return fail()
	}
	if high != "" {
		return f, true, fmt.Errorf("%w: 386 scalar-lane %s lacks a physical high-bank identity", ErrProbeNeedsContext, high)
	}
	return f, true, nil
}

func (c *amd64Ctx) bindScalarLaneForm(op Op, ins Instr) (Instr, x86ScalarLaneForm, bool, error) {
	if ins.Op != "" && !strings.EqualFold(string(op), string(ins.Op)) {
		return ins, x86ScalarLaneForm{}, true, fmt.Errorf("scalar-lane dispatch/source mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op
	f, known, err := x86ScalarLaneProperties(ins, c.goarch)
	if err == nil && known && f.memory >= 0 && ins.Args[f.memory].Kind == OpFP {
		err = c.scalarLaneFPSpan(ins.Args[f.memory].FPOffset, f.bits)
	}
	if err == nil && known {
		for _, slot := range c.fpResults {
			if slot.Type == I8 || slot.Type == I16 || slot.Type == I32 || slot.Type == I64 {
				// Extraction into a GP followed by an ordinary FP store must
				// not evade the same original whole-source byte proof.
				err = c.scalarFPResultInitialized()
				break
			}
		}
	}
	return ins, f, known, err
}

func validateX86ScalarLaneFile(file *File, arch string) error {
	if file == nil || file.Arch != ArchAMD64 {
		return nil
	}
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			if _, known, err := x86ScalarLaneProperties(ins, arch); known && err != nil {
				return fmt.Errorf("%s: %w", fn.Sym, err)
			}
		}
	}
	return nil
}

// Both caller and result consumers use this same selected-byte writeback.
// Legacy keeps the wider alias; VEX/EVEX clears all bytes above X128.
func x86ScalarLaneInsertKnown(f x86ScalarLaneForm, base, source, old uint64) uint64 {
	low := x86CallerVectorByteMask(int64(f.bits / 8))
	lane := low << uint(f.offset)
	known := base&0xffff&^lane | (source&low)<<uint(f.offset)
	upper := ^uint64(0xffff)
	if f.legacy {
		upper &= old
	}
	return upper | known
}
