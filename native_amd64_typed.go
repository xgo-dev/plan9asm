package plan9asm

import (
	"fmt"
	"strings"
)

func (e *nativeAMD64) emitTyped(out *strings.Builder, name string, bits int, args ...Operand) error {
	values := make([]string, len(args))
	for i, arg := range args {
		var err error
		values[i], err = e.operand(arg, bits)
		if err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "\t%s %s\n", name, strings.Join(values, ", "))
	return nil
}

// Only the existing typed family grammar selects a physical operation. No
// Go register facts, numerical values, FLAGS or call prototypes are invented.
func (e *nativeAMD64) typedInstruction(out *strings.Builder, ins Instr) error {
	op, args := string(ins.Op), ins.Args
	bad := func() error { return fmt.Errorf("unsupported native amd64 typed form: %q", ins.Raw) }
	if ins.Op == "ADJSP" {
		if len(args) < 1 || len(args) > 2 ||
			args[0].Kind != OpImm || args[0].ImmRaw != "" || args[0].ImmIsFloat ||
			args[0].Imm < -2147483647 || args[0].Imm > 2147483647 ||
			len(args) == 2 && (args[1].Kind != OpReg || args[1].Reg != SP) {
			return bad()
		}
		// Match obj6 ADJSP's SUB/ADD selection, including physical FLAGS.
		if args[0].Imm > 0 {
			fmt.Fprintf(out, "\tsubq $%d, %%rsp\n", args[0].Imm)
		}
		if args[0].Imm < 0 {
			fmt.Fprintf(out, "\taddq $%d, %%rsp\n", -args[0].Imm)
		}
		return nil
	}
	if f, known, err := x86LockScalarRMWProperties(ins.Op, ins, "amd64"); known {
		if err != nil {
			return err
		}
		if f.spec.unary {
			return e.emitTyped(out, strings.ToLower(op), f.spec.bits, f.destination)
		}
		return e.emitTyped(out, strings.ToLower(op), f.spec.bits, f.source, f.destination)
	}
	if f, known, err := x86ScalarCompareProperties(ins.Op, ins, "amd64"); known {
		if err != nil {
			return err
		}
		if !f.test {
			f.args[0], f.args[1] = f.args[1], f.args[0]
		}
		return e.emitTyped(out, strings.ToLower(op), f.bits, f.args[:]...)
	}
	if f, known, err := x86ScalarShiftProperties(ins.Op, ins, "amd64"); known && !f.bmi2 {
		if err != nil {
			return err
		}
		if f.count.Kind == OpReg {
			f.count.Reg = CL
		}
		count, err := e.operand(f.count, 8)
		if err != nil {
			return err
		}
		dst, err := e.operand(f.destination, f.bits)
		if err != nil {
			return err
		}
		if f.double {
			src, err := e.operand(f.source, f.bits)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "\t%sd%s %s, %s, %s\n", strings.ToLower(f.stem), strings.ToLower(op[len(op)-1:]), count, src, dst)
		} else {
			fmt.Fprintf(out, "\t%s %s, %s\n", strings.ToLower(op), count, dst)
		}
		return nil
	}
	if f, known, err := x86StackWidthProperties(ins, "amd64"); known {
		if err != nil {
			return err
		}
		if len(args) == 1 && x86SegmentRegisterOperand(args[0]) {
			name := strings.ToLower(op)
			if f.segmentNativeWidth {
				name = name[:len(name)-1] + "q"
			}
			fmt.Fprintf(out, "\t%s %%%s\n", name, strings.ToLower(string(args[0].Reg)))
			return nil
		}
		if len(args) == 1 && args[0].Kind == OpImm {
			arg := args[0]
			arg.Imm = amd64ScalarAddSubImmediateInt64(arg.Imm, f.bits)
			return e.emitTyped(out, strings.ToLower(op), f.bits, arg)
		}
		return e.emitTyped(out, strings.ToLower(op), f.bits, args...)
	}
	if f, known, err := x86ImplicitDivideProperties(ins.Op, ins, "amd64"); known {
		if err != nil {
			return err
		}
		return e.emitTyped(out, strings.ToLower(op), f.spec.bits, f.source)
	}
	if f, known, err := x86GPSIMDTransferProperties(ins, "amd64"); known {
		if err != nil || f.mmx {
			return bad()
		}
		name := "movq"
		if f.bits == 32 {
			name = "movd"
		}
		return e.emitTyped(out, name, f.bits, args...)
	}
	if f, known, err := amd64ScalarVectorMoveProperties(ins, "amd64"); known {
		if err != nil || !f.spec.legacy || f.literal {
			return bad()
		}
		return e.emitTyped(out, strings.ToLower(op), f.spec.bits, args...)
	}
	if width := x86LEAWidth(ins.Op, "amd64"); width != 0 {
		if _, err := x86LEAOperandWidth(ins, "amd64"); err != nil {
			return err
		}
		return e.emitTyped(out, strings.ToLower(op), int(width*8), args...)
	}
	if f, known, err := x86ScalarPhysicalMoveProperties(ins, "amd64"); known {
		if err != nil {
			return err
		}
		if f.address {
			f.source.Sym = strings.TrimPrefix(f.source.Sym, "$")
			return e.emitTyped(out, "lea"+strings.ToLower(op[len(op)-1:]), f.bits, f.source, f.destination)
		}
		return e.emitTyped(out, strings.ToLower(op), f.bits, f.source, f.destination)
	}
	if f, known, err := x86BroadcastProperties(ins.Op, ins, "amd64"); known && f.kind == x86BroadcastInteger {
		if err != nil {
			return err
		}
		if args[0].Kind != OpReg || !isX86YrlRegisterForArch(args[0].Reg, "amd64") {
			return bad()
		}
		return emitNativeAMD64GPBroadcast(out, ins, f)
	}
	if f, known, err := x86ScalarFloatIntegerProperties(ins, "amd64"); known {
		if err != nil {
			return err
		}
		return e.emitScalarFloatInteger(out, ins, f)
	}
	if f, known, err := x86SignedIntegerFloatProperties(ins, "amd64"); known {
		if err != nil {
			return err
		}
		return e.emitIntegerScalarFloat(out, ins, f, false)
	}
	if f, known, err := x86UnsignedIntegerFloatProperties(ins, "amd64"); known {
		if err != nil {
			return err
		}
		return e.emitIntegerScalarFloat(out, ins, f.x86SignedIntegerFloatForm, true)
	}
	return bad()
}

func emitNativeAMD64GPBroadcast(out *strings.Builder, ins Instr, form x86BroadcastForm) error {
	// The B/W opcodes read low bytes from a dword register encoding.
	bits := 32
	if form.sourceBytes == 8 {
		bits = 64
	}
	source, err := nativeAMD64Reg(ins.Args[0], bits)
	if err != nil {
		return err
	}
	bank := "xmm"
	switch form.byteWidth {
	case 32:
		bank = "ymm"
	case 64:
		bank = "zmm"
	}
	index, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
	destination := fmt.Sprintf("%%%s%d", bank, index)
	if form.mask >= 0 {
		destination += " {%" + strings.ToLower(string(ins.Args[form.mask].Reg)) + "}"
	}
	if form.zeroing {
		destination += " {z}"
	}
	opcode, _, _ := strings.Cut(strings.ToLower(string(ins.Op)), ".")
	fmt.Fprintf(out, "\t%s %s, %s\n", opcode, source, destination)
	return nil
}
