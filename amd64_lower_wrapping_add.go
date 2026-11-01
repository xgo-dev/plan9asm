package plan9asm

import (
	"fmt"
	"strings"
)

func (c *amd64Ctx) lowerPackedIntegerAddForm(op Op, ins Instr) (bool, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := amd64PackedAddSpecs[Op(base)]; !known {
		return false, false, nil
	}
	if ins.Op != "" && strings.ToUpper(string(ins.Op)) != strings.ToUpper(string(op)) {
		return true, false, fmt.Errorf("packed add dispatch/source opcode mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op
	arch := c.goarch
	if arch == "" {
		arch = "amd64"
	}
	form, known, err := x86PackedIntegerAddProperties(ins, arch)
	if err != nil || !known {
		return known, false, err
	}
	first, second, destination := ins.Args[form.first], ins.Args[form.second], ins.Args[form.destination]
	if form.legacy && !form.mmx && form.memory >= 0 {
		virtual := first.Kind == OpFP
		if first.Kind == OpMem && !x86CallerMemoryCertified(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
			virtual = !x86OrdinaryNativeMemoryOperand(first, c.goarch)
		}
		if virtual {
			return true, false, fmt.Errorf("%w: legacy packed add m128 needs original native storage, not virtual FP/SP/BP alignment", ErrProbeNeedsContext)
		}
	}
	if form.memory >= 0 && first.Kind == OpFP {
		if err := c.validateFPVectorSpan(first.FPOffset, form.memoryBytes); err != nil {
			return true, false, err
		}
	}
	bits := form.spec.laneBits
	lanes := form.byteWidth * 8 / bits
	if form.mmx {
		var a string
		if first.Kind == OpReg {
			a, err = c.loadReg(first.Reg)
		} else {
			a, err = c.loadPackedUnpackMMXSource(first, 8)
		}
		if err != nil {
			return true, false, err
		}
		b, err := c.loadReg(second.Reg)
		if err != nil {
			return true, false, err
		}
		value := c.emitPackedIntegerAdd(lanes, bits, c.bitcastI64ToIntegerLanes(lanes, bits, a), c.bitcastI64ToIntegerLanes(lanes, bits, b), form.spec.mode)
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to i64\n", out, lanes, bits, value)
		return true, false, c.storeReg(destination.Reg, "%"+out)
	}
	mnemonic := ""
	if form.legacy && form.memory >= 0 {
		mnemonic = strings.ToLower(string(form.spec.canonical))
		if mnemonic == "paddl" {
			mnemonic = "paddd"
		}
	}
	err = c.emitPackedBinaryE4(ins, form.x86PackedBinaryForm, bits, mnemonic,
		func(lanes, bits int, first, second string) string {
			return c.emitPackedIntegerAdd(lanes, bits, first, second, form.spec.mode)
		})
	return true, false, err
}

// The caller supplies a registered legacy mnemonic. Keeping its memory form
// native preserves alignment/fault effects which an unaligned vector load
// followed by portable arithmetic would erase.
func (c *amd64Ctx) emitPackedBinaryNativeMemory(source Operand, bits int, data, mnemonic string) (string, error) {
	pointer, pointerType, _, err := c.packedVectorMemoryPointer(source)
	if err != nil {
		return "", err
	}
	segment := ""
	if pointerType == "ptr addrspace(256)" {
		segment = "%gs:"
	} else if pointerType == "ptr addrspace(257)" {
		segment = "%fs:"
	}
	carrier, result := c.newTmp(), c.newTmp()
	// LLVM's i386 v4i32 inline-asm carrier requires SSE2. A bitcast-only
	// v4f32 carrier also represents original SSE1 PS operations without
	// strengthening their CPU requirements. No floating arithmetic occurs.
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <4 x float>\n", carrier, 128/bits, bits, data)
	fmt.Fprintf(c.b, "  %%%s = call <4 x float> asm sideeffect %q, %q(<4 x float> %%%s, %s %s)\n", result, mnemonic+" "+segment+"($2), $0", "=x,0,r,~{memory}", carrier, pointerType, pointer)
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <4 x float> %%%s to <%d x i%d>\n", value, result, 128/bits, bits)
	return "%" + value, nil
}
