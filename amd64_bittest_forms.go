package plan9asm

import (
	"fmt"
	"strings"
)

// All twelve Go ybtl registrations share these roles. A memory destination
// with a register index is a signed bit string, not a fixed-width envelope.
// This grammar supplies no memory, caller, native-frame or initialized bytes.
type x86BitTestForm struct {
	stem        string
	bits        int
	index       Operand
	destination Operand
}

func x86BitTestProperties(op Op, ins Instr, arch string) (x86BitTestForm, bool, error) {
	name := strings.ToUpper(string(op))
	base := strings.SplitN(name, ".", 2)[0]
	stem, bits, known := amd64BitTestProperties(base)
	form := x86BitTestForm{stem: stem, bits: bits}
	if !known {
		return form, false, nil
	}
	fail := func(reason string) (x86BitTestForm, bool, error) {
		return form, true, fmt.Errorf("%s %s %s: %q", arch, op, reason, ins.Raw)
	}
	if name != base || ins.Op != "" && !strings.EqualFold(string(ins.Op), name) ||
		arch != "386" && arch != "amd64" || arch == "386" && bits == 64 || len(ins.Args) != 2 {
		return fail("has an invalid mode, suffix, identity or operand count")
	}
	form.index, form.destination = ins.Args[0], ins.Args[1]
	if projected, segment, err := x86NamedSegmentMemorySource(ins, form.destination, arch); segment {
		if err != nil {
			return form, true, err
		}
		form.destination = projected
	}
	if form.index.Kind == OpImm {
		if form.index.ImmIsFloat || form.index.ImmRaw != "" {
			return fail("requires a resolved integer bit index")
		}
		if arch == "386" {
			form.index.Imm = int64(int32(form.index.Imm)) // Go oclass precedes Yi8.
		}
		if form.index.Imm < -128 || form.index.Imm > 127 {
			return fail("bit index is outside Go's signed Yi8 class")
		}
	} else if form.index.Kind != OpReg || !isX86YrlRegisterForArch(form.index.Reg, arch) {
		return fail("bit index is outside Go's Yi8/Yrl rows")
	}
	if form.destination.Kind == OpReg {
		if !isX86YrlRegisterForArch(form.destination.Reg, arch) {
			return fail("destination is outside Go's Yml register class")
		}
	} else if !x86ScalarCompareMemoryValid(form.destination, arch) {
		if x86SourceTLSMemoryRole(form.destination, arch) {
			return form, true, fmt.Errorf("%w: bit string needs its actual Go TLS address contract", ErrProbeNeedsContext)
		}
		return fail("destination is outside Go's encodable Yml memory class")
	}
	return form, true, nil
}

func x86TypedBitTestByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86BitTestProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width := int64(form.bits / 8)
	return x86TypedByteEffect{
		operands: []x86TypedByteOperand{
			{index: 0, operand: form.index, width: width, read: true},
			{index: 1, operand: form.destination, width: width, read: true, write: form.stem != "BT"},
		},
		flagsDefined:  x86ByteFlagCF,
		flagsKilled:   x86ByteFlagOF | x86ByteFlagSF | x86ByteFlagAF | x86ByteFlagPF,
		dynamicMemory: form.index.Kind == OpReg && form.destination.Kind != OpReg,
	}, true, nil
}
