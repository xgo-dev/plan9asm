package plan9asm

import (
	"fmt"
	"strings"
)

type x86GPSIMDTransferSpec struct {
	bits            int
	legacy, rawOnly bool
}

// MOVD is Go's MOVQ alias, not Intel's 32-bit MOVD. Ordinary GP-only
// MOVL/Q/D and the separate MMX rows retain their existing scalar grammar.
var x86GPSIMDTransferSpecs = map[Op]x86GPSIMDTransferSpec{
	"MOVL":    {bits: 32, legacy: true},
	"MOVQ":    {bits: 64, legacy: true},
	"MOVD":    {bits: 64, legacy: true},
	"MOVDQ2Q": {bits: 64, legacy: true},
	"VMOVD":   {bits: 32},
	"VMOVQ":   {bits: 64},
	"VMOVW":   {bits: 16, rawOnly: true},
}

type x86GPSIMDTransferForm struct {
	spec                       x86GPSIMDTransferSpec
	bits, memory               int
	sourceX, destinationX, mmx bool
	memoryWrite                bool
}

// A scalar transfer replaces its low X bytes, zeroes the rest of X, and
// preserves or clears wider aliases according to its original encoding.
// Numerical availability does not supply a pointer or memory access role.
func (f x86GPSIMDTransferForm) definedVectorBytes(source, previous uint64) uint64 {
	low := x86CallerVectorByteMask(int64(f.bits / 8))
	upper := ^uint64(0xffff)
	if f.spec.legacy {
		upper &= previous
	}
	return upper | (0xffff &^ low) | (source & low)
}

// Encoding/width selection grants neither initialized data nor memory backing.
// In mode32 VEX.W is ignored for GP transfers, but Q memory/X copies stay 64-bit.
func x86GPSIMDTransferProperties(ins Instr, arch string) (x86GPSIMDTransferForm, bool, error) {
	base, _, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, known := x86GPSIMDTransferSpecs[Op(base)]
	if !known {
		return x86GPSIMDTransferForm{}, false, nil
	}
	f := x86GPSIMDTransferForm{spec: spec, bits: spec.bits, memory: -1}
	hasX := false
	for _, arg := range ins.Args {
		hasX = hasX || isAMD64GoXRegister(arg)
	}
	if spec.legacy && !hasX {
		return f, false, nil
	}
	fail := func() (x86GPSIMDTransferForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside complete Go GP/X transfer grammar: %q", arch, ins.Op, ins.Raw)
	}
	if arch == "" {
		arch = "amd64"
	}
	if arch != "amd64" && arch != "386" || dotted || len(ins.Args) != 2 || spec.rawOnly && !ins.x86Encoded {
		return fail()
	}
	src, dst := ins.Args[0], ins.Args[1]
	f.sourceX, f.destinationX = isAMD64GoXRegister(src), isAMD64GoXRegister(dst)
	for _, arg := range ins.Args {
		if isAMD64GoXRegister(arg) {
			index, _ := amd64ParseXReg(arg.Reg)
			if spec.legacy && index >= 16 {
				return fail()
			}
		}
	}
	if f.sourceX && f.destinationX {
		if spec.bits != 64 {
			return fail()
		}
	} else if f.sourceX || f.destinationX {
		other, index := src, 0
		if f.sourceX {
			other, index = dst, 1
		}
		if isAMD64MemoryOperand(other) && x86PackedShiftMemoryValid(other, arch) {
			f.memory, f.memoryWrite = index, index == 1
		} else if other.Kind == OpReg && isX86YrlRegisterForArch(other.Reg, arch) {
			if spec.legacy && spec.bits == 64 && arch == "386" {
				return fail()
			}
			if arch == "386" && !spec.legacy && f.bits > 32 {
				f.bits = 32
			}
		} else if f.sourceX && spec.legacy && spec.bits == 64 && isAMD64MOVDMRegister(other) {
			f.mmx = true // Go's MOVDQ2Q row, never a physical caller-state proof.
		} else if !f.sourceX && other.Kind == OpImm && ins.x86RIPLiteral &&
			!other.ImmIsFloat && other.ImmRaw == "" {
			// Only the decoder's already-bound RIP data receipt supplies this
			// representation. A named literal cannot acquire it.
		} else {
			return fail()
		}
	} else {
		return fail()
	}
	return f, true, x86Mode32VectorRegisterContext(ins, arch)
}

// Preserve the original operand class before normalization can rewrite an
// invalid register/address spelling. Direct and textual APIs share this guard.
func validateX86GPSIMDTransferFile(file *File, arch string) error {
	if file == nil || file.Arch != ArchAMD64 {
		return nil
	}
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			if _, known, err := x86GPSIMDTransferProperties(ins, arch); known && err != nil {
				return fmt.Errorf("%s: %w", fn.Sym, err)
			}
		}
	}
	return nil
}
