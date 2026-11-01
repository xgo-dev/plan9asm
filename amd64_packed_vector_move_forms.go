package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedMoveEncoding uint8

const (
	amd64PackedMoveVEX amd64PackedMoveEncoding = iota
	amd64PackedMoveVEXOrEVEX
	amd64PackedMoveEVEX
)

type amd64PackedVectorMoveSpec struct {
	elementBits int
	encoding    amd64PackedMoveEncoding
	aligned     bool
}

// This is the complete _yvmovdqa, _yvmovapd and _yvmovdqa32 family.
// Encoding generation controls widths/registers/masks; elementBits controls
// mask granularity, not the native memory access's complete byte envelope.
var amd64PackedVectorMoveSpecs = map[Op]amd64PackedVectorMoveSpec{
	"VMOVDQA":   {8, amd64PackedMoveVEX, true},
	"VMOVDQU":   {8, amd64PackedMoveVEX, false},
	"VMOVAPD":   {64, amd64PackedMoveVEXOrEVEX, true},
	"VMOVAPS":   {32, amd64PackedMoveVEXOrEVEX, true},
	"VMOVUPD":   {64, amd64PackedMoveVEXOrEVEX, false},
	"VMOVUPS":   {32, amd64PackedMoveVEXOrEVEX, false},
	"VMOVDQA32": {32, amd64PackedMoveEVEX, true},
	"VMOVDQA64": {64, amd64PackedMoveEVEX, true},
	"VMOVDQU8":  {8, amd64PackedMoveEVEX, false},
	"VMOVDQU16": {16, amd64PackedMoveEVEX, false},
	"VMOVDQU32": {32, amd64PackedMoveEVEX, false},
	"VMOVDQU64": {64, amd64PackedMoveEVEX, false},
}

type amd64PackedVectorMoveForm struct {
	spec         amd64PackedVectorMoveSpec
	byteWidth    int
	destination  int
	mask         int // -1 for unmasked forms
	memory       int // -1 for register-to-register forms
	memoryWrite  bool
	zeroing      bool // native EVEX.z; memory destinations raise #UD
	physicalEVEX bool // Exact decoded generation, including unmasked low X/Y registers.
}

// Go's frontend accepts .Z memory stores and sets EVEX.z in their objects,
// although the native instruction requires EVEX.z=0 for a memory destination.
// Keep syntax acceptance separate from its terminal exception effect.
func (form amd64PackedVectorMoveForm) undefinedOpcode() bool {
	return form.zeroing && form.memoryWrite
}

// Only the written vector bytes are described here. Callers independently
// supply numerical source/merge bytes and validate every mask and native
// memory role. VEX/EVEX upper-zeroing is applied by the state consumer.
func (form amd64PackedVectorMoveForm) definedActiveBytes(source, previous uint64) uint64 {
	known := source & x86CallerVectorByteMask(int64(form.byteWidth))
	if form.mask >= 0 && !form.zeroing {
		known &= previous
	}
	return known
}

// Both the lowerer and caller-effect proof consume this grammar. It supplies
// no memory bounds, alignment, initialized bytes, mask value or continuation.
func amd64PackedVectorMoveProperties(ins Instr, goarch string) (amd64PackedVectorMoveForm, bool, error) {
	name := strings.ToUpper(string(ins.Op))
	base, suffix, dotted := strings.Cut(name, ".")
	spec, recognized := amd64PackedVectorMoveSpecs[Op(base)]
	if !recognized {
		return amd64PackedVectorMoveForm{}, false, nil
	}
	form := amd64PackedVectorMoveForm{
		spec: spec, destination: len(ins.Args) - 1,
		mask: -1, memory: -1, zeroing: suffix == "Z",
		physicalEVEX: ins.x86PackedVectorMoveEVEX,
	}
	fail := func() (amd64PackedVectorMoveForm, bool, error) {
		return form, true, fmt.Errorf("%s %s operands/suffix are outside the packed vector-move grammar: %q", goarch, base, ins.Raw)
	}
	if goarch != "amd64" && goarch != "386" || dotted && suffix != "Z" ||
		form.physicalEVEX && spec.encoding == amd64PackedMoveVEX ||
		len(ins.Args) != 2 && len(ins.Args) != 3 {
		return fail()
	}
	if len(ins.Args) == 3 {
		if spec.encoding == amd64PackedMoveVEX || !amd64NonzeroKOperand(ins.Args[1]) {
			return fail()
		}
		form.mask = 1
	} else if form.zeroing {
		return fail()
	}
	vector := func(operand Operand, width int) bool {
		if !amd64GoPackedVectorMoveRegister(operand, width, goarch) {
			return false
		}
		if spec.encoding == amd64PackedMoveVEX {
			return width != 64 && amd64VEXVectorRegister(operand, width)
		}
		return true
	}
	source, destination := ins.Args[0], ins.Args[form.destination]
	switch {
	case source.Kind == OpReg:
		form.byteWidth = amd64VectorByteWidth(source.Reg)
		if !vector(source, form.byteWidth) {
			return fail()
		}
		if isAMD64MemoryOperand(destination) {
			form.memory, form.memoryWrite = form.destination, true
		} else if !vector(destination, form.byteWidth) {
			return fail()
		}
	case isAMD64MemoryOperand(source):
		form.byteWidth = amd64VectorByteWidth(destination.Reg)
		if !vector(destination, form.byteWidth) {
			return fail()
		}
		form.memory = 0
	default:
		return fail()
	}
	if form.memory >= 0 {
		memory := ins.Args[form.memory]
		if !x86PackedShiftMemoryValid(memory, goarch) {
			return fail()
		}
		if memory.Kind == OpMem {
			if err := x86SymbolIndexedMemoryError(memory.Mem, goarch); err != nil {
				return form, true, err
			}
			if memory.Mem.OffRaw != "" || memory.Mem.IndexExt != "" {
				return fail()
			}
		}
	}
	return form, true, x86Mode32VectorRegisterContext(ins, goarch)
}

// This selects actual ordinary memory, not an extent or a continuation proof.
// The lowerer and private conditional result reader must select the same path.
func (form amd64PackedVectorMoveForm) unalignedOrdinaryMemory(ins Instr, arch string) bool {
	return !form.spec.aligned && form.ordinaryMemory(ins, arch)
}

func (form amd64PackedVectorMoveForm) ordinaryMemory(ins Instr, arch string) bool {
	return form.memory >= 0 &&
		x86OrdinaryNativeMemoryOperand(ins.Args[form.memory], arch)
}

func (form amd64PackedVectorMoveForm) nativeEVEX(ins Instr) bool {
	if form.physicalEVEX || form.spec.encoding == amd64PackedMoveEVEX || form.mask >= 0 || form.byteWidth == 64 {
		return true
	}
	for _, operand := range ins.Args {
		if operand.Kind == OpReg && amd64VectorByteWidth(operand.Reg) != 0 {
			index, ok := amd64VectorRegisterIndex(operand.Reg, form.byteWidth)
			if ok && index >= 16 {
				return true
			}
		}
	}
	return false
}

func amd64GoPackedVectorMoveRegister(operand Operand, width int, goarch string) bool {
	if !amd64EVEXVectorRegister(operand, width) {
		return false
	}
	index, _ := amd64VectorRegisterIndex(operand.Reg, width)
	return goarch != "386" || width != 64 || index < 8
}
