package plan9asm

import (
	"fmt"
	"strings"
)

type amd64FarPointerSpec struct {
	segment Reg
	bits    int
}

// amd64FarPointerSpecs is the complete Go 1.27 LFS/LGS/LSS grammar. Segment
// selection and offset width are data; memory shape, destination class, and
// architecture availability are parsed once for all nine opcodes.
var amd64FarPointerSpecs = map[Op]amd64FarPointerSpec{
	"LFSW": {segment: FS, bits: 16},
	"LFSL": {segment: FS, bits: 32},
	"LFSQ": {segment: FS, bits: 64},
	"LGSW": {segment: GS, bits: 16},
	"LGSL": {segment: GS, bits: 32},
	"LGSQ": {segment: GS, bits: 64},
	"LSSW": {segment: SS, bits: 16},
	"LSSL": {segment: SS, bits: 32},
	"LSSQ": {segment: SS, bits: 64},
}

type amd64FarPointerForm struct {
	memory      Operand
	destination Reg
}

func (c *amd64Ctx) lowerFarPointer(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, recognized := amd64FarPointerSpecs[Op(baseOp)]
	if !recognized {
		return false, false, nil
	}
	if rawOp != baseOp {
		return true, false, fmt.Errorf("%s %s does not accept instruction suffixes: %q", c.goarch, baseOp, ins.Raw)
	}
	if c.goarch == "386" && spec.bits == 64 {
		return true, false, fmt.Errorf("386 %s is absent from Go 1.27's 32-bit encoding table: %q", baseOp, ins.Raw)
	}
	form, err := c.parseFarPointerForm(baseOp, ins)
	if err != nil {
		return true, false, err
	}
	return c.emitFarPointer(spec, form)
}

func (c *amd64Ctx) parseFarPointerForm(op string, ins Instr) (amd64FarPointerForm, error) {
	var form amd64FarPointerForm
	if len(ins.Args) != 2 {
		return form, fmt.Errorf("%s %s expects far-pointer memory and GP destination: %q", c.goarch, op, ins.Raw)
	}
	memory, destination := ins.Args[0], ins.Args[1]
	if !isAMD64MemoryOperand(memory) {
		return form, fmt.Errorf("%s %s source must be Go 1.27 Ym memory: %q", c.goarch, op, ins.Raw)
	}
	if memory.Kind == OpMem && !x86MemoryRegistersValidForArch(memory.Mem, c.goarch) {
		return form, fmt.Errorf("%s %s source address uses an out-of-range register: %q", c.goarch, op, ins.Raw)
	}
	if destination.Kind != OpReg || !isX86YrlRegisterForArch(destination.Reg, c.goarch) {
		return form, fmt.Errorf("%s %s destination must be a Go 1.27 Yrl register: %q", c.goarch, op, ins.Raw)
	}
	return amd64FarPointerForm{memory: memory, destination: destination.Reg}, nil
}

func (c *amd64Ctx) emitFarPointer(spec amd64FarPointerSpec, form amd64FarPointerForm) (bool, bool, error) {
	pointer, pointerType, err := c.x86DescriptorMemoryPointer(form.memory)
	if err != nil {
		return true, false, err
	}
	typ := amd64IntegerTypeForBits(spec.bits)
	memoryBytes := spec.bits/8 + 2
	width := map[int]string{16: "w", 32: "l", 64: "q"}[spec.bits]
	result := c.newTmp()
	assembly := "l" + strings.ToLower(string(spec.segment)) + width + " $1, $0"
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s elementtype([%d x i8]) %s)\n",
		result, typ, assembly, "=r,*m,~{memory},~{dirflag},~{fpsr},~{flags}", pointerType, memoryBytes, pointer)
	if err := c.storeRegSized(form.destination, typ, "%"+result); err != nil {
		return true, false, err
	}
	return true, false, nil
}
