package plan9asm

import (
	"fmt"
	"strings"
)

type x86FloatCompareSpec struct {
	bits           int
	legacy, scalar bool
}

var x86FloatCompareSpecs = map[Op]x86FloatCompareSpec{
	"CMPPS": {32, true, false}, "CMPPD": {64, true, false},
	"CMPSS": {32, true, true}, "CMPSD": {64, true, true},
	"VCMPPS": {32, false, false}, "VCMPPD": {64, false, false},
	"VCMPSS": {32, false, true}, "VCMPSD": {64, false, true},
}

// Compare has an immediate position and a K-result generation distinct from
// binary arithmetic. The shared source-width axes do not imply merge/zero
// destination semantics or shared floating exception policy.
type x86FloatCompareForm struct {
	spec x86FloatCompareSpec
	x86FloatBinaryForm
	immediate       uint8
	maskResult, sae bool
}

func (form x86FloatCompareForm) inputByteWidth() int {
	if form.scalar {
		return form.bits / 8
	}
	return form.byteWidth
}

// Both callers and result analysis use the same architectural byte writes.
// These are definedness facts, not predicate values or native memory rights.
func (form x86FloatCompareForm) resultDefinedBytes(second, previous uint64) uint64 {
	active := x86CallerVectorByteMask(int64(form.inputByteWidth()))
	if form.legacy {
		return previous | active
	}
	if form.scalar {
		return ^uint64(0xffff) | active | second&(0xffff&^active)
	}
	return ^uint64(0)
}

func x86FloatCompareProperties(ins Instr, goarch string) (x86FloatCompareForm, bool, error) {
	base, suffix, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, known := x86FloatCompareSpecs[Op(base)]
	if !known {
		return x86FloatCompareForm{}, false, nil
	}
	form := x86FloatCompareForm{spec: spec, x86FloatBinaryForm: x86FloatBinaryForm{
		bits: spec.bits, legacy: spec.legacy, scalar: spec.scalar,
		mask: -1, memory: -1,
	}}
	fail := func() (x86FloatCompareForm, bool, error) {
		return form, true, fmt.Errorf("%s %s operands/suffix outside Go floating compare grammar: %q", goarch, ins.Op, ins.Raw)
	}
	if goarch != "386" && goarch != "amd64" {
		return fail()
	}
	if spec.legacy {
		if dotted || len(ins.Args) != 3 {
			return fail()
		}
		if ins.Args[2].Kind == OpImm && (ins.Args[2].ImmIsFloat || ins.Args[2].ImmRaw != "") {
			return fail()
		}
		immediate, valid := amd64LegacyFloatingCompareImmediate(ins.Args[2])
		if !valid || immediate < -128 || immediate > 127 {
			return fail()
		}
		form.immediate = uint8(immediate)
		form.first, form.second, form.destination, form.byteWidth = 0, 1, 1, 16
	} else {
		if goarch == "386" && !ins.x86Encoded || len(ins.Args) != 4 && len(ins.Args) != 5 ||
			dotted && suffix != "BCST" && suffix != "SAE" || ins.Args[0].Kind != OpImm || ins.Args[0].ImmIsFloat || ins.Args[0].ImmRaw != "" || ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
			return fail()
		}
		form.immediate = uint8(ins.Args[0].Imm)
		form.first, form.second, form.destination = 1, 2, len(ins.Args)-1
		form.broadcast, form.sae = suffix == "BCST", suffix == "SAE"
		form.maskResult = amd64IsKOperand(ins.Args[form.destination])
		if form.maskResult {
			form.byteWidth = amd64VectorByteWidth(ins.Args[form.second].Reg)
			if len(ins.Args) == 5 {
				if !amd64NonzeroKOperand(ins.Args[3]) {
					return fail()
				}
				form.mask = 3
			}
		} else {
			form.byteWidth = amd64VectorByteWidth(ins.Args[form.destination].Reg)
			if dotted || len(ins.Args) != 4 || form.byteWidth != 16 && form.byteWidth != 32 {
				return fail()
			}
		}
		if spec.scalar && form.byteWidth != 16 || form.byteWidth != 16 && form.byteWidth != 32 && form.byteWidth != 64 {
			return fail()
		}
	}
	register := func(operand Operand) bool {
		if operand.Kind != OpReg || amd64VectorByteWidth(operand.Reg) != form.byteWidth {
			return false
		}
		index, valid := amd64VectorRegisterIndex(operand.Reg, form.byteWidth)
		limit := 16
		if goarch == "386" {
			limit = 8
		} else if form.maskResult {
			limit = 32
		}
		return valid && index < limit
	}
	if !register(ins.Args[form.second]) || !form.maskResult && !register(ins.Args[form.destination]) {
		return fail()
	}
	first := ins.Args[form.first]
	if isAMD64MemoryOperand(first) {
		if form.sae {
			return fail()
		}
		if first.Kind == OpSym {
			symbol := strings.TrimSpace(first.Sym)
			_, absolute := parseInt(symbol)
			if strings.HasPrefix(symbol, "$") || !strings.HasSuffix(symbol, "(SB)") && absolute != nil {
				return fail()
			}
		}
		if first.Kind == OpMem {
			displacement := first.Mem.Off
			if displacement != int64(int32(displacement)) && (goarch != "386" || displacement != int64(uint32(displacement))) ||
				!x86MemoryRegistersValidForArch(first.Mem, goarch) || first.Mem.Index != "" &&
				(first.Mem.Index == SP || first.Mem.Scale != 1 && first.Mem.Scale != 2 && first.Mem.Scale != 4 && first.Mem.Scale != 8) {
				return fail()
			}
		}
		form.memory, form.memoryBytes = form.first, form.byteWidth
		if spec.scalar || form.broadcast {
			form.memoryBytes = spec.bits / 8
		}
	} else if !register(first) || form.broadcast {
		return fail()
	}
	if form.broadcast && (spec.scalar || !form.maskResult) || form.sae && (!form.maskResult || !spec.scalar && form.byteWidth != 64) {
		return fail()
	}
	return form, true, nil
}
