package plan9asm

import (
	"fmt"
	"math"
	"strings"
)

// The complete Go ycmpb/ycmpl and yxorb/ytestl rows differ in immediate
// direction. These are operand roles, not a backing or initialization proof.
type x86ScalarCompareForm struct {
	bits   int
	test   bool
	args   [2]Operand
	memory int
}

func x86ScalarCompareProperties(op Op, ins Instr, arch string) (x86ScalarCompareForm, bool, error) {
	name := strings.ToUpper(string(op))
	base := strings.SplitN(name, ".", 2)[0]
	form := x86ScalarCompareForm{memory: -1}
	switch base {
	case "CMPB", "TESTB":
		form.bits = 8
	case "CMPW", "TESTW":
		form.bits = 16
	case "CMPL", "TESTL":
		form.bits = 32
	case "CMPQ", "TESTQ":
		form.bits = 64
	default:
		return form, false, nil
	}
	form.test = strings.HasPrefix(base, "TEST")
	fail := func(reason string) (x86ScalarCompareForm, bool, error) {
		return form, true, fmt.Errorf("%s %s %s: %q", arch, op, reason, ins.Raw)
	}
	if name != base || ins.Op != "" && !strings.EqualFold(string(ins.Op), name) ||
		arch != "386" && arch != "amd64" || arch == "386" && form.bits == 64 || len(ins.Args) != 2 {
		return fail("has an invalid mode, suffix, identity or operand count")
	}
	copy(form.args[:], ins.Args)
	immediatePosition := 1
	if form.test {
		immediatePosition = 0
	}
	registers, immediates := 0, 0
	needsTLS := false
	for index, operand := range form.args {
		if projected, segment, err := x86NamedSegmentMemorySource(ins, operand, arch); segment && !x86SourceTLSMemoryRole(operand, arch) {
			if err != nil {
				return fail("has an invalid named segment memory operand")
			}
			operand, form.args[index] = projected, projected
		}
		switch operand.Kind {
		case OpImm:
			if index != immediatePosition || operand.ImmIsFloat || operand.ImmRaw != "" ||
				arch == "amd64" && (operand.Imm < -1<<31 || operand.Imm > 1<<32-1) {
				return fail("requires a resolved Yi32 integer in its original operand position")
			}
			form.args[index].Imm = amd64ScalarAddSubImmediateInt64(operand.Imm, form.bits)
			immediates++
		case OpReg:
			allowed := isX86YrlRegisterForArch(operand.Reg, arch)
			if form.bits == 8 {
				allowed = isGoYmbRegisterForArch(operand.Reg, arch)
			}
			if !allowed {
				return fail("uses a register outside its Go Yrb/Yrl class")
			}
			registers++
		default:
			if operand.Kind == OpSym && strings.HasPrefix(strings.TrimSpace(operand.Sym), "$") {
				// Non-shared 386's Yi32 includes relocated symbol addresses,
				// but Go can emit the address relocation only for the L width.
				// This syntax does not make the address numerical in a result proof.
				if arch != "386" || index != immediatePosition {
					return fail("has no relocated Yi32 row in this mode/position")
				}
				address := Operand{Kind: OpSym, Sym: strings.TrimPrefix(strings.TrimSpace(operand.Sym), "$")}
				if _, _, valid := x86ScalarCompareSBAddress(address, arch); !valid {
					return fail("has an unresolved relocated immediate")
				}
				if form.bits != 32 {
					return form, true, fmt.Errorf("%w: Go %s short relocated immediate has no original relocation sink: %q", ErrProbeNeedsContext, op, ins.Raw)
				}
				immediates++
				continue
			}
			tls := x86SourceTLSMemoryRole(operand, arch)
			if form.memory >= 0 || !tls && !x86ScalarCompareMemoryValid(operand, arch) {
				return fail("requires at most one encodable Ymb/Yml memory operand")
			}
			form.memory = index
			needsTLS = needsTLS || tls
		}
	}
	if registers == 0 && (form.memory < 0 || immediates != 1) {
		return fail("does not match any complete Go compare/test row")
	}
	if needsTLS {
		// Check the complete row first: a TLS annotation cannot make a bad
		// register, immediate direction, or second memory operand valid.
		return form, true, fmt.Errorf("%w: %s %s TLS memory needs its actual Go OS/arch/shared progedit, relocation and native TLS address contract: %q", ErrProbeNeedsContext, arch, op, ins.Raw)
	}
	if arch == "amd64" && form.bits == 8 && x86CompareExchangeHasREXByteView(x86CompareExchangeForm{
		source: form.args[0], destination: form.args[1],
	}) {
		for index, operand := range form.args {
			if operand.Kind == OpReg && (operand.Reg == AH || operand.Reg == CH || operand.Reg == DH || operand.Reg == BH) {
				form.args[index].Reg = amd64YmbEffectiveRegister(operand.Reg, 16)
			}
		}
	}
	return form, true, nil
}

func x86ScalarCompareMemoryValid(operand Operand, arch string) bool {
	if operand.Kind == OpFP {
		return true // Its separate logical frame consumer validates the byte span.
	}
	if operand.Kind == OpSym {
		if strings.HasPrefix(strings.TrimSpace(operand.Sym), "$") {
			return false
		}
		if _, _, valid := x86ScalarCompareSBAddress(operand, arch); valid {
			return true
		}
		address, err := parseInt(strings.TrimSpace(operand.Sym))
		return err == nil && (address == int64(int32(address)) || arch == "386" && address == int64(uint32(address)))
	}
	if operand.Kind != OpMem {
		return false
	}
	memory := operand.Mem
	if x86SymbolIndexedMemoryError(memory, arch) != nil || unresolvedX86MemoryOffsetError(memory) != nil ||
		memory.IndexExt != "" || memory.Segment != "" && memory.Segment != FS && memory.Segment != GS {
		return false
	}
	if memory.Sym != "" {
		var valid bool
		_, memory, valid = x86ScalarCompareSBAddress(operand, arch)
		if !valid {
			return false
		}
	}
	return x86MemoryRegistersValidForArch(memory, arch) &&
		(memory.Off == int64(int32(memory.Off)) || arch == "386" && memory.Off == int64(uint32(memory.Off))) &&
		(memory.Index == "" && memory.Scale == 0 || memory.Index != "" && memory.Index != SP &&
			(memory.Scale == 1 || memory.Scale == 2 || memory.Scale == 4 || memory.Scale == 8))
}

// Unlike the same-file DATA reader this recognizes an address, including a
// negative displacement, without claiming an allocated or initialized extent.
func x86ScalarCompareSBAddress(operand Operand, arch string) (string, MemRef, bool) {
	memory, valid := x86SBMemoryAddressRole(operand, arch)
	if !valid || memory.OffRaw != "" || memory.IndexExt != "" {
		return "", MemRef{}, false
	}
	base, offset, valid := parseSBRef(memory.Sym)
	if !valid || base == "" || strings.IndexAny(base, "$+(),[] \t") >= 0 ||
		memory.Off > 0 && offset > math.MaxInt64-memory.Off ||
		memory.Off < 0 && offset < math.MinInt64-memory.Off {
		return "", MemRef{}, false
	}
	offset += memory.Off
	if offset != int64(int32(offset)) && !(arch == "386" && offset == int64(uint32(offset))) {
		return "", MemRef{}, false
	}
	return base, memory, true
}
