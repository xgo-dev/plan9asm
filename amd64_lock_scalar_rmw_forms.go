package plan9asm

import (
	"fmt"
	"strings"
)

// This is an operand/effect record, not an atomic, pointer or frame capability.
// LOCK requires the independent complete source-adjacency consumer.
type x86LockScalarRMWSpec struct {
	stem         string
	bits         int
	unary        bool
	bitString    bool
	carryInput   bool
	flagsDefined uint8
	flagsKilled  uint8
}

type x86LockScalarRMWForm struct {
	spec        x86LockScalarRMWSpec
	source      Operand
	destination Operand
}

// Numerical output bytes are independent of FLAGS preservation. INC/DEC do
// not read CF to compute data, while ADC/SBB do. Arithmetic carry/borrow flows
// only toward higher bytes; the four logical operations are byte-local.
func (s x86LockScalarRMWSpec) numericalByteInputs(output int) (mask uint8, carry bool) {
	if output < 0 || output >= s.bits/8 {
		return 0, false
	}
	switch s.stem {
	case "AND", "OR", "XOR", "NOT":
		return 1 << uint(output), false
	case "ADC", "SBB":
		return uint8((uint16(1) << uint(output+1)) - 1), true
	case "ADD", "SUB", "INC", "DEC", "NEG":
		return uint8((uint16(1) << uint(output+1)) - 1), false
	default:
		return 0, false // Bit-string indexes retain their separate dependencies.
	}
}

var x86LockScalarRMWSpecs = func() map[Op]x86LockScalarRMWSpec {
	result := make(map[Op]x86LockScalarRMWSpec)
	for _, stem := range []string{"ADC", "ADD", "AND", "OR", "SBB", "SUB", "XOR", "INC", "DEC", "NEG", "NOT", "BTC", "BTR", "BTS"} {
		for index, suffix := range "BWLQ" {
			spec := x86LockScalarRMWSpec{stem: stem, bits: []int{8, 16, 32, 64}[index], flagsDefined: x86ByteFlagsAll}
			switch stem {
			case "ADC", "SBB":
				spec.carryInput = true
			case "AND", "OR", "XOR":
				spec.flagsDefined &^= x86ByteFlagAF
				spec.flagsKilled = x86ByteFlagAF
			case "INC", "DEC":
				spec.unary, spec.carryInput = true, true
				spec.flagsDefined &^= x86ByteFlagCF
			case "NEG":
				spec.unary = true
			case "NOT":
				spec.unary, spec.flagsDefined = true, 0
			case "BTC", "BTR", "BTS":
				if suffix == 'B' {
					continue
				}
				spec.bitString = true
				spec.flagsDefined = x86ByteFlagCF
				spec.flagsKilled = x86ByteFlagOF | x86ByteFlagSF | x86ByteFlagAF | x86ByteFlagPF
			}
			result[Op(stem+string(suffix))] = spec
		}
	}
	return result
}()

func x86LockScalarRMWProperties(op Op, ins Instr, arch string) (x86LockScalarRMWForm, bool, error) {
	name := strings.ToUpper(string(op))
	base, _, _ := strings.Cut(name, ".")
	spec, recognized := x86LockScalarRMWSpecs[Op(base)]
	if !recognized {
		return x86LockScalarRMWForm{}, false, nil
	}
	if spec.bitString {
		form, _, err := x86BitTestProperties(op, ins, arch)
		return x86LockScalarRMWForm{spec: spec, source: form.index, destination: form.destination}, true, err
	}
	fail := func(reason string) (x86LockScalarRMWForm, bool, error) {
		return x86LockScalarRMWForm{}, true, fmt.Errorf("%s %s %s: %q", arch, op, reason, ins.Raw)
	}
	if name != base || ins.Op != "" && !strings.EqualFold(string(ins.Op), name) ||
		arch != "amd64" && arch != "386" || arch == "386" && spec.bits == 64 {
		return fail("has an invalid suffix, dispatch identity or machine mode")
	}
	count := 2
	if spec.unary {
		count = 1
	}
	if len(ins.Args) != count {
		return fail("has an incomplete operand list")
	}
	form := x86LockScalarRMWForm{spec: spec, destination: ins.Args[count-1]}
	if projected, segment, err := x86NamedSegmentMemorySource(ins, form.destination, arch); segment {
		if err != nil {
			return form, true, err
		}
		form.destination = projected
	}
	if form.destination.Kind == OpSym && strings.HasPrefix(strings.TrimSpace(form.destination.Sym), "$") {
		return fail("requires writable memory, not a symbol address literal")
	}
	if !spec.unary {
		form.source = ins.Args[0]
		if projected, segment, err := x86NamedSegmentMemorySource(ins, form.source, arch); segment {
			if err != nil {
				return form, true, err
			}
			form.source = projected
		}
	}
	if spec.unary {
		if form.destination.Kind == OpReg {
			allowed := isX86YrlRegisterForArch(form.destination.Reg, arch)
			if spec.stem == "NEG" || spec.stem == "NOT" || spec.bits == 8 {
				allowed = isGoYmbRegisterForArch(form.destination.Reg, arch)
			}
			if !allowed {
				return fail("destination is outside its complete Go register class")
			}
			if spec.stem == "NEG" || spec.stem == "NOT" {
				form.destination.Reg = amd64YmbEffectiveRegister(form.destination.Reg, spec.bits)
			}
		} else if !isAMD64MemoryOperand(form.destination) {
			return fail("destination is outside the Go memory class")
		}
	} else {
		if err := validateAMD64ScalarAddSubOperands(arch, base, spec.bits, form.source, form.destination, ins); err != nil {
			return x86LockScalarRMWForm{}, true, err
		}
		if form.source.Kind == OpImm {
			form.source.Imm = amd64ScalarAddSubImmediateInt64(form.source.Imm, spec.bits)
		}
	}
	needsTLS := false
	for _, operand := range []Operand{form.source, form.destination} {
		if operand.Kind == OpImm && (operand.ImmRaw != "" || operand.ImmIsFloat) {
			return fail("requires a resolved integer immediate")
		}
		if operand.Kind != OpMem {
			continue
		}
		if x86SourceTLSMemoryRole(operand, arch) {
			needsTLS = true
			continue
		}
		memory := operand.Mem
		if err := x86SymbolIndexedMemoryError(memory, arch); err != nil {
			return x86LockScalarRMWForm{}, true, err
		}
		if arch == "386" && strings.HasSuffix(memory.Sym, "(SB)") {
			memory.Base = "" // Only the actual Go ignored annotation is discarded.
		}
		if !x86MemoryRegistersValidForArch(memory, arch) || memory.OffRaw != "" ||
			memory.Index == SP || memory.Index != "" && memory.Scale != 1 && memory.Scale != 2 && memory.Scale != 4 && memory.Scale != 8 ||
			memory.Off != int64(int32(memory.Off)) && !(arch == "386" && memory.Off == int64(uint32(memory.Off))) {
			return fail("has an unencodable or unresolved native memory operand")
		}
	}
	if needsTLS {
		// Validate the complete operand row before preserving TLS's source
		// role. It is not an ordinary SIB address or a native memory grant.
		return form, true, fmt.Errorf("%w: %s %s TLS memory needs its actual Go OS/arch/shared address contract: %q",
			ErrProbeNeedsContext, arch, op, ins.Raw)
	}
	if arch == "amd64" && spec.bits == 8 && x86CompareExchangeHasREXByteView(x86CompareExchangeForm{
		source: form.source, destination: form.destination,
	}) {
		// Go emits these original Ymb spellings with their raw ModRM number.
		// A REX prefix selects SP/BP/SI/DI's low byte instead of AH/CH/DH/BH.
		// Recording the physical view does not bind a source/native input.
		for _, operand := range []*Operand{&form.source, &form.destination} {
			if operand.Kind == OpReg && (operand.Reg == AH || operand.Reg == CH || operand.Reg == DH || operand.Reg == BH) {
				operand.Reg = amd64YmbEffectiveRegister(operand.Reg, 16)
			}
		}
	}
	return form, true, nil
}

func x86LockScalarNativeMemoryBound(form x86LockScalarRMWForm, ins Instr, arch string) error {
	if form.destination.Kind == OpSym && strings.HasPrefix(strings.TrimSpace(form.destination.Sym), "$") {
		return fmt.Errorf("%s LOCK RMW address literal is not writable native memory", arch)
	}
	if form.destination.Kind != OpMem && form.destination.Kind != OpSym || ins.x86UnboundAddressOverride {
		return fmt.Errorf("%w: %s LOCK RMW needs its bound native memory destination, not a virtual FP/AUTO span", ErrProbeNeedsContext, arch)
	}
	if form.destination.Kind == OpMem {
		memory := form.destination.Mem
		if memory.Base == SP || memory.Base == BP || memory.Index == SP || memory.Index == BP {
			// Numeric source slots and LLVM's private SP allocation do not
			// establish the original instruction's physical native address.
			return fmt.Errorf("%w: %s LOCK RMW needs independent native SP/BP backing", ErrProbeNeedsContext, arch)
		}
	}
	if arch == "amd64" && form.spec.bits == 8 && form.source.Kind == OpReg &&
		len(ins.Args) == 2 && form.source.Reg != ins.Args[0].Reg {
		return fmt.Errorf("%w: amd64 LOCK byte source needs its original Go REX physical register view", ErrProbeNeedsContext)
	}
	if arch == "386" && form.spec.bits == 8 && form.source.Kind == OpReg {
		switch form.source.Reg {
		case AX, BX, CX, DX, AL, AH, BL, BH, CL, CH, DL, DH:
		default:
			return fmt.Errorf("%w: 386 LOCK byte source requires Go's original scratch-register expansion", ErrProbeNeedsContext)
		}
	}
	return nil
}
