package plan9asm

import (
	"fmt"
	"strings"
)

type x86CRC32Form struct {
	bits                int
	source, destination Operand
}

// ycrc32b is Zlitm_r/Ymb,Yrl; W/L/Q use Zlitm_r/Yml,Yrl.
// Px/Pe/Pw select the source width, not the accumulator width: every row
// reads only the old low32 and writes a zero-extended CRC32 result.
var x86CRC32Specs = map[Op]int{"CRC32B": 8, "CRC32W": 16, "CRC32L": 32, "CRC32Q": 64}

func x86CRC32Properties(op Op, ins Instr, arch string) (x86CRC32Form, bool, error) {
	name, _, suffix := strings.Cut(strings.ToUpper(string(op)), ".")
	bits, known := x86CRC32Specs[Op(name)]
	if !known {
		return x86CRC32Form{}, false, nil
	}
	fail := func(reason string) (x86CRC32Form, bool, error) {
		return x86CRC32Form{}, true, fmt.Errorf("%s %s %s: %q", arch, op, reason, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || arch == "386" && bits == 64 || suffix ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), name) || len(ins.Args) != 2 {
		return fail("requires its complete Go mode and source/destination row")
	}
	source, destination := ins.Args[0], ins.Args[1]
	if destination.Kind != OpReg || !isX86YrlRegisterForArch(destination.Reg, arch) {
		return fail("requires a Go Yrl accumulator destination")
	}
	if source.Kind == OpReg {
		valid := isX86YrlRegisterForArch(source.Reg, arch)
		if bits == 8 {
			valid = isGoYmbRegisterForArch(source.Reg, arch)
		}
		if !valid {
			return fail("source is outside its Go Ymb/Yml register class")
		}
	} else {
		if x86SourceTLSMemoryRole(source, arch) {
			return x86CRC32Form{}, true, fmt.Errorf("%w: CRC32 TLS source needs its actual native address contract", ErrProbeNeedsContext)
		}
		if !x86ScalarCompareMemoryValid(source, arch) {
			return fail("requires an encodable Go Ymb/Yml memory source")
		}
	}
	if arch == "amd64" && bits == 8 && source.Kind == OpReg && !ins.x86Encoded && ins.x86SourceRaw == nil {
		source.Reg = x86CRC32GoByteRegister(source.Reg, destination.Reg)
	}
	return x86CRC32Form{bits: bits, source: source, destination: destination}, true, nil
}

// Unlike Pb, Go's Px/Zlitm_r CRC row never calls bytereg. Full SP/BP/SI/DI
// therefore encode AH/CH/DH/BH without REX. An extended accumulator or an
// explicit low-byte/extended source selects the REX low-byte view instead.
// This local operand copy does not rewrite original source/certificate identity.
func x86CRC32GoByteRegister(source, destination Reg) Reg {
	rex := strings.HasPrefix(string(destination), "R") || strings.HasPrefix(string(source), "R") ||
		source == BPB || source == SIB || source == DIB
	if rex {
		switch source {
		case AH, CH, DH, BH:
			return amd64YmbEffectiveRegister(source, 16)
		}
		return source
	}
	switch source {
	case SP:
		return AH
	case BP:
		return CH
	case SI:
		return DH
	case DI:
		return BH
	}
	return source
}

// NUM-only dependency registration is deliberately not admission in the raw,
// source-stack or caller grammars. All inputs precede any destination write.
func x86TypedCRC32ByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	if !x86ResultNamedPredicateInstruction(ins) {
		return x86TypedByteEffect{}, false, nil
	}
	form, known, err := x86CRC32Properties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	return x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: 0, operand: form.source, width: int64(form.bits / 8), read: true},
		{index: 1, operand: form.destination, width: 4, read: true, write: true},
	}}, true, nil // CRC32 preserves all six status bits and DF.
}

func x86LoweredCRC32NativeRead(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) (bool, bool) {
	form, known, err := x86CRC32Properties(ins.Op, ins, arch)
	if !known || err != nil {
		return false, known
	}
	if !x86ResultNamedPredicateInstruction(ins) ||
		!x86ResultRead(form.destination, 4, state, owned, arch) ||
		!x86ResultReadWithNativeContinuation(ins, form.source, int64(form.bits/8), state, owned, arch, true) {
		return false, true
	}
	return x86ResultStore(form.destination, 4, state, owned, resultOffset, arch), true
}
